/* oaf-lite -- lightweight user-list sampler.
 *
 *   feature.bin/cfg (plaintext OAF rules) --> domain/port index (feature.c)
 *   AF_PACKET first packets               --> L7 label per flow  (probe.c)
 *   conntrack deltas + DESTROY events     --> bytes / rates      (acct.c)
 *   HNAT/PPE writeback                    --> offloaded bytes    (acct.c)
 *   /tmp/oaf-lite/*.json                 --> LuCI read layer
 *
 * No kernel module, no ubus daemon, no firewall changes, no flash writes.
 */
#include "common.h"
#include <getopt.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile sig_atomic_t stop = 0;
static int active_sec = OL_ACTIVE_SEC;
static int idle_sec = OL_IDLE_SEC;
/* 页面快通道的余温：任何一次 watched_now() 读到 1（CGI 轮询写入）都会把
 * fast_until 推到未来 2 秒。这期间主循环跑 active_sec（1s）节奏；没人看
 * 页面时退到 idle_sec，省 CPU。记账不受节奏影响：长连接的差分是单调
 * 计数器相减，快慢只影响差分粒度；短连接有 DESTROY 事件兜底。 */
static time_t fast_until = 0;

static void on_signal(int s) { (void)s; stop = 1; }

static int watched_now(void)
{
    char path[300], buf[16];
    FILE *f;
    size_t n;
    snprintf(path, sizeof(path), "%s/watched", G.dir);
    f = fopen(path, "r");
    if (!f) return 0;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    if (strchr(buf, '1')) {
        FILE *w = fopen(path, "w");
        if (w) fclose(w);
        fast_until = time(NULL) + 2;
        return 1;
    }
    return 0;
}

static void wait_round(double want)
{
    double deadline = ol_wall() + want;
    while (!stop) {
        double left = deadline - ol_wall();
        struct timespec ts;
        double nap;
        if (left <= 0) return;
        if (watched_now()) return;        /* page opened: switch to 1 Hz now */
        nap = left > 0.25 ? 0.25 : left;
        ts.tv_sec = (time_t)nap;
        ts.tv_nsec = (long)((nap - (double)ts.tv_sec) * 1e9);
        if (ts.tv_nsec < 0) ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
    }
}

static void usage(const char *argv0)
{
    printf("oaf-lite %s -- lightweight OAF-compatible user list sampler\n"
           "Usage: %s [options]\n"
           "  -i IF     LAN bridge to sample (default br-lan)\n"
           "  -d DIR    JSON output dir (default /tmp/oaf-lite)\n"
           "  -f FILE   OAF feature library, PLAINTEXT cfg or FWXB bin\n"
           "            (default /etc/fwxd/feature.cfg, fallback feature.bin)\n"
           "  -b MODE   conntrack | hnat-aggr | auto (default auto)\n"
           "  -T HOURS  timezone offset for day/hour buckets (default 8)\n"
           "  -s SEC    fast sampling while a page is open (default 1)\n"
           "  -S SEC    slow sampling when idle (default 3, was 15)\n"
           "  --selftest        run built-in protocol/feature/accounting tests\n"
           "  --probe-hnat      print raw `hw_nat -A AG` output and exit (read only)\n"
           "  -v                version\n", OL_VERSION, argv0);
}

static int probe_hnat(void)
{
    char out[4096];
    size_t n;
    FILE *p = popen("/sbin/hw_nat -A AG 2>&1", "r");
    if (!p) { printf("hw_nat unavailable\n"); return 1; }
    printf("--- hw_nat -A AG (single aggregate read, no -A 2 / -f / -g) ---\n");
    while ((n = fread(out, 1, sizeof(out), p)) > 0) fwrite(out, 1, n, stdout);
    pclose(p);
    printf("\n--- adapt hnat_parse_aggr() in acct.c to this format ---\n");
    return 0;
}

static int selftest(const char *feature)
{
    int fail = 0, plain_rules;
    char cmd[512], twin[512];
    const char *dot;
    snprintf(cmd, sizeof(cmd), "mkdir -p /tmp/oaf-lite-selftest/day");
    if (system(cmd) != 0) { printf("FAIL mkdir selftest dir\n"); return 1; }
    strncpy(G.dir, "/tmp/oaf-lite-selftest", sizeof(G.dir) - 1);
    G.dir[sizeof(G.dir) - 1] = '\0';
    G.tz_offset = 8 * 3600;
    G.now = time(NULL);
    setenv("OAF_LITE_STDERR", "1", 1);

    printf("=== feature library (plaintext): %s ===\n", feature);
    fail += feature_selftest(feature);
    plain_rules = feature_rule_count();

    /* The same library as FWXB ciphertext must give exactly the same index. */
    dot = strrchr(feature, '.');
    if (dot && strcmp(dot, ".cfg") == 0) {
        snprintf(twin, sizeof(twin), "%.*s.bin", (int)(dot - feature), feature);
        if (access(twin, F_OK) == 0) {
            int enc_rules;
            printf("\n=== feature library (encrypted twin): %s ===\n", twin);
            if (feature_load(twin) != 0) { printf("FAIL encrypted load\n"); fail++; }
            else {
                enc_rules = feature_rule_count();
                printf("%s encrypted rules=%d plaintext rules=%d\n",
                       enc_rules == plain_rules ? "PASS" : "FAIL",
                       enc_rules, plain_rules);
                if (enc_rules != plain_rules) fail++;
                feature_load(feature);   /* restore plaintext for later tests */
            }
        }
    }

    printf("\n=== protocol parser ===\n");
    fail += probe_selftest();
    printf("\n=== conntrack accounting + JSON ===\n");
    fail += acct_selftest();
    {
        FILE *f = fopen("/tmp/oaf-lite-selftest/hosts.json", "r");
        printf("%s observed-host diagnostic\n", f ? "PASS" : "FAIL");
        if (f) fclose(f); else fail++;
    }
    printf("\n=== result: %d failure(s) ===\n", fail);
    return fail ? 1 : 0;
}

int main(int argc, char **argv)
{
    int opt, full;
    const char *feature = NULL, *ifname = NULL, *dir = NULL;
    int do_selftest = 0, do_probe_hnat = 0, backend = -1;
    double prev, t0, dt;
    time_t last_full = 0, last_mac = 0;
    char today[16], cmd[512];

    memset(&G, 0, sizeof(G));
    G.tz_offset = 8 * 3600;
    strncpy(G.dir, "/tmp/oaf-lite", sizeof(G.dir) - 1);
    strncpy(G.lan_if, "br-lan", sizeof(G.lan_if) - 1);

    static struct option long_opts[] = {
        {"selftest", no_argument, 0, 1000},
        {"probe-hnat", no_argument, 0, 1001},
        {"help", no_argument, 0, 'h'},
        {NULL, 0, 0, 0}
    };
    while ((opt = getopt_long(argc, argv, "i:d:f:b:T:s:S:hv", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': ifname = optarg; break;
        case 'd': dir = optarg; break;
        case 'f': feature = optarg; break;
        case 'T': G.tz_offset = atoi(optarg) * 3600; break;
        case 's': active_sec = atoi(optarg); if (active_sec < 1) active_sec = 1; break;
        case 'S': idle_sec = atoi(optarg); if (idle_sec < 1) idle_sec = OL_IDLE_SEC; break;
        case 'b':
            if (!strcmp(optarg, "hnat-aggr")) backend = BACKEND_HNAT_AGGR;
            else if (!strcmp(optarg, "conntrack")) backend = BACKEND_CONNTRACK;
            else backend = -1;
            break;
        case 1000: do_selftest = 1; break;
        case 1001: do_probe_hnat = 1; break;
        case 'v': printf("oaf-lite %s\n", OL_VERSION); return 0;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }
    if (dir) { strncpy(G.dir, dir, sizeof(G.dir) - 1); G.dir[sizeof(G.dir) - 1] = '\0'; }
    if (ifname) { strncpy(G.lan_if, ifname, sizeof(G.lan_if) - 1); G.lan_if[sizeof(G.lan_if) - 1] = '\0'; }
    if (backend >= 0) G.backend = backend;

    if (do_probe_hnat) return probe_hnat();

    /* Feature library: plaintext first (user-editable), encrypted as fallback. */
    if (!feature) {
        struct stat st;
        feature = "/etc/fwxd/feature.cfg";
        if (stat(feature, &st) != 0) feature = "/etc/fwxd/feature.bin";
    }
    snprintf(G.feature_path, sizeof(G.feature_path), "%s", feature);

    if (do_selftest) return selftest(feature);

    if (feature_load(feature) != 0) {
        fprintf(stderr, "oaf-lite: cannot load feature library %s\n", feature);
        return 1;
    }
    /* 本地补充特征：按 id 追加域名，用来补官方库覆盖不到的 CDN。
     * 文件不存在是正常情况（回到纯官方库）。 */
    {
        char extra[256];
        const char *slash = strrchr(feature, '/');
        if (slash) {
            size_t dl = (size_t)(slash - feature);
            if (dl < sizeof(extra) - 32) {
                snprintf(extra, sizeof(extra), "%.*s/feature.local.cfg", (int)dl, feature);
                if (access(extra, R_OK) == 0) feature_load_extra(extra);
            }
        }
    }
    if (acct_init() != 0) { fprintf(stderr, "oaf-lite: acct_init failed\n"); return 1; }
    probe_init(G.lan_if);       /* failure is non-fatal: traffic still works */

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    signal(SIGHUP, SIG_IGN);

    snprintf(cmd, sizeof(cmd), "mkdir -p %s/day", G.dir);
    if (system(cmd) != 0) fprintf(stderr, "oaf-lite: cannot create %s/day\n", G.dir);
    ol_log("oaf-lite %s start: feature=%s rules=%d if=%s backend=%d active=%ds idle=%ds",
           OL_VERSION, feature, feature_rule_count(), G.lan_if,
           G.backend, active_sec, idle_sec);

    prev = ol_wall();
    last_mac = G.now;
    while (!stop) {
        int fast;
        t0 = ol_wall();
        G.now = time(NULL);
        dt = t0 - prev;
        if (dt < 0.05) dt = 0.05;
        prev = t0;
        watched_now();                 /* refresh the fast-channel window */
        fast = G.now < fast_until;
        ol_localdate("%Y-%m-%d", G.now, today, sizeof(today));
        if (strcmp(today, G.today) != 0) acct_roll_day(today);
        if (G.now - last_mac >= 60) { acct_refresh_macs(); last_mac = G.now; }

        probe_poll(OL_MAX_PKT_ROUND);
        acct_snapshot(G.now);
        acct_events(G.now);
        acct_hnat_poll(G.now);
        acct_settle(dt);
        acct_rates(dt);

        full = (last_full == 0) || (G.now - last_full >= OL_FULL_SEC);
        if (full) last_full = G.now;
        acct_write_json(full);

        /* 记账与节奏解耦：
         *
         * 以前这里用 `watched_now() ? active_sec : idle_sec`，也就是没人看
         * 页面时整循环退到 15 秒。但 acct_snapshot 的差分记账是在这个循环里
         * 做的：循环 15 秒一次时，一条 10 秒的下载从头到尾只被看到一次，那次
         * 只能建立基线，DESTROY 时再补剩下的——实测 337 MiB 记为 0 B。
         * 也就是说「没人看页面时统计会静默丢流量」，这与页面开不开毫无关系。
         *
         * 现在的取舍：快慢只影响差分粒度，不影响总量——
         *   - 长连接：conntrack 计数器单调递增，1s 差分和 3s 差分结果相同；
         *   - 短连接：两次快照之间生灭的，由 conntrack -E DESTROY 事件流
         *     兜底（事件带完整字节计数），不依赖快照间隔；
         *   - probe 的首包收进 socket 缓冲区等下一拍统一消费，BPF 只放行
         *     SYN / 端口命中包，几秒内不会撑爆 4 MB rcvbuf。
         * 因此 idle 时把整循环降到 idle_sec（默认 3s），CPU 约降为 1/3；
         * 页面打开（watched 文件每秒被 CGI 写 1）立即回 active_sec。
         * idle_sec 仍决定是否跳过完整快照序列化。 */
        {
            double target = fast ? (double)active_sec : (double)idle_sec;
            double spent = ol_wall() - t0;
            double left = target - spent;
            if (left > 0) wait_round(left);
        }
    }
    ol_log("oaf-lite stopping");
    probe_close();
    acct_close();
    return 0;
}
