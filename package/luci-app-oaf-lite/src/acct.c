/* Accounting: conntrack deltas + hardware-offload backends.
 *
 * Byte counters come from /proc/net/nf_conntrack (two snapshots) and the
 * DESTROY event feed. On the AN7581 open stack the PPE writes its MIB back
 * into conntrack (nf_flow_table_offload -> nf_ct_acct_add), so those counters
 * keep growing after offload. On vendor MTK closed HNAT that writeback may be
 * missing; an optional aggregate-compensation backend can be switched on,
 * clearly flagged as an estimate in stats.json.
 *
 * The emitted JSON is deliberately shaped like ponwrt's oaf_ctstat.lua output,
 * so the existing LuCI read layer only needs its paths changed.
 *
 * HARD RED LINE: never call `hw_nat -A 2`, `-f`, `-g` or loop `hw_nat -c`
 * over the whole table. Those have been measured to hard-hang the box and
 * trigger a watchdog reset. Only `-A AG` (one aggregate read) is used.
 */
#include "common.h"
#include <ctype.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>

#define IPMAC_SLOTS   4096
#define DNS_SLOTS     2048
#define DNS_TTL       3600
#define HNAT_INTERVAL 3
#define CT_LINE_MAX   1024

typedef struct { char ip[46], mac[18]; unsigned char used; } ipmac_t;
typedef struct { char ip[46], host[OL_MAX_HOST]; time_t at; unsigned char used; } dnsrec_t;
/* 远端 IP -> 应用 id。
 *
 * 硬件加速（PPE / HNAT / FOE）接管一条流之后，这条流就再也不路过 CPU，
 * 我们永远等不到它的 ClientHello。但真实流量不是「一条流吃满带宽」，
 * 而是「同一个 CDN IP 上开几十上百条连接」：只要其中任意一条在建立时
 * 被 AF_PACKET 抓到并认出了应用，这个 IP 的归属就确定了，剩下那些看不
 * 到首包的连接（包括守护进程启动前就已经在跑的大流）全部可以归到同一
 * 个应用上。没有这张表，几十 GB 的下载会一直堆在「未识别」里。 */
typedef struct { char ip[46]; int appid; time_t at; unsigned char used; } ipapp_t;
typedef struct {
    char s1[46], d1[46], s2[46], d2[46];
    unsigned p1, p2;
    uint64_t b1, b2;
    int mark, ipproto, fam;
} ct_rec_t;

static ipmac_t ipmac[IPMAC_SLOTS];
static dnsrec_t dnsc[DNS_SLOTS];

#define IPAPP_SLOTS 1024
#define IPAPP_TTL   1800
static ipapp_t ipapp[IPAPP_SLOTS];

static void ipapp_remember(const char *ip, int appid)
{
    uint32_t start, i;
    if (!ip || !*ip || appid <= 0) return;
    start = ol_hash_str(ip) % IPAPP_SLOTS;
    i = start;
    do {
        if (!ipapp[i].used || strcmp(ipapp[i].ip, ip) == 0 ||
            G.now - ipapp[i].at > IPAPP_TTL) {
            ipapp[i].used = 1;
            ipapp[i].appid = appid;
            ipapp[i].at = G.now;
            strncpy(ipapp[i].ip, ip, 45);
            ipapp[i].ip[45] = '\0';
            return;
        }
        i = (i + 1) % IPAPP_SLOTS;
    } while (i != start);
}

static int ipapp_lookup(const char *ip)
{
    uint32_t start, i;
    if (!ip || !*ip) return 0;
    start = ol_hash_str(ip) % IPAPP_SLOTS;
    i = start;
    do {
        if (!ipapp[i].used) return 0;
        if (strcmp(ipapp[i].ip, ip) == 0)
            return (G.now - ipapp[i].at > IPAPP_TTL) ? 0 : ipapp[i].appid;
        i = (i + 1) % IPAPP_SLOTS;
    } while (i != start);
    return 0;
}

/* OTHER breakdown: aggregate the bytes that landed in PROTO_OTHER by remote
 * (ipproto, dport) so the UI can explain what the big OTHER slice actually is
 * (e.g. udp/6667, tcp/11010) instead of a black box. On closed-HNAT boxes the
 * bulk of offloaded traffic never shows a first packet, so it ends up here. */
#define OL_OTHER_BUCKETS 256
typedef struct { uint32_t key; uint64_t up, down; } other_bucket_t;
static other_bucket_t other_buckets[OL_OTHER_BUCKETS];

static void other_accum(int ipproto, unsigned rport, uint64_t bytes)
{
    uint32_t key = ((uint32_t)ipproto << 16) | (rport & 0xffff);
    uint32_t i = key % OL_OTHER_BUCKETS;
    uint32_t start = i;
    do {
        if (other_buckets[i].key == 0) {
            other_buckets[i].key = key;
            other_buckets[i].up = 0;
        }
        if (other_buckets[i].key == key) {
            other_buckets[i].up += bytes;
            return;
        }
        i = (i + 1) % OL_OTHER_BUCKETS;
    } while (i != start);
}

static FILE *evf = NULL;
static time_t ev_at = 0;
static uint64_t hnat_last = 0;
static time_t hnat_at = 0;
static int warmup = 2;
static rate_sample_t g_rh[16];
static int g_rh_n = 0, g_rh_i = 0;

#define N(v) ol_num((uint64_t)(v), (char[24]){0}, 24)

/* ---------------------------------------------------------------- helpers */

static void expand6(const char *s, char out[46])
{
    uint8_t b[16];
    char tmp[64];
    char *p;
    int i, n = 0;
    strncpy(tmp, s, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    p = strchr(tmp, '%');
    if (p) *p = '\0';
    if (inet_pton(AF_INET6, tmp, b) != 1) {
        strncpy(out, s, 45); out[45] = '\0'; return;
    }
    for (i = 0; i < 16; i += 2)
        n += snprintf(out + n, 46 - (size_t)n, "%02x%02x%s",
                      b[i], b[i + 1], i < 14 ? ":" : "");
}

static void ip_key(const char *ip, char out[46])
{
    if (strchr(ip, ':')) expand6(ip, out);
    else { strncpy(out, ip, 45); out[45] = '\0'; }
}

static uint32_t slot_of(const char *s, uint32_t slots)
{
    return ol_hash_str(s) % slots;
}

static void ipmac_put(const char *ip, const char *mac)
{
    char key[46], norm[18];
    uint32_t i, start;
    int z;
    if (!ip || !*ip || !mac || !*mac) return;
    if (strncmp(mac, "00:00:00:00:00:00", 17) == 0) return;
    /* ARP prints lowercase, /proc/net/af_client uppercase. Normalise once so
     * a single device never ends up with two rows / two flow keys. */
    strncpy(norm, mac, 17); norm[17] = '\0';
    for (z = 0; norm[z]; z++) norm[z] = (char)toupper((unsigned char)norm[z]);
    mac = norm;
    ip_key(ip, key);
    i = start = slot_of(key, IPMAC_SLOTS);
    do {
        if (!ipmac[i].used) {
            ipmac[i].used = 1;
            strncpy(ipmac[i].ip, key, 45);
            strncpy(ipmac[i].mac, mac, 17);
            return;
        }
        if (strcmp(ipmac[i].ip, key) == 0) {
            strncpy(ipmac[i].mac, mac, 17);
            return;
        }
        i = (i + 1) % IPMAC_SLOTS;
    } while (i != start);
}

const char *acct_mac_for_ip(const char *ip)
{
    char key[46];
    uint32_t i, start;
    if (!ip || !*ip) return NULL;
    ip_key(ip, key);
    i = start = slot_of(key, IPMAC_SLOTS);
    do {
        if (!ipmac[i].used) return NULL;
        if (strcmp(ipmac[i].ip, key) == 0) return ipmac[i].mac;
        i = (i + 1) % IPMAC_SLOTS;
    } while (i != start);
    return NULL;
}

void acct_cache_dns(const char *ip, const char *host)
{
    char key[46];
    uint32_t i, start;
    if (!ip || !*ip || !host || !*host) return;
    ip_key(ip, key);
    i = start = slot_of(key, DNS_SLOTS);
    do {
        if (!dnsc[i].used || strcmp(dnsc[i].ip, key) == 0 ||
            G.now - dnsc[i].at > DNS_TTL) {
            dnsc[i].used = 1;
            dnsc[i].at = G.now;
            strncpy(dnsc[i].ip, key, 45);
            strncpy(dnsc[i].host, host, OL_MAX_HOST - 1);
            dnsc[i].host[OL_MAX_HOST - 1] = '\0';
            return;
        }
        i = (i + 1) % DNS_SLOTS;
    } while (i != start);
}

const char *acct_host_for_ip(const char *ip)
{
    char key[46];
    uint32_t i, start;
    if (!ip || !*ip) return NULL;
    ip_key(ip, key);
    i = start = slot_of(key, DNS_SLOTS);
    do {
        if (!dnsc[i].used) return NULL;
        if (strcmp(dnsc[i].ip, key) == 0 && G.now - dnsc[i].at <= DNS_TTL)
            return dnsc[i].host;
        i = (i + 1) % DNS_SLOTS;
    } while (i != start);
    return NULL;
}

static client_t *client_get(const char *mac, int create)
{
    int i;
    char key[18];
    if (!mac || !*mac) return NULL;
    strncpy(key, mac, 17); key[17] = '\0';
    for (i = 0; key[i]; i++) key[i] = (char)toupper((unsigned char)key[i]);
    for (i = 0; i < G.n_clients; i++)
        if (strcmp(G.clients[i].mac, key) == 0) return &G.clients[i];
    if (!create || G.n_clients >= OL_MAX_CLIENTS) return NULL;
    memset(&G.clients[G.n_clients], 0, sizeof(client_t));
    strncpy(G.clients[G.n_clients].mac, key, 17);
    return &G.clients[G.n_clients++];
}

/* Publish the address a device actually uses. DHCP leases are the most
 * trustworthy, then ARP, then the OAF kernel's af_client table. Without this
 * the list page's IP column was always blank (ipmac_put only filled the
 * reverse IP->MAC lookup, never the client row itself). */
static void client_addr(const char *mac, const char *addr, int fam, int prio)
{
    client_t *c;
    if (!mac || !*mac || !addr || !*addr) return;
    c = client_get(mac, 1);
    if (!c) return;
    if (fam == 6) {
        if (strncasecmp(addr, "fe80", 4) == 0) return;  /* link-local is noise */
        if (prio < c->addr6_prio) return;
        strncpy(c->ip6, addr, sizeof(c->ip6) - 1);
        c->ip6[sizeof(c->ip6) - 1] = '\0';
        c->addr6_prio = prio;
    } else {
        if (prio < c->addr_prio) return;
        strncpy(c->ip, addr, sizeof(c->ip) - 1);
        c->ip[sizeof(c->ip) - 1] = '\0';
        c->addr_prio = prio;
    }
}

static int app_get(client_t *c, int id)
{
    int i;
    if (!c->apps) {
        c->apps = (app_stat_t *)calloc(OL_MAX_APPS, sizeof(app_stat_t));
        if (!c->apps) return -1;
    }
    for (i = 0; i < c->n_apps; i++) if (c->apps[i].id == id) return i;
    if (c->n_apps >= OL_MAX_APPS) return -1;
    i = c->n_apps++;
    memset(&c->apps[i], 0, sizeof(app_stat_t));
    c->apps[i].id = id;
    return i;
}

static flow_t *flow_find(const char *key, int create)
{
    uint32_t i, start, hole = OL_MAX_FLOWS;
    if (!G.flows) return NULL;
    i = start = slot_of(key, OL_MAX_FLOWS);
    do {
        if (G.flows[i].used == 0) {
            if (!create) return NULL;
            if (hole == OL_MAX_FLOWS) hole = i;
            break;
        }
        if (G.flows[i].used == 2) {
            if (hole == OL_MAX_FLOWS) hole = i;
        } else if (strcmp(G.flows[i].key, key) == 0) {
            return &G.flows[i];
        }
        i = (i + 1) % OL_MAX_FLOWS;
    } while (i != start);
    if (!create || hole == OL_MAX_FLOWS) return NULL;
    memset(&G.flows[hole], 0, sizeof(flow_t));
    G.flows[hole].used = 1;
    G.flows[hole].proto = PROTO_OTHER;
    G.flows[hole].born = G.now;
    strncpy(G.flows[hole].key, key, OL_MAX_KEY - 1);
    return &G.flows[hole];
}

/* DESTROY can arrive after its flow was tombstoned. Recovering the stored
 * baseline lets us settle only the final delta; without this the whole
 * lifetime of the connection was charged a second time as OTHER. */
static flow_t *flow_find_any(const char *key)
{
    uint32_t i, start;
    if (!G.flows) return NULL;
    i = start = slot_of(key, OL_MAX_FLOWS);
    do {
        if (G.flows[i].used == 0) return NULL;
        if (strcmp(G.flows[i].key, key) == 0) return &G.flows[i];
        i = (i + 1) % OL_MAX_FLOWS;
    } while (i != start);
    return NULL;
}

/* Local hour of a timestamp. Called once per accounted flow per round, so a
 * single-slot cache (same-second calls are the norm: every conntrack row in
 * one snapshot carries the same `now`; a burst of DESTROY events shares its
 * timestamp too) turns gmtime_r+strftime+atoi into one integer compare. */
static int hour_idx(time_t ts)
{
    static time_t c_ts = -1;
    static int c_h = 0;
    char b[8];
    int h;
    if (ts == c_ts) return c_h;
    ol_localdate("%H", ts, b, sizeof(b));
    h = atoi(b);
    if (h < 0 || h > 23) h = 0;
    c_ts = ts;
    c_h = h;
    return h;
}

/* ---------------------------------------------------------------- MAC table */

void acct_refresh_macs(void)
{
    FILE *f;
    char line[512], ip[46], mac[18], v6[46], name[64];
    memset(ipmac, 0, sizeof(ipmac));

    f = fopen("/proc/net/af_client", "r");
    if (f) {
        fgets(line, sizeof(line), f);        /* column header */
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%*d %17s %45s %45s", mac, ip, v6) == 3) {
                if (strcmp(ip, "0.0.0.0") != 0) {
                    ipmac_put(ip, mac);
                    client_addr(mac, ip, 4, 1);
                }
                if (strcmp(v6, "::") != 0) {
                    ipmac_put(v6, mac);
                    client_addr(mac, v6, 6, 1);
                }
            }
        }
        fclose(f);
    }
    f = fopen("/proc/net/arp", "r");
    if (f) {
        fgets(line, sizeof(line), f);        /* "IP address HW type ..." header */
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%45s %*s %*s %17s", ip, mac) == 2 &&
                strchr(ip, '.') && strchr(mac, ':')) {
                ipmac_put(ip, mac);
                client_addr(mac, ip, 4, 2);
            }
        }
        fclose(f);
    }
    f = fopen("/tmp/dhcp.leases", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            name[0] = '\0';
            if (sscanf(line, "%*s %17s %45s %63s", mac, ip, name) >= 2) {
                ipmac_put(ip, mac);
                client_addr(mac, ip, 4, 3);
                /* dnsmasq writes interface names (wlan0 / br-lan) as the
                 * hostname when the client sent none - don't show those. */
                if (name[0] && strcmp(name, "*") != 0 &&
                    strncmp(name, "wlan", 4) != 0 &&
                    strncmp(name, "br-", 3) != 0) {
                    client_t *c = client_get(mac, 1);
                    if (c && !c->name[0]) {
                        strncpy(c->name, name, sizeof(c->name) - 1);
                        c->name[sizeof(c->name) - 1] = '\0';
                    }
                }
            }
        }
        fclose(f);
    }
    f = popen("ip -6 neigh show 2>/dev/null", "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "%45s dev %*s lladdr %17s", ip, mac) == 2) {
                ipmac_put(ip, mac);
                client_addr(mac, ip, 6, 2);
            }
        }
        pclose(f);
    }
    /* Make sure every known MAC has a client row, so idle devices still show. */
    {
        int i;
        for (i = 0; i < IPMAC_SLOTS; i++)
            if (ipmac[i].used) client_get(ipmac[i].mac, 1);
    }
}

/* ---------------------------------------------------------------- L7 binding */

/* 只把外网域名写进 URL 列。
 *
 * 采样器看到的是「这台设备最近连了谁」，里面混着大量局域网目标：网关
 * 192.168.1.1、wpad.lan、单标签主机名、mDNS 的 .local。这些地址在页面上
 * 没有信息量，还会把真正的上网目标挤掉，所以在这里统一挡掉：
 *   1) IPv6 字面量（带 ':'）—— 不可能是可读的外网域名
 *   2) IPv4 字面量里的私有/保留段（10/8、172.16/12、192.168/16、169.254/16、
 *      127/8、100.64/10 CGNAT），公网 v4 字面量保留
 *   3) 单标签主机名（wpad、router）
 *   4) .lan / .local / .localdomain / .home / .internal / .intranet / .arpa
 */
static int host_is_external(const char *h)
{
    const char *dot;
    unsigned a = 0, b = 0, c = 0, d = 0;

    if (!h || !*h) return 0;

    if (strchr(h, ':')) return 0;          /* IPv6 字面量 */

    if (sscanf(h, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        if (a == 0 || a == 10 || a == 127) return 0;
        if (a == 192 && b == 168) return 0;
        if (a == 172 && b >= 16 && b <= 31) return 0;
        if (a == 169 && b == 254) return 0;
        if (a == 100 && b >= 64 && b <= 127) return 0;
        return 1;                          /* 公网 IPv4 字面量 */
    }

    dot = strrchr(h, '.');
    if (!dot) return 0;                    /* 单标签主机名 */

    if (!strcasecmp(dot, ".lan") || !strcasecmp(dot, ".local") ||
        !strcasecmp(dot, ".localdomain") || !strcasecmp(dot, ".home") ||
        !strcasecmp(dot, ".internal") || !strcasecmp(dot, ".intranet") ||
        !strcasecmp(dot, ".arpa"))
        return 0;

    return 1;
}

/* Remember the last hostname a client was seen talking to. The page's URL
 * column needs "what is this device visiting right now", which the OAF build
 * took from fwx; oaf-lite has to keep it itself. Only the newest hostname is
 * kept (plus a timestamp) — a full per-client host history would be far more
 * memory than a home router should spend on a table column. */
void acct_note_client_host(const char *ip, const char *host)
{
    int i;
    if (!ip || !*ip || !host || !*host) return;
    if (!host_is_external(host)) return;   /* 内网地址不进 URL 列 */
    for (i = 0; i < G.n_clients; i++) {
        if (strcmp(G.clients[i].ip, ip) == 0) {
            strncpy(G.clients[i].host, host, sizeof(G.clients[i].host) - 1);
            G.clients[i].host[sizeof(G.clients[i].host) - 1] = '\0';
            G.clients[i].host_ts = G.now;
            return;
        }
    }
}

void acct_bind_flow(const probe_result_t *r)
{
    flow_t *f = flow_find(r->key, 1);
    const char *m;
    if (!f) return;
    if (!f->mac[0]) {
        m = acct_mac_for_ip(r->client_ip);
        strncpy(f->mac, (m && *m) ? m : r->mac, 17);
        f->mac[17] = '\0';
    }
    if (!f->ip[0]) {
        strncpy(f->ip, r->client_ip, 45);
        strncpy(f->remote, r->remote_ip, 45);
    }
    f->fam = r->fam;
    f->ipproto = r->ipproto;
    if (f->pkts >= OL_MAX_FLOW_PKTS) return;    /* sampled enough for this flow */
    f->pkts++;
    if (r->host[0] && !f->host[0]) {
        strncpy(f->host, r->host, sizeof(f->host) - 1);
        f->host[sizeof(f->host) - 1] = '\0';
    }
    if (r->host[0]) acct_note_client_host(r->client_ip, r->host);
    /* 把 SNI / HTTP Host 也写进「远端 IP -> 域名」这张表。
     *
     * 这是硬件加速下最关键的一条兜底：PPE/HNAT 接管之后，一条流只有刚
     * 建立时的几个包会路过 CPU。SDK 的下载、视频的分片，几乎都落在
     * 「同一个 CDN IP 上开几十条新连接」的形态——只要其中任意一条被
     * 抓到过 ClientHello，这个 IP 就有名字了，后面所有看不到首包的
     * 连接（包括守护进程启动前就已经在跑的、一直在灌流量的大流）都能
     * 靠 acct_host_for_ip() 晚绑定认出来，而不是全部堆进「未识别」。 */
    if (r->host[0] && r->remote_ip[0] && r->appid > 0)
        acct_cache_dns(r->remote_ip, r->host);
    if (r->appid > 0 && f->appid == 0) f->appid = r->appid;
    if (r->proto_fixed) {
        /* A RST at teardown is not a failed connection when we already know
         * what the flow was. Keep the earlier, more specific label. */
        if (!(f->proto_fixed && r->proto == PROTO_FAILED)) {
            f->proto = r->proto;
            f->proto_fixed = 1;
        }
    } else if (!f->proto_fixed && r->proto != PROTO_OTHER) {
        f->proto = r->proto;
    }
    if (r->is_syn) f->syn_only = 1;
    else if (r->proto_fixed) f->syn_only = 0;
}

/* ---------------------------------------------------------------- conntrack */

static char gw_ip4[46];

/* Traffic destined to the router itself (SSH, LuCI, local DNS) is LAN
 * management traffic, not a client's Internet usage. One 2.75 MB deploy over
 * SSH was measured as 2.9 MB of OTHER against 192.168.1.100.
 * Only the ORIGINAL direction's dst is compared: NAT reply tuples also carry
 * the gateway IP (as src) and those are perfectly real WAN flows. */
static void gw_detect(const char *ifname)
{
    struct ifaddrs *ifa, *p;
    gw_ip4[0] = '\0';
    if (getifaddrs(&ifa) != 0) return;
    for (p = ifa; p; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(p->ifa_name, "lo") == 0) continue;
        if (ifname && *ifname && strcmp(p->ifa_name, ifname) != 0) continue;
        inet_ntop(AF_INET,
                  &((struct sockaddr_in *)p->ifa_addr)->sin_addr,
                  gw_ip4, sizeof(gw_ip4));
        break;
    }
    freeifaddrs(ifa);
}

/* Connections that were already hardware-offloaded, or that existed before
 * the daemon started, never present a first packet to AF_PACKET. Their L4
 * port is all we have. This must not set proto_fixed: a later real payload
 * verdict is more specific and is allowed to override the guess. */
static int proto_by_port(unsigned rport, int ipproto)
{
    if (ipproto == 6) {
        if (rport == 443 || rport == 8443) return PROTO_TLS;
        if (rport == 80 || rport == 8080) return PROTO_HTTP;
    } else if (ipproto == 17) {
        if (rport == 443) return PROTO_QUIC;
        if (rport == 53 || rport == 5353) return PROTO_DNS;
    }
    return PROTO_OTHER;
}

/* LAN broadcast / multicast is discovery noise, not Internet traffic. Measured
 * on the box: three 255.255.255.255:6667 entries and one 192.168.1.255:5001
 * entry each carried ~500 KB of cumulative conntrack bytes and were charged
 * straight into OTHER. Deliberately does NOT drop LAN unicast (casting, SMB). */
static int ct_is_lan_noise(const char *s, const char *d)
{
    unsigned a, b, c, e, sa, sb, sc, sd;
    if (!d || !*d) return 1;
    if (strchr(d, ':')) return strncasecmp(d, "ff", 2) == 0;  /* IPv6 mcast */
    if (sscanf(d, "%u.%u.%u.%u", &a, &b, &c, &e) != 4) return 1;
    if (a == 255 && b == 255 && c == 255 && e == 255) return 1;
    if (a >= 224 && a <= 239) return 1;                       /* IPv4 mcast */
    if (a == 0 || a == 127) return 1;
    /* A .255 tail is a directed broadcast only when both ends share a /24;
     * on a /23 or wider net it can be a perfectly valid host address. */
    if (e == 255 && s && sscanf(s, "%u.%u.%u.%u", &sa, &sb, &sc, &sd) == 4
        && sa == a && sb == b && sc == c) return 1;
    return 0;
}

static int kv(const char *line, const char *key, int nth, char *out, size_t cap)
{
    const char *p = line;
    size_t kl = strlen(key);
    int seen = 0;
    while ((p = strstr(p, key)) != NULL) {
        const char *v;
        size_t n = 0;
        if (p != line && !isspace((unsigned char)p[-1])) { p += kl; continue; }
        if (seen++ != nth) { p += kl; continue; }
        v = p + kl;
        while (*v && !isspace((unsigned char)*v) && n + 1 < cap) out[n++] = *v++;
        out[n] = '\0';
        return 1;
    }
    return 0;
}

static int parse_ct_line(const char *line, ct_rec_t *o)
{
    char b1[32], b2[32], p1[16], p2[16], mk[16], t[16], c[16], id[16];
    int num = 0;
    memset(o, 0, sizeof(*o));
    o->fam = (strncmp(line, "ipv6", 4) == 0) ? 6 : 4;
    /* Derive ipproto from the L4 protocol word. The old position-based sscanf
     * ("%*s %*d %*s %d") only matches the "ipv4 2 tcp 6" prefix; on some kernels
     * the line is "tcp 6 ..." without the leading family/ttl tokens, which left
     * ipproto = 0 and broke every port-based decision. */
    if (strstr(line, "tcp6") || strstr(line, " tcp "))
        o->ipproto = 6;
    else if (strstr(line, "udp6") || strstr(line, " udp "))
        o->ipproto = 17;
    else if (strstr(line, "icmp6") || strstr(line, "icmp"))
        o->ipproto = 1;
    else if (sscanf(line, "%*s %*d %*s %d", &num) == 1)
        o->ipproto = num;
    else
        o->ipproto = 0;
    if (!kv(line, "src=", 0, o->s1, sizeof(o->s1))) return 0;
    if (!kv(line, "dst=", 0, o->d1, sizeof(o->d1))) return 0;
    kv(line, "src=", 1, o->s2, sizeof(o->s2));
    kv(line, "dst=", 1, o->d2, sizeof(o->d2));
    /* IPv6 的写法必须先统一，否则同一连接会变成两条不同的流。
     *
     * /proc/net/nf_conntrack 打印的是补零全写：
     *   2409:8087:2001:0010:0000:0000:2786:4d63
     * conntrack -E 打出的事件却是压缩写：
     *   2409:8087:2001:10::2786:4d63
     * 快照按前者的文本拼 key 建了流记录，DESTROY 按后者的文本找不到它 →
     * 走「没见过的流」全量记账，快照已经记过的几 GB 又被记一遍。实测一台
     * 机器 116 MB/s 的 IPv6 压测，统计能翻到 2 倍、瞬时速率冲到 475 MB/s。
     *
     * ip_key()/expand6() 早就在 MAC 表、DNS 表里做了这件事，只有流 key 这
     * 一条路是用原始文本拼的，所以这里是唯一需要改的地方。 */
    {
        char c1[46];
        ip_key(o->s1, c1); strncpy(o->s1, c1, sizeof(o->s1) - 1); o->s1[45] = '\0';
        ip_key(o->d1, c1); strncpy(o->d1, c1, sizeof(o->d1) - 1); o->d1[45] = '\0';
        if (o->s2[0]) { ip_key(o->s2, c1); strncpy(o->s2, c1, sizeof(o->s2) - 1); o->s2[45] = '\0'; }
        if (o->d2[0]) { ip_key(o->d2, c1); strncpy(o->d2, c1, sizeof(o->d2) - 1); o->d2[45] = '\0'; }
    }
    if (ct_is_lan_noise(o->s1, o->d1)) return 0;
    /* orig dst == gateway itself -> local management, not Internet traffic */
    if (gw_ip4[0] && strcmp(o->d1, gw_ip4) == 0) return 0;
    if (o->d2[0] && ct_is_lan_noise(o->s2, o->d2)) return 0;
    if (kv(line, "sport=", 0, p1, sizeof(p1))) o->p1 = (unsigned)atoi(p1);
    else if (kv(line, "type=", 0, t, sizeof(t)) && kv(line, "code=", 0, c, sizeof(c)))
        o->p1 = (unsigned)(atoi(t) * 256 + atoi(c));
    if (kv(line, "dport=", 0, p2, sizeof(p2))) o->p2 = (unsigned)atoi(p2);
    else if (kv(line, "id=", 0, id, sizeof(id))) o->p2 = (unsigned)atoi(id);
    if (!kv(line, "bytes=", 0, b1, sizeof(b1))) return 0;
    if (!kv(line, "bytes=", 1, b2, sizeof(b2))) b2[0] = '\0';
    o->b1 = strtoull(b1, NULL, 10);
    o->b2 = b2[0] ? strtoull(b2, NULL, 10) : 0;
    if (kv(line, "mark=", 0, mk, sizeof(mk))) o->mark = atoi(mk);
    return 1;
}

static void account(const char *mac, uint64_t du, uint64_t dd,
                    int appid, int proto, int fam, time_t ts)
{
    client_t *c = client_get(mac, 1);
    app_stat_t *a;
    int ai, h;
    if (!c || (du == 0 && dd == 0)) return;
    h = hour_idx(ts);
    if (h < 0 || h > 23) h = 0;
    c->up += du; c->down += dd;
    c->hours[h].up += du; c->hours[h].down += dd;
    if (fam == 6) { c->up6 += du; c->down6 += dd; }
    ai = app_get(c, appid);
    if (ai >= 0) {
        a = &c->apps[ai];
        a->up += du; a->down += dd;
        a->hours[h].up += du; a->hours[h].down += dd;
        c->round_appbytes[ai] += du + dd;
    }
    c->proto[proto].up += du;
    c->proto[proto].down += dd;
    c->round_bytes += du + dd;
    G.total_up += du; G.total_down += dd;
    G.hours[h].up += du; G.hours[h].down += dd;
    G.proto[proto].up += du; G.proto[proto].down += dd;
}

/* 没有基线时的全量记账要有个天花板。
 * 正常情况下「流表里没有它、却收到 DESTROY」只可能是两拍之间就结束的短
 * 连接；但如果我们漏看了它一辈子（IPv6 邻居表还没建立、表满被回收等），
 * 一次就能把几 GB 的历史算进今天。超过 OL_UNSEEN_CLAMP 的按比例压回，
 * 并留一条日志方便定位。 */
static void clamp_unseen(const char *mac, const char *key,
                         uint64_t *up, uint64_t *down)
{
    uint64_t total = *up + *down;
    if (total <= OL_UNSEEN_CLAMP) return;
    ol_log("acct: unseen flow %s %s %llu bytes, clamped to 2 GiB",
           mac, key, (unsigned long long)total);
    *up = (uint64_t)((double)*up * (double)OL_UNSEEN_CLAMP / (double)total);
    *down = (uint64_t)((double)*down * (double)OL_UNSEEN_CLAMP / (double)total);
}

/* Normalise a conntrack row to the same key the packet probe uses, and settle
 * the byte delta. destroy=1 means the flow is gone (DESTROY event).
 * hint/hint_dir: when the caller already resolved which side is our LAN
 * client (snapshot pre-filter), skip the two redundant ipmac hash lookups.
 * hint==0 falls back to the self-contained lookup used by the event feed. */
static void ct_settle(const ct_rec_t *o, time_t ts, int destroy,
                      const char *hint, int hint_dir)
{
    const char *m1, *m2, *mac, *remote;
    char key[OL_MAX_KEY];
    uint64_t up, down, du = 0, dd = 0;
    unsigned rport;
    int fam, appid;
    flow_t *f;

    if (hint && *hint) {
        m1 = hint_dir ? hint : NULL;
        m2 = hint_dir ? NULL : hint;
    } else {
        m1 = acct_mac_for_ip(o->s1);
        m2 = acct_mac_for_ip(o->s2);
    }
    if (m1 && *m1) {
        mac = m1;
        remote = o->d1;
        rport = o->p2;
        snprintf(key, sizeof(key), "%s|%s|%u|%u|%d",
                 o->s1, o->d1, o->p1, o->p2, o->ipproto);
        up = o->b1; down = o->b2;
    } else if (m2 && *m2) {
        mac = m2;
        remote = o->s1;
        rport = o->p1;
        snprintf(key, sizeof(key), "%s|%s|%u|%u|%d",
                 o->s2, o->s1, o->p2, o->p1, o->ipproto);
        up = o->b2; down = o->b1;
    } else {
        return;     /* not one of our LAN clients */
    }
    fam = strchr(o->s1, ':') ? 6 : 4;
    f = destroy ? flow_find_any(key) : flow_find(key, 1);
    if (!f) {
        /* Born and destroyed entirely between two snapshots: the DESTROY
         * event carries the whole connection. It still deserves a proper
         * protocol label and a DNS-cache app lookup. */
        if (destroy) {
            const char *h = acct_host_for_ip(remote);
            int app = 0;
            int p = proto_by_port(rport, o->ipproto);
            if (h && *h) feature_lookup(h, (int)rport, o->ipproto, &app);
            clamp_unseen(mac, key, &up, &down);
            if (p == PROTO_OTHER && (up || down))
                other_accum(o->ipproto, rport, up + down);
            account(mac, up, down, app, p, fam, ts);
        }
        return;
    }
    if (!f->mac[0]) { strncpy(f->mac, mac, 17); f->mac[17] = '\0'; }
    if (!f->remote[0] && remote) {
        strncpy(f->remote, remote, sizeof(f->remote) - 1);
        f->remote[sizeof(f->remote) - 1] = '\0';
    }
    f->fam = fam;
    f->ipproto = o->ipproto;
    appid = o->mark % 65536;
    if (appid > 0 && appid < 32000 && f->appid == 0) f->appid = appid;

    /* Flows that were already offloaded when the daemon started never show a
     * first packet. Fall back to the well-known ports so the protocol chart
     * is not 97% OTHER, without blocking a later real payload verdict. */
    if (!f->proto_fixed && f->proto == PROTO_OTHER) {
        int guess = proto_by_port(rport, o->ipproto);
        if (guess != PROTO_OTHER) f->proto = guess;
    }
    /* Late binding: a DNS answer may arrive after the flow was created. Keep
     * trying to attach an app id until one sticks. */
    if (f->appid == 0) {
        const char *h = f->host[0] ? f->host : acct_host_for_ip(f->remote);
        if (h && *h) {
            int late = 0;
            if (!f->host[0]) {
                strncpy(f->host, h, sizeof(f->host) - 1);
                f->host[sizeof(f->host) - 1] = '\0';
            }
            feature_lookup(h, (int)rport, o->ipproto, &late);
            if (late > 0) f->appid = late;
        }
    }
    /* 同 IP 归因排在域名之后：域名是更精确的证据，实在没有了才退到
     * 「这个 IP 上的别的流是什么应用」。 */
    if (f->remote[0]) {
        if (f->appid > 0) ipapp_remember(f->remote, f->appid);
        else {
            int known = ipapp_lookup(f->remote);
            if (known > 0) f->appid = known;
        }
    }
    if (f->syn_only && !f->proto_fixed && ts - f->born > 5) {
        f->proto = PROTO_FAILED;      /* SYN with no answer */
        f->proto_fixed = 1;
    }
    if (!f->has_base) {
        if (!destroy) {
            /* First snapshot sighting is a baseline only, no bytes yet. */
            f->base_up = up; f->base_down = down; f->has_base = 1;
            return;
        }
        /* Never seen by a snapshot, but now destroyed: the whole connection
         * is the delta. Previously this fell through to du = up - base_up = 0
         * and silently dropped all such short connections. */
        du = up; dd = down;
        clamp_unseen(mac, key, &du, &dd);
    } else {
        du = up > f->base_up ? up - f->base_up : 0;
        dd = down > f->base_down ? down - f->base_down : 0;
    }
    f->base_up = up; f->base_down = down; f->has_base = 1;
    if ((du || dd) && !f->proto_counted) {
        /* One connection contributes one "flow" to its protocol bucket.
         * Count on the first byte delta, by which time the L7 probe has
         * normally already labelled the flow. */
        client_t *c = client_get(mac, 1);
        if (c && f->proto >= 0 && f->proto < PROTO_MAX) {
            c->proto_flows[f->proto]++;
            f->proto_counted = 1;
        }
    }
    if (du || dd) {
        if (f->proto == PROTO_OTHER)
            other_accum(o->ipproto, rport, du + dd);
        account(mac, du, dd, f->appid, f->proto, fam, ts);
    }
    if (destroy) f->used = 2;         /* tombstone */
    else { f->seen = G.round; f->gone_at = 0; }
}

/* Cheap pre-filter: pull just the two src= addresses out of a conntrack line.
 * The full parse_ct_line costs ~10 strstr scans of the whole line; rows that
 * belong to nobody in our MAC table (the router itself, WAN peers, other LAN
 * segments -- typically 90%+ of the table) can be rejected after two strstr
 * calls and two O(1) hash probes. */
static int ct_src_peek(const char *line, char *s1, size_t n1, char *s2, size_t n2)
{
    const char *p = strstr(line, "src=");
    const char *q;
    size_t k = 0;
    if (!p) return 0;
    p += 4;
    while (p[k] && !isspace((unsigned char)p[k]) && k + 1 < n1) k++;
    memcpy(s1, p, k);
    s1[k] = '\0';
    s2[0] = '\0';
    q = strstr(p, "src=");
    if (!q) return 1;
    q += 4;
    k = 0;
    while (q[k] && !isspace((unsigned char)q[k]) && k + 1 < n2) k++;
    memcpy(s2, q, k);
    s2[k] = '\0';
    return 1;
}

void acct_snapshot(time_t now)
{
    FILE *f;
    char line[CT_LINE_MAX];
    int i;
    G.round++;
    for (i = 0; i < G.n_clients; i++) {
        G.clients[i].flows = 0;
        G.clients[i].flows6 = 0;
    }
    f = fopen("/proc/net/nf_conntrack", "r");
    if (!f) { ol_log("acct: /proc/net/nf_conntrack unavailable"); return; }
    while (fgets(line, sizeof(line), f)) {
        char sa[46], sb[46];
        const char *m;
        int m_is_s1 = 1;
        ct_rec_t o;
        client_t *c;
        if (!ct_src_peek(line, sa, sizeof(sa), sb, sizeof(sb))) continue;
        m = acct_mac_for_ip(sa);
        if (!m) { m = acct_mac_for_ip(sb); m_is_s1 = 0; }
        if (!m) continue;              /* not one of our LAN clients */
        /* parse before counting: LAN-noise / gateway-local rows must not
         * flip a device's "online" state (parse_ct_line rejects them). */
        if (!parse_ct_line(line, &o)) continue;
        c = client_get(m, 1);
        if (c) {
            c->flows++;
            if (strchr(o.s1, ':')) c->flows6++;
        }
        ct_settle(&o, now, 0, m, m_is_s1);
    }
    fclose(f);
    if (!G.flows) return;
    for (i = 0; i < OL_MAX_FLOWS; i++) {
        flow_t *fl = &G.flows[i];
        if (fl->used != 1 || fl->seen == G.round) continue;
        if (fl->gone_at == 0) fl->gone_at = now;
        if (now - fl->gone_at > OL_GONE_TTL) fl->used = 2;
    }
}

void acct_events(time_t now)
{
    char line[CT_LINE_MAX];
    int n = 0;
    if (!evf) {
        if (now - ev_at < 30) return;
        ev_at = now;
        evf = popen("conntrack -E -e DESTROY -o timestamp 2>/dev/null", "r");
        if (!evf) return;
        fcntl(fileno(evf), F_SETFL, O_NONBLOCK);
        ol_log("acct: DESTROY event feed started");
    }
    while (n < OL_EVENTS_MAX) {
        ct_rec_t o;
        double tss;
        time_t ts;
        if (!fgets(line, sizeof(line), evf)) {
            if (feof(evf)) { pclose(evf); evf = NULL; ev_at = 0; return; }
            clearerr(evf);
            return;
        }
        n++;
        if (!strstr(line, "[DESTROY]")) continue;
        tss = strtod(strchr(line, '[') ? strchr(line, '[') + 1 : "0", NULL);
        ts = (time_t)tss;
        if (ts < G.boot_ts) continue;      /* buffered event from before boot */
        if (!parse_ct_line(line, &o)) continue;
        ct_settle(&o, ts, 1, NULL, 0);
    }
}

/* ---------------------------------------------------------------- HNAT backends */

static int hnat_detect(void)
{
    struct stat st;
    if (G.backend == BACKEND_HNAT_AGGR) {
        snprintf(G.backend_note, sizeof(G.backend_note),
                 "vendor closed HNAT: aggregate estimate (hw_nat -A AG only)");
        return G.backend;
    }
    if (stat("/sys/module/airoha_ppe", &st) == 0 ||
        stat("/sys/module/mtk_ppe", &st) == 0) {
        snprintf(G.backend_note, sizeof(G.backend_note),
                 "open PPE / nft flowtable: conntrack MIB writeback");
        return BACKEND_CONNTRACK;
    }
    if (stat("/sys/module/hw_nat", &st) == 0 ||
        stat("/dev/hwnat0", &st) == 0) {
        snprintf(G.backend_note, sizeof(G.backend_note),
                 "vendor closed HNAT detected; conntrack writeback assumed (enable hnat_aggr to compensate)");
        G.hw_offload_unreliable = 1;
        return BACKEND_CONNTRACK;
    }
    snprintf(G.backend_note, sizeof(G.backend_note),
             "software / conntrack-only");
    return BACKEND_CONNTRACK;
}

/* Vendor `hw_nat -A AG` output seen on the TC3162 / closed-HNAT box:
 *     Byte cnt=0
 *     Pkt cnt=0
 *     done
 * Prefer the labelled byte counter: taking "the largest number on the line"
 * would misread Pkt cnt (or an entry index) as bytes. A bare-number fallback
 * is kept for vendors that print only a decimal counter. Use
 * `oaf-lite --probe-hnat` on a new SDK and extend the label list here.
 * NOTE: on some vendor stacks AG counting is not enabled at all and the
 * counter stays 0; acct_hnat_poll() then degrades back to conntrack. */
static uint64_t hnat_parse_aggr(const char *text, uint64_t *best)
{
    const char *p = text;
    uint64_t found = 0, fallback = 0, v;
    char *end;
    while (*p) {
        const char *line = p, *q, *stop;
        const char *nl = strchr(p, '\n');
        stop = nl ? nl : line + strlen(line);
        for (q = line; q + 4 <= stop; q++) {
            if (strncasecmp(q, "byte", 4) == 0) {
                q += 4;
                while (q < stop && !isdigit((unsigned char)*q)) q++;
                if (q < stop) {
                    v = strtoull(q, &end, 10);
                    if (end > q) found = v;
                }
                break;
            }
        }
        for (q = line; q < stop; q++) {
            if (isdigit((unsigned char)*q)) {
                v = strtoull(q, &end, 10);
                if (end > stop) break;
                if (end > q && v > 1024 && v > fallback) fallback = v;
                if (end > q) q = end - 1;
            }
        }
        if (!nl) break;
        p = nl + 1;
    }
    if (!found) found = fallback;
    if (found) *best = found;
    return found;
}

void acct_hnat_poll(time_t now)
{
    char out[4096];
    size_t n;
    uint64_t hw = 0, delta;
    FILE *p;
    int i;
    if (G.backend != BACKEND_HNAT_AGGR || now - hnat_at < HNAT_INTERVAL) return;
    hnat_at = now;
    p = popen("/sbin/hw_nat -A AG 2>/dev/null", "r");
    if (!p) { G.degraded = 1; return; }
    n = fread(out, 1, sizeof(out) - 1, p);
    out[n] = '\0';
    pclose(p);
    if (hnat_parse_aggr(out, &hw) == 0) {
        ol_log("hnat: AG output not parseable, falling back to conntrack");
        snprintf(G.backend_note, sizeof(G.backend_note),
                 "HNAT AG unparseable; conntrack only (see --probe-hnat)");
        G.backend = BACKEND_CONNTRACK;
        G.degraded = 1;
        return;
    }
    if (hnat_last == 0 || hw <= hnat_last) { hnat_last = hw; return; }
    delta = hw - hnat_last;
    hnat_last = hw;
    {
        uint64_t ct_delta = 0;
        for (i = 0; i < G.n_clients; i++) ct_delta += G.clients[i].round_bytes;
        if (delta > ct_delta + 1048576) {
            uint64_t extra = delta - ct_delta;
            /* Distribute the residual by each client's share of this window.
             * This is an ESTIMATE: the aggregate counter has no per-flow key. */
            for (i = 0; i < G.n_clients; i++) {
                client_t *c = &G.clients[i];
                uint64_t share;
                if (ct_delta == 0 || c->round_bytes == 0) continue;
                share = (uint64_t)((double)extra * c->round_bytes / ct_delta);
                c->down += share;
                c->hours[hour_idx(now)].down += share;
                G.total_down += share;
                G.hours[hour_idx(now)].down += share;
                G.proto[PROTO_OTHER].down += share;
            }
            G.degraded = 1;
        }
    }
}

/* ---------------------------------------------------------------- windows */

void acct_settle(double dt)
{
    int i, j, h = hour_idx(G.now);
    if (h < 0 || h > 23) h = 0;
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        if (c->round_bytes >= OL_ACTIVE_MIN) c->day_active += dt;
        /* 在线 = 这一刻真的有活跃连接，或者这一刻真的在走字节。
         *
         * 这里原来写的是 `c->flows > 0 || c->day_active > 0`，而 day_active 是
         * 当天累计值：只要设备当天传过一个字节，这个条件就永远成立，于是设备
         * 早就断电离线了，day_online 还在每秒往上加，一天能涨满 24 小时。
         * 改成看「当前拍」的信号：有活连接（flows）或这一拍有字节（round_bytes，
         * 每拍末尾会被清零），离线后自然停止累加。
         * 只保留 flow 一个条件会让「连着但闲着」的设备不算在线，所以两个都看。 */
        if (c->flows > 0 || c->round_bytes >= OL_ACTIVE_MIN) c->day_online += dt;
        if (c->apps) {
            for (j = 0; j < c->n_apps; j++) {
                if (c->round_appbytes[j] >= OL_ACTIVE_MIN)
                    c->apps[j].active[h] += dt;
            }
        }
        c->round_bytes = 0;
        memset(c->round_appbytes, 0, sizeof(c->round_appbytes));
    }
}

/* 速率 = 窗口首尾的累计字节差 ÷ 窗口真实时长。
 *
 * 这里以前存的是「每拍增量」，再除以累加出来的 dt。在硬件加速的机器上这条
 * 路会崩：PPE 条目被回收时会把最后一次轮询之后的计数一次性刷进 conntrack，
 * 一批就是几百 MB。如果这一批正好落在 dt 很小的一拍上，这一拍算出来的瞬时
 * 速率就是几百 MB/s，9 秒窗口平均也拉不回来 —— 实测下行 116 MB/s 会显示成
 * 475 MB/s。
 *
 * 改成窗口首尾的累计差之后：分子是这段时间真实涨了多少字节，分母是真实过
 * 了多少秒，单拍的抖动被自然摊平，也不再依赖每拍 dt 的精度。
 */
static void win_rate(rate_sample_t *h, int *n, int *i,
                     uint64_t cu, uint64_t cd, uint64_t cu6, uint64_t cd6,
                     double *ru, double *rd, double *ru6, double *rd6)
{
    double now = ol_wall();
    int k, cnt = *n, idx = *i;
    rate_sample_t *first = NULL, *last;

    h[idx].t = now;
    h[idx].cu = cu; h[idx].cd = cd; h[idx].cu6 = cu6; h[idx].cd6 = cd6;
    *i = (idx + 1) % 16;
    if (cnt < 16) { cnt++; *n = cnt; }
    last = &h[idx];

    for (k = 0; k < cnt; k++) {
        rate_sample_t *x = &h[k];
        if (x->t <= 0 || x->t > now) continue;
        if (now - x->t > OL_RATE_WIN) continue;
        if (!first || x->t < first->t) first = x;
    }
    if (!first) { *ru = *rd = *ru6 = *rd6 = 0; return; }
    {
        double span = last->t - first->t;
        uint64_t du, dd, du6, dd6;
        if (span < 0.5) span = 0.5;   /* 刚起来那一两拍别除出天文数字 */
        du  = last->cu  > first->cu  ? last->cu  - first->cu  : 0;
        dd  = last->cd  > first->cd  ? last->cd  - first->cd  : 0;
        du6 = last->cu6 > first->cu6 ? last->cu6 - first->cu6 : 0;
        dd6 = last->cd6 > first->cd6 ? last->cd6 - first->cd6 : 0;
        *ru = du / span; *rd = dd / span;
        *ru6 = du6 / span; *rd6 = dd6 / span;
    }
}

void acct_rates(double dt)
{
    int i;
    double dummy1 = 0, dummy2 = 0;
    (void)dt;
    if (warmup > 0) warmup--;
    if (warmup == 0)
        win_rate(g_rh, &g_rh_n, &g_rh_i, G.total_up, G.total_down, 0, 0,
                 &G.rate_up, &G.rate_down, &dummy1, &dummy2);
    else { G.rate_up = G.rate_down = 0; }
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        if (warmup == 0)
            win_rate(c->rh, &c->rh_n, &c->rh_i, c->up, c->down,
                     c->up6, c->down6,
                     &c->rate_up, &c->rate_down, &c->rate_up6, &c->rate_down6);
        else c->rate_up = c->rate_down = c->rate_up6 = c->rate_down6 = 0;
    }
}

/* ---------------------------------------------------------------- JSON output */

typedef struct { char *p; size_t n, cap; } sb_t;

static void other_emit(sb_t *b);

static void sb_init(sb_t *b, size_t cap)
{
    b->cap = cap; b->n = 0;
    b->p = (char *)malloc(cap);
    if (!b->p) { b->cap = 0; return; }
    b->p[0] = '\0';
}

static void sb_add(sb_t *b, const char *fmt, ...)
{
    va_list ap;
    int k;
    if (!b->p) return;
    va_start(ap, fmt);
    k = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (k < 0) return;
    if (b->n + (size_t)k + 1 > b->cap) {
        size_t nc = (b->n + (size_t)k + 1) * 2;
        char *np = (char *)realloc(b->p, nc);
        if (!np) return;
        b->p = np; b->cap = nc;
    }
    va_start(ap, fmt);
    vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    b->n += (size_t)k;
}

static void sb_flush(sb_t *b, const char *path)
{
    if (!b->p) return;
    b->p[b->n] = '\0';
    ol_atomic_write(path, b->p);
    b->n = 0; b->p[0] = '\0';
}

static void sb_jstr(sb_t *b, const char *s)
{
    char tmp[512];
    ol_json_str(tmp, sizeof(tmp), s);
    sb_add(b, "%s", tmp);
}

static void other_emit(sb_t *b)
{
    int i, j, n = 0;
    uint32_t keys[8]; uint64_t tot[8];
    for (i = 0; i < OL_OTHER_BUCKETS && n < 8; i++) {
        if (other_buckets[i].key == 0) continue;
        uint64_t v = other_buckets[i].up;
        int k = n;
        for (j = 0; j < n; j++) { if (v > tot[j]) { k = j; break; } }
        if (k == n) { keys[n] = other_buckets[i].key; tot[n] = v; n++; }
        else {
            for (j = n; j > k; j--) { keys[j] = keys[j-1]; tot[j] = tot[j-1]; }
            keys[k] = other_buckets[i].key; tot[k] = v; n++;
        }
    }
    sb_add(b, ",\"other_top\":[");
    for (i = 0; i < n; i++) {
        int ip = (keys[i] >> 16) & 0xff;
        int port = keys[i] & 0xffff;
        char pn[8];
        const char *pro = (ip == 6) ? "tcp" : (ip == 17) ? "udp" :
                          (ip == 1) ? "icmp" : (snprintf(pn, sizeof(pn), "%d", ip), pn);
        if (i) sb_add(b, ",");
        sb_add(b, "{\"proto\":"); sb_jstr(b, pro);
        sb_add(b, ",\"port\":%d,\"bytes\":%s}", port, N(tot[i]));
    }
    sb_add(b, "]");
}

static void sb_buckets(sb_t *b, pair_t *hh)
{
    int i;
    sb_add(b, "[");
    for (i = 0; i < 24; i++) {
        if (i) sb_add(b, ",");
        sb_add(b, "{\"up\":%s,\"down\":%s}", N(hh[i].up), N(hh[i].down));
    }
    sb_add(b, "]");
}

static void write_stats(sb_t *b)
{
    int i;
    char path[300];
    sb_add(b, "{\"updated\":%s,\"total_up\":%s,\"total_down\":%s,"
              "\"rate_up\":%.0f,\"rate_down\":%.0f,"
              "\"backend\":", N((uint64_t)G.now), N(G.total_up), N(G.total_down),
              G.rate_up, G.rate_down);
    sb_jstr(b, G.backend_note);
    sb_add(b, ",\"backend_id\":%d,\"degraded\":%d,\"hw_offload_unreliable\":%d,"
              "\"feature_rules\":%d,\"version\":",
              G.backend, G.degraded, G.hw_offload_unreliable, feature_rule_count());
    sb_jstr(b, OL_VERSION);
    sb_add(b, ",\"clients\":[");
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        if (i) sb_add(b, ",");
        sb_add(b, "{\"mac\":"); sb_jstr(b, c->mac);
        sb_add(b, ",\"ip\":"); sb_jstr(b, c->ip);
        sb_add(b, ",\"ip6\":"); sb_jstr(b, c->ip6);
        sb_add(b, ",\"name\":"); sb_jstr(b, c->name);
        sb_add(b, ",\"vendor\":"); sb_jstr(b, c->vendor);
        sb_add(b, ",\"rate_up\":%.0f,\"rate_down\":%.0f,"
                  "\"rate_up6\":%.0f,\"rate_down6\":%.0f,"
                  "\"day_up\":%s,\"day_down\":%s,\"day_up6\":%s,\"day_down6\":%s,"
                  "\"day_active\":%.0f,\"day_online\":%.0f,"
                  "\"flows\":%d,\"flows6\":%d,\"online\":%d}",
               c->rate_up, c->rate_down, c->rate_up6, c->rate_down6,
               N(c->up), N(c->down), N(c->up6), N(c->down6),
               c->day_active, c->day_online, c->flows, c->flows6,
               c->flows > 0 ? 1 : 0);
    }
    sb_add(b, "]}");
    snprintf(path, sizeof(path), "%s/stats.json", G.dir);
    sb_flush(b, path);
}

static void write_hourly(sb_t *b)
{
    int i;
    char path[300];
    sb_add(b, "{\"updated\":%s,\"hours\":", N((uint64_t)G.now));
    sb_buckets(b, G.hours);
    sb_add(b, ",\"clients\":[");
    for (i = 0; i < G.n_clients; i++) {
        if (i) sb_add(b, ",");
        sb_add(b, "{\"mac\":"); sb_jstr(b, G.clients[i].mac);
        sb_add(b, ",\"hours\":"); sb_buckets(b, G.clients[i].hours);
        sb_add(b, "}");
    }
    sb_add(b, "]}");
    snprintf(path, sizeof(path), "%s/hourly.json", G.dir);
    sb_flush(b, path);
}

static void write_apps(sb_t *b)
{
    int i, j, k, h, first_client = 1;
    char path[300];
    sb_add(b, "{\"updated\":%s,\"clients\":{", N((uint64_t)G.now));
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        if (!c->apps || c->n_apps == 0) continue;
        if (!first_client) sb_add(b, ",");
        first_client = 0;
        { char ml[64]; int z;
          strncpy(ml, c->mac, sizeof(ml) - 1); ml[sizeof(ml) - 1] = '\0';
          for (z = 0; ml[z]; z++) ml[z] = (char)tolower((unsigned char)ml[z]);
          sb_jstr(b, ml); }
        sb_add(b, ":[");
        for (j = 0; j < c->n_apps; j++) {
            app_stat_t *a = &c->apps[j];
            if (j) sb_add(b, ",");
            sb_add(b, "{\"id\":%d,\"up\":%s,\"down\":%s,\"name\":", a->id,
                   N(a->up), N(a->down));
            { const char *nm = feature_app_name(a->id);
              sb_jstr(b, nm ? nm : (a->id == 0 ? "未识别" : "")); }
            sb_add(b, ",\"h\":{");
            for (h = 0, k = 0; h < 24; h++) {
                if (a->hours[h].up == 0 && a->hours[h].down == 0) continue;
                if (k++) sb_add(b, ",");
                sb_add(b, "\"%d\":{\"up\":%s,\"down\":%s}", h,
                       N(a->hours[h].up), N(a->hours[h].down));
            }
            sb_add(b, "},\"a\":{");
            for (h = 0, k = 0; h < 24; h++) {
                if (a->active[h] <= 0) continue;
                if (k++) sb_add(b, ",");
                sb_add(b, "\"%d\":%.0f", h, a->active[h]);
            }
            sb_add(b, "}}");
        }
        sb_add(b, "]");
    }
    sb_add(b, "}}");
    snprintf(path, sizeof(path), "%s/apps.json", G.dir);
    sb_flush(b, path);
}

static void write_proto(sb_t *b)
{
    int i, p, first_client = 1;
    char path[300];
    sb_add(b, "{\"updated\":%s,\"hw_offload_unreliable\":%d,\"order\":[",
            N((uint64_t)G.now), G.hw_offload_unreliable);
    for (p = 0; p < PROTO_MAX; p++) {
        if (p) sb_add(b, ",");
        sb_add(b, "{\"name\":"); sb_jstr(b, ol_proto_names[p]);
        sb_add(b, ",\"color\":"); sb_jstr(b, ol_proto_colors[p]);
        sb_add(b, "}");
    }
    sb_add(b, "],\"lan\":[");
    for (p = 0; p < PROTO_MAX; p++) {
        if (p) sb_add(b, ",");
        sb_add(b, "{\"name\":"); sb_jstr(b, ol_proto_names[p]);
        sb_add(b, ",\"up\":%s,\"down\":%s}",
               N(G.proto[p].up), N(G.proto[p].down));
    }
    sb_add(b, "],\"clients\":{");
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        char ml[64]; int z, first = 1;
        int any = 0;
        for (p = 0; p < PROTO_MAX; p++)
            if (c->proto[p].up || c->proto[p].down) any = 1;
        if (!any) continue;
        strncpy(ml, c->mac, sizeof(ml) - 1); ml[sizeof(ml) - 1] = '\0';
        for (z = 0; ml[z]; z++) ml[z] = (char)tolower((unsigned char)ml[z]);
        if (!first_client) sb_add(b, ",");
        first_client = 0;
        sb_jstr(b, ml);
        sb_add(b, ":[");
        for (p = 0; p < PROTO_MAX; p++) {
            if (c->proto[p].up == 0 && c->proto[p].down == 0) continue;
            if (!first) sb_add(b, ",");
            first = 0;
            sb_add(b, "{\"name\":"); sb_jstr(b, ol_proto_names[p]);
            sb_add(b, ",\"up\":%s,\"down\":%s,\"flows\":%d}",
                   N(c->proto[p].up), N(c->proto[p].down), c->proto_flows[p]);
        }
        sb_add(b, "]");
    }
    sb_add(b, "}");
    other_emit(b);
    sb_add(b, "}");
    snprintf(path, sizeof(path), "%s/proto.json", G.dir);
    sb_flush(b, path);
}

static void write_users(sb_t *b)
{
    int i, j;
    char path[300];
    sb_add(b, "{\"updated\":%s,\"users\":[", N((uint64_t)G.now));
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        /* Top app by bytes: the list page shows it as the device's current
         * application, and the detail page ranks the rest. id 0 ("未识别") is
         * deliberately not a candidate — an empty cell reads better than
         * labelling everything "unknown". */
        int top_id = 0;
        uint64_t top_bytes = 0;
        const char *top_name = NULL;
        for (j = 0; j < c->n_apps; j++) {
            uint64_t b2 = c->apps[j].up + c->apps[j].down;
            if (c->apps[j].id > 0 && b2 > top_bytes) {
                top_bytes = b2;
                top_id = c->apps[j].id;
            }
        }
        if (top_id > 0) top_name = feature_app_name(top_id);
        if (i) sb_add(b, ",");
        sb_add(b, "{\"mac\":"); sb_jstr(b, c->mac);
        sb_add(b, ",\"ip\":"); sb_jstr(b, c->ip);
        sb_add(b, ",\"ipv6\":"); sb_jstr(b, c->ip6);
        sb_add(b, ",\"hostname\":"); sb_jstr(b, c->name);
        sb_add(b, ",\"vendor\":"); sb_jstr(b, c->vendor);
        sb_add(b, ",\"online\":%d,\"active\":%d,"
                  "\"up_rate\":%.0f,\"down_rate\":%.0f,"
                  "\"today_up_bytes\":%s,\"today_down_bytes\":%s,"
                  "\"today_up6_bytes\":%s,\"today_down6_bytes\":%s,"
                  "\"today_active_time\":%.0f,\"today_online_time\":%.0f,"
                  "\"flows\":%d,\"app_id\":%d,\"app\":",
               c->flows > 0 ? 1 : 0, c->day_active > 0 ? 1 : 0,
               c->rate_up, c->rate_down,
               N(c->up), N(c->down), N(c->up6), N(c->down6),
               c->day_active, c->day_online, c->flows, top_id);
        sb_jstr(b, top_name ? top_name : "");
        sb_add(b, ",\"url\":"); sb_jstr(b, c->host);
        sb_add(b, ",\"nickname\":\"\"}");
    }
    sb_add(b, "]}");
    snprintf(path, sizeof(path), "%s/users.json", G.dir);
    sb_flush(b, path);
}

/* Publish the feature library's id->name map and its #class sections.
 * oafd used to serve these over ubus (with a cloud name lookup); here they
 * come straight from the plaintext feature.cfg, so an edited library shows
 * up on the page immediately and APP names never depend on a stale Lua
 * table. Written once at start-up, not on every snapshot. */
void acct_write_meta(void)
{
    sb_t b;
    char path[300], idbuf[16];
    int i, j, first;

    sb_init(&b, 65536);

    sb_add(&b, "{");
    for (i = 0; i < feature_name_count(); i++) {
        const appname_t *a = feature_name_at(i);
        if (!a) continue;
        if (i) sb_add(&b, ",");
        snprintf(idbuf, sizeof(idbuf), "%d", a->id);
        sb_jstr(&b, idbuf);
        sb_add(&b, ":");
        sb_jstr(&b, a->name);
    }
    sb_add(&b, "}");
    snprintf(path, sizeof(path), "%s/app_names.json", G.dir);
    sb_flush(&b, path);

    sb_add(&b, "{\"version\":");
    sb_jstr(&b, OL_VERSION);
    sb_add(&b, ",\"class_list\":[");
    for (i = 0; i < feature_class_count(); i++) {
        const appclass_t *k = feature_class_at(i);
        if (!k) continue;
        if (i) sb_add(&b, ",");
        sb_add(&b, "{\"id\":%d,\"key\":", k->id);
        sb_jstr(&b, k->key);
        sb_add(&b, ",\"name\":");
        sb_jstr(&b, k->name);
        sb_add(&b, ",\"app_list\":[");
        first = 1;
        for (j = 0; j < feature_name_count(); j++) {
            const appname_t *a = feature_name_at(j);
            if (!a || a->class_id != k->id) continue;
            if (!first) sb_add(&b, ",");
            first = 0;
            snprintf(idbuf, sizeof(idbuf), "%d", a->id);
            sb_jstr(&b, idbuf);
        }
        sb_add(&b, "]}");
    }
    sb_add(&b, "]}");
    snprintf(path, sizeof(path), "%s/classes.json", G.dir);
    sb_flush(&b, path);

    ol_log("acct: meta app_names=%d classes=%d",
           feature_name_count(), feature_class_count());
    free(b.p);
}

static void write_day(sb_t *b)
{
    int i, j;
    char path[300], date[32];
    ol_localdate("%Y-%m-%d", G.now, date, sizeof(date));
    snprintf(path, sizeof(path), "%s/day/%s.json", G.dir, date);
    sb_add(b, "{\"date\":"); sb_jstr(b, date);
    sb_add(b, ",\"clients\":[");
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        if (i) sb_add(b, ",");
        sb_add(b, "{\"mac\":"); sb_jstr(b, c->mac);
        sb_add(b, ",\"day_up\":%s,\"day_down\":%s,\"hours\":",
               N(c->up), N(c->down));
        sb_buckets(b, c->hours);
        sb_add(b, "}");
    }
    sb_add(b, "],\"apps\":{");
    {
        int first = 1;
        for (i = 0; i < G.n_clients; i++) {
            client_t *c = &G.clients[i];
            char ml[64]; int z;
            if (!c->apps || c->n_apps == 0) continue;
            if (!first) sb_add(b, ",");
            first = 0;
            strncpy(ml, c->mac, sizeof(ml) - 1);
            for (z = 0; ml[z]; z++) ml[z] = (char)tolower((unsigned char)ml[z]);
            sb_jstr(b, ml);
            sb_add(b, ":[");
            for (j = 0; j < c->n_apps; j++) {
                if (j) sb_add(b, ",");
                sb_add(b, "{\"id\":%d,\"up\":%s,\"down\":%s}",
                       c->apps[j].id, N(c->apps[j].up), N(c->apps[j].down));
            }
            sb_add(b, "]");
        }
    }
    sb_add(b, "}}");
    sb_flush(b, path);
}

/* 诊断用：把「还在跑、但认不出应用」的大流按字节排序列出来。
 * 硬件加速之后这些流永远等不到首包，只能靠 DNS / 同 IP 归因兜底；
 * 拿不到名字的到底是哪几个 IP、还缺哪条规则，看这个文件最直接。 */
static void write_unknown_flows(void)
{
    char path[512], json[8192];
    FILE *f;
    size_t o = 0;
    int i, k, shown = 0;
    int idx[24];
    uint64_t best[24];
    if (!G.flows) return;
    memset(best, 0, sizeof(best));
    for (k = 0; k < 24; k++) idx[k] = -1;

    for (i = 0; i < OL_MAX_FLOWS; i++) {
        const flow_t *fl = &G.flows[i];
        uint64_t bytes;
        if (fl->used != 1 || fl->appid != 0) continue;
        if (!fl->remote[0] || !fl->mac[0]) continue;  /* 基线空壳，不是真流 */
        bytes = fl->base_up + fl->base_down;
        if (bytes < 100000) continue;               /* 小流不占版面 */
        /* 维护一个固定大小的 top-N（N=24），避免额外分配 */
        for (k = 0; k < 24; k++) {
            if (bytes > best[k]) {
                int m;
                for (m = 23; m > k; m--) { best[m] = best[m - 1]; idx[m] = idx[m - 1]; }
                best[k] = bytes; idx[k] = i;
                break;
            }
        }
    }
    o += (size_t)snprintf(json + o, sizeof(json) - o, "{\"flows\":[");
    for (k = 0; k < 24; k++) {
        const flow_t *fl;
        const char *h;
        if (!best[k]) break;
        fl = &G.flows[idx[k]];
        h = acct_host_for_ip(fl->remote);
        {
            char cip[46], rip[46];
            unsigned sp = 0, dp = 0;
            int ipp = 0, dport = 0;
            if (sscanf(fl->key, "%45[^|]|%45[^|]|%u|%u|%d", cip, rip, &sp, &dp, &ipp) >= 4)
                dport = (int)dp;
            o += (size_t)snprintf(json + o, sizeof(json) - o,
                "%s{\"mac\":\"%s\",\"remote\":\"%s\",\"host\":", shown ? "," : "",
                fl->mac, fl->remote);
            if (h && *h) o += (size_t)snprintf(json + o, sizeof(json) - o, "\"%s\"", h);
            else o += (size_t)snprintf(json + o, sizeof(json) - o, "null");
            o += (size_t)snprintf(json + o, sizeof(json) - o,
                ",\"dport\":%d,\"proto\":%d,\"mb\":%.1f}",
                dport, fl->ipproto,
                (double)(fl->base_up + fl->base_down) / 1048576.0);
        }
        shown++;
        if (o > sizeof(json) - 400) break;
    }
    snprintf(json + o, sizeof(json) - o, "],\"n\":%d}\n", shown);
    snprintf(path, sizeof(path), "%s/unknown_flows.json", G.dir);
    f = fopen(path, "w");
    if (!f) return;
    fputs(json, f);
    fclose(f);
}

/* One persistent scratch buffer for every JSON file written. Previously this
 * was malloc(256 KB) + free on EVERY round (1 s) -- steady-state zero, but
 * it churned the allocator and touched ~64 fresh pages per second. Reusing
 * the buffer means zero allocations after the first round; the size grows
 * on demand for full rounds and simply stays there. */
static sb_t out_sb;

void acct_write_json(int full)
{
    sb_t *b = &out_sb;
    if (!b->p) sb_init(b, 131072);
    if (!b->p) return;                 /* malloc failed: skip this round */
    b->n = 0;
    b->p[0] = '\0';
    write_stats(b);
    if (full) {
        write_hourly(b);
        write_apps(b);
        write_proto(b);
        write_users(b);
        write_day(b);
        probe_write_hosts(G.dir);
        write_unknown_flows();
    }
}

void acct_roll_day(const char *newday)
{
    int i, j;
    acct_write_json(1);
    ol_log("acct: day rollover %s -> %s", G.today, newday);
    strncpy(G.today, newday, sizeof(G.today) - 1);
    G.today[sizeof(G.today) - 1] = '\0';
    G.total_up = G.total_down = 0;
    memset(G.hours, 0, sizeof(G.hours));
    memset(G.proto, 0, sizeof(G.proto));
    for (i = 0; i < G.n_clients; i++) {
        client_t *c = &G.clients[i];
        c->up = c->down = c->up6 = c->down6 = 0;
        c->prev_up = c->prev_down = c->prev_up6 = c->prev_down6 = 0;
        c->day_active = c->day_online = 0;
        memset(c->hours, 0, sizeof(c->hours));
        memset(c->proto, 0, sizeof(c->proto));
        memset(c->proto_flows, 0, sizeof(c->proto_flows));
        c->rh_n = c->rh_i = 0;
        memset(c->rh, 0, sizeof(c->rh));
        if (c->apps) {
            for (j = 0; j < c->n_apps; j++) {
                c->apps[j].up = c->apps[j].down = 0;
                memset(c->apps[j].hours, 0, sizeof(c->apps[j].hours));
                memset(c->apps[j].active, 0, sizeof(c->apps[j].active));
            }
        }
    }
    if (G.flows) {
        for (i = 0; i < OL_MAX_FLOWS; i++)
            if (G.flows[i].used == 1) G.flows[i].has_base = 0;
    }
}

/* ---------------------------------------------------------------- lifecycle */

/* 开机基线：把「启动那一刻已经在表里」的连接全部预置基线。
 *
 * 首次快照本身会给每条流打基线，但「首次快照根本没看到这条流」是常态，
 * 尤其是 IPv6：邻居表要靠 NDP 建立，acct_refresh_macs() 还没拿到 地址→MAC
 * 映射时，ct_settle() 会在开头直接 return，这条流在流表里压根不存在。
 * 等它被 DESTROY 时，事件里带的是它**一辈子的累计字节**，而 destroy 分支
 * 没有基线只能全量记账 —— 一条挂了几个小时的隧道/网盘/视频连接，一次就能
 * 把 5.3 GB 记成「今天刚下的」。
 *
 * 这里在进入主循环前扫一遍 conntrack，给每条已存在的流预置基线。key 按
 * 「哪一侧是 LAN 客户端」拼，和 ct_settle 完全同一判据 —— 早先两个方向都置，
 * 结果反向 key 建出一条永远等不到 settle 的空壳流（ct_settle 只用客户端侧
 * key），它带着基线字节数留在表里，还以 {"mac":"","remote":""} 的形式污染
 * unknown_flows.json。
 */
void acct_seed_baseline(void)
{
    FILE *f;
    char line[CT_LINE_MAX];
    char key[OL_MAX_KEY];
    int rows = 0, seeded = 0;
    if (!G.flows) return;
    f = fopen("/proc/net/nf_conntrack", "r");
    if (!f) return;
    while (fgets(line, sizeof(line), f)) {
        ct_rec_t o;
        flow_t *fl;
        const char *m1, *m2, *mac, *remote;
        unsigned lport, rport;
        uint64_t up, down;
        if (++rows > 20000) break;          /* 防御：异常大的表不阻塞启动 */
        if (!parse_ct_line(line, &o)) continue;
        if (!o.s1[0] || !o.s2[0]) continue;
        m1 = acct_mac_for_ip(o.s1);
        m2 = (m1 && *m1) ? NULL : acct_mac_for_ip(o.s2);
        if (m1 && *m1) {
            mac = m1; remote = o.d1; lport = o.p1; rport = o.p2;
            up = o.b1; down = o.b2;
            snprintf(key, sizeof(key), "%s|%s|%u|%u|%d",
                     o.s1, o.d1, lport, rport, o.ipproto);
        } else if (m2 && *m2) {
            mac = m2; remote = o.s1; lport = o.p2; rport = o.p1;
            up = o.b2; down = o.b1;
            snprintf(key, sizeof(key), "%s|%s|%u|%u|%d",
                     o.s2, o.s1, lport, rport, o.ipproto);
        } else {
            continue;                       /* 不是本机 LAN 客户端 */
        }
        fl = flow_find(key, 1);
        if (!fl) continue;
        /* 同一连接的两个 conntrack 方向会落到同一个 key 上。取较大的累计值，
         * 避免「先到的那条是 0」把基线冲掉。 */
        if (fl->has_base && up + down <= fl->base_up + fl->base_down) continue;
        fl->base_up = up; fl->base_down = down;
        fl->has_base = 1; fl->born = G.now;
        fl->fam = strchr(o.s1, ':') ? 6 : 4;
        fl->ipproto = o.ipproto;
        if (!fl->mac[0]) {
            strncpy(fl->mac, mac, 17);
            fl->mac[17] = '\0';
        }
        if (!fl->remote[0]) {
            strncpy(fl->remote, remote, sizeof(fl->remote) - 1);
            fl->remote[sizeof(fl->remote) - 1] = '\0';
        }
        seeded++;
    }
    fclose(f);
    ol_log("acct: seeded %d baselines from %d conntrack rows", seeded, rows);
}

int acct_init(void)
{
    char cmd[300];
    G.flows = (flow_t *)calloc(OL_MAX_FLOWS, sizeof(flow_t));
    G.clients = (client_t *)calloc(OL_MAX_CLIENTS, sizeof(client_t));
    if (!G.flows || !G.clients) return -1;
    G.boot_ts = time(NULL);
    G.now = G.boot_ts;
    G.round = 0;
    ol_localdate("%Y-%m-%d", G.now, G.today, sizeof(G.today));
    snprintf(cmd, sizeof(cmd), "mkdir -p %s/day", G.dir);
    if (system(cmd) != 0) ol_log("acct: mkdir %s/day failed", G.dir);
    G.backend = hnat_detect();
    gw_detect(G.lan_if);
    if (gw_ip4[0]) ol_log("acct: LAN gateway %s (%s), local traffic excluded",
                          gw_ip4, G.lan_if);
    acct_refresh_macs();
    acct_seed_baseline();
    acct_write_meta();
    ol_log("acct: init backend=%d (%s), %d clients", G.backend,
           G.backend_note, G.n_clients);
    return 0;
}

void acct_close(void)
{
    if (evf) { pclose(evf); evf = NULL; }
}

/* Minimal JSON balance checker used by the selftest. Ignores characters
 * inside "..." string literals (handles \" escapes) and verifies that
 * {}, [], () are all properly nested/closed. It will not catch a trailing
 * comma or a wrong number, but it is enough to catch the stray-brace class
 * of bug that only otherwise surfaces as BADJSON on the router. */
static int json_balanced(const char *s)
{
    char st[256]; int top = 0; int in_str = 0;
    for (int i = 0; s[i]; i++) {
        char c = s[i];
        if (in_str) {
            if (c == '\\') { i++; continue; }
            if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') { in_str = 1; continue; }
        switch (c) {
            case '{': case '[': case '(':
                if (top >= (int)sizeof(st)) return 0;
                st[top++] = c; break;
            case '}':
                if (top == 0 || st[--top] != '{') return 0; break;
            case ']':
                if (top == 0 || st[--top] != '[') return 0; break;
            case ')':
                if (top == 0 || st[--top] != '(') return 0; break;
        }
    }
    return top == 0 ? 1 : 0;
}

int acct_selftest(void)
{
    ct_rec_t o;
    if (!G.flows) G.flows = (flow_t *)calloc(OL_MAX_FLOWS, sizeof(flow_t));
    if (!G.clients) G.clients = (client_t *)calloc(OL_MAX_CLIENTS, sizeof(client_t));
    if (!G.flows || !G.clients) return 1;
    const char *line =
        "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.100 "
        "dst=1.2.3.4 sport=51000 dport=443 packets=10 bytes=5000 "
        "src=1.2.3.4 dst=192.168.1.100 sport=443 dport=51000 "
        "packets=20 bytes=30000 mark=3003";
    char before[46];
    if (!parse_ct_line(line, &o)) { printf("FAIL parse_ct_line\n"); return 1; }
    printf("%s parse_ct_line src=%s dport=%u bytes=%llu/%llu mark=%d proto=%d\n",
           (o.p2 == 443 && o.b1 == 5000 && o.b2 == 30000 && o.mark == 3003 &&
            o.ipproto == 6) ? "PASS" : "FAIL",
           o.s1, o.p2, (unsigned long long)o.b1,
           (unsigned long long)o.b2, o.mark, o.ipproto);
    if (!(o.p2 == 443 && o.b1 == 5000 && o.b2 == 30000 &&
          o.mark == 3003 && o.ipproto == 6)) return 1;
    strcpy(before, o.s1);
    ipmac_put("192.168.1.100", "64:BD:6D:C8:8E:4C");
    if (!acct_mac_for_ip("192.168.1.100")) { printf("FAIL ipmac\n"); return 1; }
    printf("PASS ipmac %s -> %s\n", before, acct_mac_for_ip("192.168.1.100"));
    /* first sighting is a baseline, second settles the delta */
    G.round = 1;
    ct_settle(&o, G.now, 0, NULL, 0);
    o.b1 = 9000; o.b2 = 90000;
    G.round = 2;
    ct_settle(&o, G.now, 0, NULL, 0);
    {
        client_t *c = (G.n_clients > 0) ? &G.clients[0] : NULL;
        int ok = c && c->down == 60000 && c->up == 4000;
        printf("%s conntrack delta up=%llu down=%llu appid=%d\n",
               ok ? "PASS" : "FAIL",
               c ? (unsigned long long)c->up : 0,
               c ? (unsigned long long)c->down : 0,
               (c && c->n_apps > 0) ? c->apps[0].id : -1);
        if (!ok) return 1;
    }
    {
        uint64_t best = 0;
        uint64_t got = hnat_parse_aggr(
            "Byte cnt=1234567\nPkt cnt=9999999\ndone\n", &best);
        printf("%s hnat AG labelled byte counter -> %llu (best=%llu)\n",
               (got == 1234567 && best == 1234567) ? "PASS" : "FAIL",
               (unsigned long long)got, (unsigned long long)best);
        if (got != 1234567) return 1;
    }
    {
        int ok = proto_by_port(443, 6) == PROTO_TLS &&
                 proto_by_port(80, 6) == PROTO_HTTP &&
                 proto_by_port(443, 17) == PROTO_QUIC &&
                 proto_by_port(53, 17) == PROTO_DNS &&
                 proto_by_port(11010, 6) == PROTO_OTHER;
        printf("%s proto_by_port fallback (443/tcp,80/tcp,443/udp,53/udp)\n",
               ok ? "PASS" : "FAIL");
        if (!ok) return 1;
    }
    {
        int ok = ct_is_lan_noise("192.168.1.166", "255.255.255.255") &&
                 ct_is_lan_noise("192.168.1.247", "192.168.1.255") &&
                 ct_is_lan_noise("192.168.1.50", "224.0.0.251") &&
                 !ct_is_lan_noise("192.168.1.100", "1.2.3.4") &&
                 !ct_is_lan_noise("192.168.1.100", "100.95.3.159");
        printf("%s lan broadcast/multicast excluded, unicast kept\n",
               ok ? "PASS" : "FAIL");
        if (!ok) return 1;
    }
    {
        ct_rec_t g1, g2;
        const char *local =
            "ipv4     2 tcp      6 56 TIME_WAIT src=192.168.1.100 "
            "dst=192.168.1.1 sport=49430 dport=22 packets=2337 bytes=2903380 "
            "src=192.168.1.1 dst=192.168.1.100 sport=22 dport=49430 "
            "packets=1076 bytes=80114 [ASSURED] mark=0";
        const char *nat =
            "ipv4     2 udp      17 29 src=192.168.1.100 "
            "dst=223.5.5.5 sport=58760 dport=53 packets=2 bytes=130 "
            "src=192.168.1.1 dst=192.168.1.100 sport=53 dport=58760 "
            "packets=2 bytes=266 [ASSURED] mark=0";
        strncpy(gw_ip4, "192.168.1.1", sizeof(gw_ip4) - 1);
        {
            int ok = !parse_ct_line(local, &g1) && parse_ct_line(nat, &g2) &&
                     strcmp(g2.d1, "223.5.5.5") == 0;
            printf("%s gateway-local SSH dropped, NAT DNS reply kept\n",
                   ok ? "PASS" : "FAIL");
            gw_ip4[0] = '\0';
            if (!ok) return 1;
        }
    }
    {
        /* DESTROY of a connection never seen by a snapshot: full byte count
         * must land in TLS, not in OTHER. */
        ct_rec_t d;
        uint64_t before;
        const char *dl =
            "ipv4     2 tcp      6 10 CLOSE src=192.168.1.101 "
            "dst=5.6.7.8 sport=52000 dport=443 packets=4 bytes=1000 "
            "src=5.6.7.8 dst=192.168.1.101 sport=443 dport=52000 "
            "packets=5 bytes=2000 mark=0 [DESTROY]";
        if (!parse_ct_line(dl, &d)) { printf("FAIL destroy parse\n"); return 1; }
        ipmac_put("192.168.1.101", "64:BD:6D:C8:8E:4D");
        before = G.proto[PROTO_TLS].up + G.proto[PROTO_TLS].down;
        ct_settle(&d, G.now, 1, NULL, 0);
        {
            int ok = (G.proto[PROTO_TLS].up + G.proto[PROTO_TLS].down - before) == 3000;
            printf("%s DESTROY unseen flow: 3000 B settled as TLS not OTHER\n",
                   ok ? "PASS" : "FAIL");
            if (!ok) return 1;
        }
    }
    {
        /* DESTROY of a flow created by AF_PACKET but never baselined: the
         * old code silently charged 0. It must now charge the full delta. */
        ct_rec_t d2;
        uint64_t before;
        const char *dl2 =
            "ipv4     2 tcp      6 10 CLOSE src=192.168.1.102 "
            "dst=5.6.7.9 sport=53000 dport=443 packets=4 bytes=7000 "
            "src=5.6.7.9 dst=192.168.1.102 sport=443 dport=53000 "
            "packets=5 bytes=11000 mark=0 [DESTROY]";
        flow_t *f = flow_find("192.168.1.102|5.6.7.9|53000|443|6", 1);
        if (!f || !parse_ct_line(dl2, &d2)) { printf("FAIL baselineless flow\n"); return 1; }
        ipmac_put("192.168.1.102", "64:BD:6D:C8:8E:4E");
        before = G.total_up + G.total_down;
        ct_settle(&d2, G.now, 1, NULL, 0);
        {
            int ok = (G.total_up + G.total_down - before) == 18000;
            printf("%s DESTROY baselineless flow: 18000 B settled (was 0)\n",
                   ok ? "PASS" : "FAIL");
            if (!ok) return 1;
        }
    }
    other_accum(6, 443, 9999);   /* exercise the other_top branch too */
    /* IPv6 的两种写法必须归一到同一条流。
     * /proc 是全写、DESTROY 事件是压缩写；不统一的话快照建立的流记录在
     * 销毁时找不到，整段历史被重复记账（实测压测能翻倍）。 */
    {
        ct_rec_t p6, e6;
        const char *pl =
            "ipv6 10 tcp 6 431999 ESTABLISHED "
            "src=2409:8087:2001:0010:0000:0000:2786:4d63 "
            "dst=2409:8a20:5261:c300:f554:f496:9dc7:dcfd sport=443 dport=59854 "
            "packets=9 bytes=1000 "
            "src=2409:8a20:5261:c300:f554:f496:9dc7:dcfd "
            "dst=2409:8087:2001:0010:0000:0000:2786:4d63 sport=59854 dport=443 "
            "packets=11 bytes=2000 mark=0";
        const char *ev =
            "[1794800000.1] [DESTROY] ipv6 10 tcp 6 "
            "src=2409:8087:2001:10::2786:4d63 "
            "dst=2409:8a20:5261:c300:f554:f496:9dc7:dcfd sport=443 dport=59854 "
            "packets=9 bytes=1000 "
            "src=2409:8a20:5261:c300:f554:f496:9dc7:dcfd "
            "dst=2409:8087:2001:10::2786:4d63 sport=59854 dport=443 "
            "packets=11 bytes=2000 mark=0";
        int ok = parse_ct_line(pl, &p6) && parse_ct_line(ev, &e6) &&
                 strcmp(p6.s1, e6.s1) == 0 && strcmp(p6.d1, e6.d1) == 0 &&
                 p6.b1 == e6.b1 && p6.b2 == e6.b2;
        if (!ok)
            printf("    proc key %s|%s\n    ev   key %s|%s\n",
                   p6.s1, p6.d1, e6.s1, e6.d1);
        printf("%s IPv6 key normalised: proc and DESTROY agree\n",
               ok ? "PASS" : "FAIL");
        if (!ok) return 1;
    }
    acct_write_json(1);
    acct_write_meta();
    /* Every published snapshot must be parseable. The real consumer is Lua
     * jsonc on the router, but a stray brace would otherwise only surface
     * there, so guard against it in CI. */
    {
        int bad = 0;
        const char *files[] = {"stats.json", "hourly.json", "apps.json",
                               "proto.json", "users.json", NULL};
        for (int fi = 0; files[fi]; fi++) {
            char p[400];
            snprintf(p, sizeof(p), "%s/%s", G.dir, files[fi]);
            FILE *f = fopen(p, "rb");
            if (!f) { printf("FAIL json %s missing\n", files[fi]); bad = 1; continue; }
            fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
            char *buf = malloc((size_t)n + 1);
            if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
                printf("FAIL json %s read\n", files[fi]); bad = 1;
                fclose(f); free(buf); continue;
            }
            buf[n] = '\0'; fclose(f);
            if (!json_balanced(buf))
                { printf("FAIL json %s UNBALANCED (%ld B)\n", files[fi], n); bad = 1; }
            else
                printf("PASS json %s (%ld B)\n", files[fi], n);
            free(buf);
        }
        /* write_day() lands in day/<YYYY-MM-DD>.json */
        {
            char date[32]; char p[400];
            ol_localdate("%Y-%m-%d", G.now, date, sizeof(date));
            snprintf(p, sizeof(p), "%s/day/%s.json", G.dir, date);
            FILE *f = fopen(p, "rb");
            if (!f) { printf("FAIL json day/%s.json missing\n", date); bad = 1; }
            else {
                fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
                char *buf = malloc((size_t)n + 1);
                if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
                    printf("FAIL json day/%s.json read\n", date); bad = 1;
                } else {
                    buf[n] = '\0';
                    if (!json_balanced(buf))
                        printf("FAIL json day/%s.json UNBALANCED (%ld B)\n", date, n);
                    else
                        printf("PASS json day/%s.json (%ld B)\n", date, n);
                }
                fclose(f); free(buf);
            }
        }
        if (bad) return 1;
    }
    return 0;
}
