/* oaf-lite: common types shared by the sampler modules.
 * Pure C99, no third-party libraries, no kernel module. */
#ifndef OAF_LITE_COMMON_H
#define OAF_LITE_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdio.h>

#define OL_VERSION        "1.0.0"
#define OL_MAX_FLOWS      8192
#define OL_MAX_CLIENTS    256
#define OL_MAX_APPS       64        /* per client, lazily allocated */
#define OL_MAX_RULES      4096
#define OL_MAX_NAMES      1200
#define OL_MAX_CLASSES    64
#define OL_MAX_PORTRULES  512
#define OL_MAX_HOST       128
/* Flow key: "ip|remote|sport|dport|ipproto". Worst case is two expanded
 * IPv6 addresses (39 chars each) + two 5-digit ports + 3-digit proto and
 * 4 separators = 95 bytes. 128 leaves headroom without paying 160. */
#define OL_MAX_KEY        128
#define OL_RATE_WIN       9        /* seconds; matches the ponwrt pages */
#define OL_MAX_PKT_ROUND  4096     /* hard cap on packets parsed per round */
#define OL_MAX_FLOW_PKTS  8        /* only the first N packets of a flow */
#define OL_ACTIVE_MIN     2048     /* bytes/window before a window is "active" */
/* 离散活跃访问段：与官方 OAF active.json 同口径。一个段 = 一次连续使用：
 * 从第一个达到 2 KiB 的采样窗口(ft)到最后一个(lt)，tt = lt - ft。两次使用
 * 之间静默超过 OL_SEG_GAP 秒就切成两段。tt 用真实墙上时间差，不用「活跃秒
 * 数之和」——后者和 First/Last 两列对不上（4 分钟区间却显示 41s）。 */
#define OL_SEG_GAP        120      /* seconds of idle that splits two visits */
#define OL_MAX_APP_SEGS   64       /* discrete visits kept per app per day */
#define OL_IDLE_SEC       3        /* slow sampling when nobody is watching */
#define OL_ACTIVE_SEC     1        /* fast channel while the page is open */
#define OL_FULL_SEC       10       /* hourly/apps serialisation throttle */
#define OL_EVENTS_MAX     512      /* DESTROY events drained per round */
#define OL_GONE_TTL       300
/* 单条「从未见过基线」的流在 DESTROY 时最多能记多少字节。
 * 这类流正常只有「两拍之间就结束」的短连接（百 MB 封顶）；真跑出 GB 级
 * 说明我们漏了它的整段历史，全量记账会把几天前的流量算进今天。 */
#define OL_UNSEEN_CLAMP   (2ULL * 1024 * 1024 * 1024)

enum {
    PROTO_TLS = 0,
    PROTO_HTTP,
    PROTO_QUIC,
    PROTO_FAILED,
    PROTO_DNS,
    PROTO_OTHER,
    PROTO_MAX
};

extern const char *ol_proto_names[PROTO_MAX];
extern const char *ol_proto_colors[PROTO_MAX];

typedef struct { uint64_t up, down; } pair_t;

/* One discrete active visit (official OAF active.json shape). */
typedef struct { time_t ft, lt; } visit_seg_t;

typedef struct { int id; char name[64]; int class_id; } appname_t;
typedef struct { int id; char key[32]; char name[64]; } appclass_t;
typedef struct { char pat[64]; int len; int appid; } domain_rule_t;
typedef struct { int lo, hi, ipproto, appid; } port_rule_t;

/* A conntrack flow plus the L7 label learned from the first packets. */
typedef struct {
    int       used;                 /* 0 free, 1 used, 2 tombstone */
    char      key[OL_MAX_KEY];      /* client_ip|remote_ip|sport|dport|ipproto */
    char      mac[18];
    char      host[OL_MAX_HOST];
    char      ip[46];
    char      remote[46];
    int       appid;
    int       proto;
    int       fam;                  /* 4 or 6 */
    int       ipproto;              /* 6 or 17 */
    int       proto_fixed;          /* 1 = identified from payload */
    int       proto_counted;        /* 1 = already added to proto_flows[] */
    int       pkts;                 /* sampled packets */
    int       syn_only;
    int       has_base;             /* conntrack baseline initialised */
    int       seen;                 /* last round id */
    time_t    gone_at;
    uint64_t  base_up, base_down;   /* conntrack orig/reply baseline */
    time_t    born;
} flow_t;

typedef struct {
    int      id;
    uint64_t up, down;
    pair_t   hours[24];
    double   active[24];
    time_t   first_ts;   /* first window with >=2KiB traffic (real connect time) */
    time_t   last_ts;    /* last window with >=2KiB traffic (real end time) */
    uint64_t valid_bytes;/* total bytes counted while window was active */
    /* Discrete visits (official active.json): one seg per continuous active
     * stretch. segs[] holds closed visits; n_segs is their count. The currently
     * open visit is tracked by cur_ft/cur_lt (cur_ft=0 when none open) and is
     * emitted as a live segment alongside the closed ones. */
    visit_seg_t segs[OL_MAX_APP_SEGS];
    int      n_segs;
    time_t   cur_ft, cur_lt;
} app_stat_t;

/* 速率采样：存的是**累计字节**与采样时刻（秒，带小数），不是每拍增量。
 * 见 acct.c:win_rate() 的说明——增量/本拍 dt 会被 PPE 的一次性回写放大。 */
typedef struct { double t; uint64_t cu, cd, cu6, cd6; } rate_sample_t;

typedef struct {
    char     mac[18];
    char     ip[46];
    char     ip6[46];
    int      addr_prio, addr6_prio;  /* source priority of ip / ip6 */
    char     name[64];
    char     vendor[64];
    char     host[OL_MAX_HOST];     /* last hostname seen for this client */
    time_t   host_ts;               /* when that hostname was last observed */
    uint64_t up, down, up6, down6;
    pair_t   hours[24];
    app_stat_t *apps;               /* lazily allocated OL_MAX_APPS slots */
    int      n_apps;
    pair_t   proto[PROTO_MAX];
    int      proto_flows[PROTO_MAX];
    /* Per-hour protocol bytes for the protocol-distribution stacked bars,
     * same 24-bucket layout as apps[].hours. Written to proto.json. */
    pair_t   proto_hours[PROTO_MAX][24];
    uint64_t prev_up, prev_down, prev_up6, prev_down6;
    double   rate_up, rate_down, rate_up6, rate_down6;
    rate_sample_t rh[16];
    int      rh_n, rh_i;
    double   day_active, day_online;
    int      flows, flows6;
    int      online;
    uint64_t round_bytes;           /* for the active-seconds gate */
    uint64_t round_appbytes[OL_MAX_APPS];
} client_t;

typedef struct {
    flow_t   *flows;
    client_t *clients;
    int       n_clients;
    uint64_t  total_up, total_down;
    pair_t    hours[24];
    pair_t    proto[PROTO_MAX];
    double    rate_up, rate_down;
    time_t    now;
    int       round;
    char      dir[128];
    char      feature_path[256];
    char      lan_if[32];
    int       tz_offset;
    int       backend;
    int       degraded;
    int       hw_offload_unreliable;  /* closed HNAT with no conntrack writeback */
    char      backend_note[128];
    time_t    boot_ts;
    char      today[16];
} ol_ctx_t;

extern ol_ctx_t G;

enum { BACKEND_CONNTRACK = 0, BACKEND_HNAT_AGGR = 1, BACKEND_HNAT_DEBUGFS = 2 };

/* ---- utils ---- */
uint32_t ol_crc32(const uint8_t *p, size_t n);
uint32_t ol_hash_str(const char *s);
void     ol_json_str(char *out, size_t cap, const char *s);
void     ol_atomic_write(const char *path, const char *body);
void     ol_log(const char *fmt, ...);
void     ol_trim(char *s);
const char *ol_num(uint64_t v, char *buf, size_t n);
double   ol_wall(void);
void     ol_localdate(const char *fmt, time_t ts, char *out, size_t cap);

/* ---- feature.bin ---- */
int         feature_load(const char *path);
int         feature_load_extra(const char *path);
int         feature_lookup(const char *host, int dport, int ipproto, int *appid);
const char *feature_app_name(int appid);
int         feature_rule_count(void);
int         feature_name_count(void);
const appname_t *feature_name_at(int i);
int         feature_class_count(void);
const appclass_t *feature_class_at(int i);
int         feature_selftest(const char *path);

/* ---- first-packet probe ---- */
typedef struct {
    char key[OL_MAX_KEY];
    char mac[18];
    char host[OL_MAX_HOST];
    char client_ip[46];
    char remote_ip[46];
    char dns_ip[46];
    char dns_host[OL_MAX_HOST];
    int  appid;
    int  proto;
    int  ipproto;
    int  fam;
    int  proto_fixed;
    int  is_rst;
    int  is_syn;
    int  reverse;      /* 1 = reply direction, key was swapped */
} probe_result_t;

int  probe_init(const char *ifname);
void probe_close(void);
int  probe_poll(int budget);
int  probe_parse_frame(const uint8_t *buf, int len, probe_result_t *r);
void probe_note_host(const char *host, int appid);
void probe_write_hosts(const char *dir);
int  probe_selftest(void);

/* ---- accounting ---- */
int         acct_init(void);
void        acct_close(void);
void        acct_seed_baseline(void);
void        acct_refresh_macs(void);
const char *acct_mac_for_ip(const char *ip);
void        acct_cache_dns(const char *ip, const char *host);
const char *acct_host_for_ip(const char *ip);
void        acct_bind_flow(const probe_result_t *r);
void        acct_note_client_host(const char *ip, const char *host);
void        acct_snapshot(time_t now);
void        acct_events(time_t now);
void        acct_hnat_poll(time_t now);
void        acct_settle(double dt);
void        acct_rates(double dt);
void        acct_write_json(int full);
void        acct_write_meta(void);
void        acct_roll_day(const char *newday);
int         acct_selftest(void);

#endif /* OAF_LITE_COMMON_H */
