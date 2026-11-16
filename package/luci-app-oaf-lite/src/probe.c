/* First-packet sampler.
 *
 * A raw AF_PACKET socket on the LAN bridge sees the packets that still walk
 * the CPU. Once a flow is taken over by the PPE / FOE / HNAT it disappears
 * from this socket -- which is exactly why we only need its FIRST few packets:
 * they carry ClientHello SNI, HTTP Host, DNS qname and QUIC long headers.
 * The label is attached to the flow key; the byte counters come from
 * conntrack (acct.c) and keep growing while the flow is offloaded.
 *
 * Lost captures only reduce identification coverage, never the traffic
 * numbers. The BPF is deliberately tiny (5 instructions, 512-byte snaplen)
 * and the userland loop is capped at OL_MAX_PKT_ROUND packets per round.
 */
#include "common.h"
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static int pfd = -1;
static uint8_t pktbuf[2048];

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void fmt6(const uint8_t a[16], char out[46])
{
    int i, n = 0;
    for (i = 0; i < 16; i += 2) {
        n += snprintf(out + n, 46 - (size_t)n, "%02x%02x%s",
                      a[i], a[i + 1], i < 14 ? ":" : "");
    }
}

static void fmt_mac(const uint8_t a[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             a[0], a[1], a[2], a[3], a[4], a[5]);
}

static int is_lan_ip(const char *s)
{
    unsigned int a, b, c, d;
    if (!s || !*s) return 0;
    if (strchr(s, ':')) {
        /* ULA / link-local / multicast-as-source are LAN-ish */
        return (strncasecmp(s, "fc", 2) == 0 || strncasecmp(s, "fd", 2) == 0 ||
                strncasecmp(s, "fe80", 4) == 0 || strncasecmp(s, "fe90", 4) == 0 ||
                strncasecmp(s, "fea0", 4) == 0 || strncasecmp(s, "feb0", 4) == 0);
    }
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
        if (a == 10 || a == 127) return 1;
        if (a == 192 && b == 168) return 1;
        if (a == 172 && b >= 16 && b <= 31) return 1;
        if (a == 169 && b == 254) return 1;
    }
    return 0;
}

/* ---- payload parsers -------------------------------------------------- */

/* DNS name with compression pointers. Returns bytes consumed at top level. */
static int dns_name(const uint8_t *pkt, int plen, int off,
                    char *out, size_t cap, int *consumed)
{
    int pos = off, n = 0, jumps = 0, first = 1, len;
    out[0] = '\0';
    while (pos < plen && jumps < 12) {
        len = pkt[pos];
        if (len == 0) { pos++; break; }
        if ((len & 0xc0) == 0xc0) {
            int ptr;
            if (pos + 1 >= plen) return -1;
            ptr = ((len & 0x3f) << 8) | pkt[pos + 1];
            if (first) { if (consumed) *consumed = pos + 2 - off; first = 0; }
            pos = ptr;
            jumps++;
            continue;
        }
        if ((len & 0xc0) || pos + 1 + len > plen) return -1;
        if (n > 0 && n + 1 < (int)cap) out[n++] = '.';
        if (n + len < (int)cap) { memcpy(out + n, pkt + pos + 1, len); n += len; }
        out[n] = '\0';
        pos += 1 + len;
    }
    if (first && consumed) *consumed = pos - off;
    return n ? 0 : -1;
}

/* Returns 1 when the payload was recognised as DNS. */
static int parse_dns(const uint8_t *p, int n, probe_result_t *r)
{
    uint16_t flags, qd, an;
    int off = 12, used = 0, i;
    if (n < 12) return 0;
    flags = be16(p + 2);
    qd = be16(p + 4);
    an = be16(p + 6);
    r->proto_fixed = 1;
    r->proto = ((flags & 0x000f) != 0) ? PROTO_FAILED : PROTO_DNS;
    if (qd > 0) {
        char qname[OL_MAX_HOST];
        if (dns_name(p, n, off, qname, sizeof(qname), &used) == 0) {
            strncpy(r->host, qname, sizeof(r->host) - 1);
            r->host[sizeof(r->host) - 1] = '\0';
            off += used + 4;      /* qtype + qclass */
        } else return 1;
    }
    /* Answers: cache A / AAAA -> hostname for QUIC and bare-IP flows. */
    for (i = 0; i < an && off + 10 <= n; i++) {
        char aname[OL_MAX_HOST];
        int u = 0, type, rdlen;
        if (dns_name(p, n, off, aname, sizeof(aname), &u) != 0) break;
        off += u;
        if (off + 10 > n) break;
        type = be16(p + off);
        rdlen = be16(p + off + 8);
        off += 10;
        if (off + rdlen > n) break;
        if (type == 1 && rdlen == 4) {
            char ip[46];
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                     p[off], p[off + 1], p[off + 2], p[off + 3]);
            strncpy(r->dns_ip, ip, sizeof(r->dns_ip) - 1);
            strncpy(r->dns_host, r->host[0] ? r->host : aname,
                    sizeof(r->dns_host) - 1);
        } else if (type == 28 && rdlen == 16) {
            fmt6(p + off, r->dns_ip);
            strncpy(r->dns_host, r->host[0] ? r->host : aname,
                    sizeof(r->dns_host) - 1);
        }
        off += rdlen;
        if (r->dns_ip[0]) break;   /* one address is enough */
    }
    return 1;
}

/* TLS ClientHello: pull server_name (0x0000) and ALPN (0x0010). */
static int parse_tls(const uint8_t *p, int n, probe_result_t *r)
{
    const uint8_t *hs, *b, *end, *ext, *extend;
    if (n < 11) return 0;
    if (p[0] == 0x15) {                       /* alert: 15 ver(2) len(2) level desc */
        r->proto = (n > 6 && p[5] == 0x02) ? PROTO_FAILED : PROTO_TLS;
        r->proto_fixed = 1;
        return 1;
    }
    if (p[0] == 0x17 || p[0] == 0x14) {       /* app data / change cipher */
        r->proto = PROTO_TLS;
        r->proto_fixed = 1;
        return 1;
    }
    if (p[0] != 0x16 || p[1] != 0x03) return 0;
    r->proto = PROTO_TLS;
    r->proto_fixed = 1;
    hs = p + 5;
    if (n < 5 + 4 || hs[0] != 0x01) return 1;  /* not ClientHello */
    b = hs + 4;
    end = p + n;
    if (b + 34 > end) return 1;
    b += 2 + 32;                              /* version + random */
    if (b >= end) return 1;
    b += 1 + b[0];                            /* session id */
    if (b + 2 > end) return 1;
    b += 2 + be16(b);                         /* cipher suites */
    if (b + 1 > end) return 1;
    b += 1 + b[0];                            /* compression methods */
    if (b + 2 > end) return 1;
    ext = b + 2;
    extend = ext + be16(b);
    if (extend > end) extend = end;
    while (ext + 4 <= extend) {
        int type = be16(ext), len = be16(ext + 2);
        const uint8_t *v = ext + 4;
        if (v + len > extend) break;
        if (type == 0x0000 && len >= 5) {
            int listlen = be16(v);
            if (listlen >= 3 && v[2] == 0x00) {
                int nl = be16(v + 3), take;
                if (nl > 0 && 5 + nl <= len) {
                    take = nl < OL_MAX_HOST - 1 ? nl : OL_MAX_HOST - 1;
                    memcpy(r->host, v + 5, take);
                    r->host[take] = '\0';
                }
            }
        }
        ext = v + len;
    }
    return 1;
}

static int parse_http(const uint8_t *p, int n, probe_result_t *r)
{
    static const char *methods[] = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ",
                                   "OPTIONS ", "PATCH ", "CONNECT ", "HTTP/1.", NULL};
    int i, hit = 0;
    const char *line, *e;
    if (n < 12) return 0;
    for (i = 0; methods[i]; i++) {
        if ((int)strlen(methods[i]) <= n &&
            strncasecmp((const char *)p, methods[i], strlen(methods[i])) == 0) {
            hit = 1; break;
        }
    }
    if (!hit) return 0;
    r->proto = PROTO_HTTP;
    r->proto_fixed = 1;
    line = (const char *)p;
    e = (const char *)p + n;
    while (line < e) {
        const char *nl = memchr(line, '\n', (size_t)(e - line));
        int llen = nl ? (int)(nl - line) : (int)(e - line);
        if (llen > 6 && strncasecmp(line, "Host:", 5) == 0) {
            int s = 5;
            while (s < llen && (line[s] == ' ' || line[s] == '\t')) s++;
            int take = llen - s;
            while (take > 0 && (line[s + take - 1] == '\r' ||
                                line[s + take - 1] == ' ')) take--;
            if (take > 0 && take < OL_MAX_HOST) {
                memcpy(r->host, line + s, take);
                r->host[take] = '\0';
                /* strip :port */
                { char *colon = strrchr(r->host, ':');
                  if (colon && strchr(colon, ']') == NULL) *colon = '\0'; }
            }
            break;
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 1;
}

static int parse_quic(const uint8_t *p, int n, probe_result_t *r)
{
    if (n < 5) return 0;
    if ((p[0] & 0xc0) != 0xc0) return 0;      /* long header only */
    r->proto = PROTO_QUIC;
    r->proto_fixed = 1;
    /* ClientHello inside QUIC Initial is encrypted; the SNI is recovered by
     * reverse-looking-up the destination IP in the DNS answer cache instead. */
    (void)be32(p + 1);
    return 1;
}

/* ---- frame parser ----------------------------------------------------- */

int probe_parse_frame(const uint8_t *buf, int len, probe_result_t *r)
{
    uint16_t et;
    int off = 14, fam = 0, ipproto = 0, reverse = 0;
    char src[46] = "", dst[46] = "";
    char cip[46], rip[46];
    uint16_t sport = 0, dport = 0, cport, rport;
    const uint8_t *l4, *payload, *ipend;
    int plen, total = 0;
    const char *m;
    char ethsrc[18], ethdst[18];

    memset(r, 0, sizeof(*r));
    r->proto = PROTO_OTHER;
    if (len < 34) return 0;
    fmt_mac(buf + 6, ethsrc);
    fmt_mac(buf + 0, ethdst);
    et = (uint16_t)((buf[12] << 8) | buf[13]);
    if (et == 0x8100 || et == 0x88a8) {        /* single VLAN tag */
        et = (uint16_t)((buf[16] << 8) | buf[17]);
        off = 18;
    }
    if (et == 0x0800) {
        const uint8_t *ip = buf + off;
        int ihl, frag;
        if (len < off + 20) return 0;
        ihl = (ip[0] & 0x0f) * 4;
        if (ihl < 20) return 0;
        ipproto = ip[9];
        frag = (int)be16(ip + 6);
        if (frag & 0x1fff) return 0;           /* non-first fragment: no L4 */
        total = (int)be16(ip + 2);
        if (total < ihl) return 0;
        ipend = ip + total;
        inet_ntop(AF_INET, ip + 12, src, sizeof(src));
        inet_ntop(AF_INET, ip + 16, dst, sizeof(dst));
        fam = 4;
        l4 = ip + ihl;
    } else if (et == 0x86dd) {
        const uint8_t *ip = buf + off;
        if (len < off + 40) return 0;
        ipproto = ip[6];                       /* no extension header walk */
        total = 40 + (int)be16(ip + 4);
        ipend = ip + total;
        fmt6(ip + 8, src);
        fmt6(ip + 24, dst);
        fam = 6;
        l4 = ip + 40;
    } else {
        return 0;
    }
    if (ipend > buf + len) ipend = buf + len;
    if (ipend < l4 || (ipproto != 6 && ipproto != 17)) return 0;

    if (ipproto == 6) {
        int doff;
        if (l4 + 20 > ipend) return 0;
        sport = be16(l4);
        dport = be16(l4 + 2);
        doff = (l4[12] >> 4) * 4;
        if (doff < 20 || l4 + doff > ipend) return 0;
        payload = l4 + doff;
        r->is_rst = (l4[13] & 0x04) != 0;
        r->is_syn = (l4[13] & 0x02) != 0 && (l4[13] & 0x10) == 0;
    } else {
        if (l4 + 8 > ipend) return 0;
        sport = be16(l4);
        dport = be16(l4 + 2);
        payload = l4 + 8;
    }
    plen = (int)(ipend - payload);
    if (plen < 0) return 0;

    /* Decide which endpoint is our LAN client and normalise the key so that
     * reply-direction packets map onto the same conntrack tuple. */
    m = acct_mac_for_ip(src);
    if (m && *m) {
        strncpy(cip, src, sizeof(cip) - 1);
        strncpy(rip, dst, sizeof(rip) - 1);
    } else {
        m = acct_mac_for_ip(dst);
        if (m && *m) {
            reverse = 1;
            strncpy(cip, dst, sizeof(cip) - 1);
            strncpy(rip, src, sizeof(rip) - 1);
        } else if (is_lan_ip(src)) {
            strncpy(cip, src, sizeof(cip) - 1);
            strncpy(rip, dst, sizeof(rip) - 1);
        } else {
            reverse = 1;
            strncpy(cip, dst, sizeof(cip) - 1);
            strncpy(rip, src, sizeof(rip) - 1);
        }
    }
    cip[sizeof(cip) - 1] = rip[sizeof(rip) - 1] = '\0';
    cport = reverse ? dport : sport;
    rport = reverse ? sport : dport;
    strncpy(r->client_ip, cip, sizeof(r->client_ip) - 1);
    strncpy(r->remote_ip, rip, sizeof(r->remote_ip) - 1);
    snprintf(r->key, sizeof(r->key), "%s|%s|%u|%u|%d",
             cip, rip, cport, rport, ipproto);
    r->reverse = reverse;
    r->ipproto = ipproto;
    r->fam = fam;
    strncpy(r->mac, (m && *m) ? m : (reverse ? ethdst : ethsrc),
            sizeof(r->mac) - 1);

    /* Content-based classification first, port heuristics last. */
    if (plen > 0) {
        if (ipproto == 17 || dport == 53 || sport == 53) {
            if ((dport == 53 || sport == 53 || dport == 853 || sport == 853) &&
                parse_dns(payload, plen, r)) {
                /* done */
            } else if (ipproto == 17 && parse_quic(payload, plen, r)) {
                /* done */
            }
        }
        if (!r->proto_fixed && ipproto == 6) {
            if (!parse_tls(payload, plen, r)) parse_http(payload, plen, r);
        }
    }
    if (!r->proto_fixed) {
        if (r->is_rst) { r->proto = PROTO_FAILED; r->proto_fixed = 1; }
        else if (dport == 53 || sport == 53 || dport == 853 || sport == 853)
            r->proto = PROTO_DNS;
        else if (ipproto == 17 && (rport == 443 || rport == 80))
            r->proto = PROTO_QUIC;
        else if (ipproto == 6 && (rport == 443 || rport == 8443))
            r->proto = PROTO_TLS;
        else if (ipproto == 6 && (rport == 80 || rport == 8080))
            r->proto = PROTO_HTTP;
        else
            r->proto = PROTO_OTHER;
    }
    if (!r->host[0]) {
        const char *h = acct_host_for_ip(rip);
        if (h && *h) {
            strncpy(r->host, h, sizeof(r->host) - 1);
            r->host[sizeof(r->host) - 1] = '\0';
        }
    }
    feature_lookup(r->host, rport, ipproto, &r->appid);
    probe_note_host(r->host, r->appid);
    return 1;
}

/* ---- observed-host diagnostic ------------------------------------------
 * A small ring of the hostnames seen in first packets, with the appid the
 * feature library assigned. This is what makes "the app list is all 未识别"
 * diagnosable: you can tell whether no SNI was captured at all, or whether
 * SNI was captured but the domains simply are not in the private library.
 * Written to hosts.json on every full snapshot (10 s), capped at 128 rows.
 */
#define SEEN_MAX 128
typedef struct { char host[OL_MAX_HOST]; int appid, hits; } seen_t;
static seen_t seen[SEEN_MAX];
static int n_seen;

void probe_note_host(const char *host, int appid)
{
    int i;
    if (!host || !*host) return;
    for (i = 0; i < n_seen; i++) {
        if (strcasecmp(seen[i].host, host) == 0) {
            seen[i].hits++;
            if (appid > 0) seen[i].appid = appid;
            return;
        }
    }
    if (n_seen >= SEEN_MAX) return;
    strncpy(seen[n_seen].host, host, sizeof(seen[n_seen].host) - 1);
    seen[n_seen].host[sizeof(seen[n_seen].host) - 1] = '\0';
    seen[n_seen].appid = appid;
    seen[n_seen].hits = 1;
    n_seen++;
}

void probe_write_hosts(const char *dir)
{
    char path[300], tmp[512], esc[300];
    int i, k, matched = 0;
    FILE *f;
    snprintf(path, sizeof(path), "%s/hosts.json", dir);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"total\":%d,\"hosts\":[", n_seen);
    for (i = 0; i < n_seen; i++) {
        const char *nm = feature_app_name(seen[i].appid);
        if (seen[i].appid > 0) matched++;
        /* Hostnames are DNS/SNI wire data: escape before putting them in JSON */
        k = 0;
        for (const char *p = seen[i].host; *p && k < (int)sizeof(esc) - 8; p++) {
            unsigned char ch = (unsigned char)*p;
            if (ch == '"' || ch == '\\') { esc[k++] = '\\'; esc[k++] = (char)ch; }
            else if (ch < 0x20) { k += snprintf(esc + k, sizeof(esc) - k, "\\u%04x", ch); }
            else esc[k++] = (char)ch;
        }
        esc[k] = '\0';
        fprintf(f, "%s{\"host\":\"%s\",\"appid\":%d,\"name\":", i ? "," : "",
                esc, seen[i].appid);
        if (nm) {
            k = 0;
            for (const char *p = nm; *p && k < (int)sizeof(esc) - 8; p++) {
                unsigned char ch = (unsigned char)*p;
                if (ch == '"' || ch == '\\') { esc[k++] = '\\'; esc[k++] = (char)ch; }
                else esc[k++] = (char)ch;
            }
            esc[k] = '\0';
            fprintf(f, "\"%s\"", esc);
        } else fprintf(f, "null");
        fprintf(f, ",\"hits\":%d}", seen[i].hits);
    }
    fprintf(f, "],\"matched\":%d}\n", matched);
    fclose(f);
    rename(tmp, path);
}

/* ---- socket ----------------------------------------------------------- */

/* Kernel-side packet whitelist.
 *
 * The old filter only checked the ethertype, so EVERY IP packet on the LAN
 * (all of the bulk download data, ACKs, beacons...) reached userland and
 * burned recv() + parse cycles -- thousands of syscalls per second under a
 * speed test. The parser only ever needs:
 *   - TCP SYN without ACK          -> new connection tuples
 *   - TCP dport 53/80/443/8080/8443-> TCP DNS, HTTP Host, TLS ClientHello
 *   - UDP dport 53/443/5353/853    -> DNS queries, QUIC Initial, mDNS, DoQ
 *   - UDP sport 53                 -> DNS answers (IP -> host cache)
 * Everything else (the vast majority of bytes and packets) is dropped in
 * the kernel, before the copy. ICMP/ARP were already rejected by the
 * frame parser, so dropping them here changes nothing. Non-standard-port
 * plaintext HTTP / TLS loses its SNI label -- byte accounting (conntrack)
 * is unaffected, and the port heuristics in acct.c still apply.
 *
 * Layout (indices are jump targets, verified by tools/bpf_selftest.py):
 *   0-2   ethertype dispatch                    27-49  IPv6 section
 *   3-26  IPv4 section (X = ihl for tcp[i])     48     accept
 *                                               49     drop
 */
static unsigned bound_idx;      /* ifindex we are bound to, 0 = not attached */
static time_t last_retry;       /* throttle for probe_retry() */
static time_t last_idx_chk;

static int probe_open(const char *ifname, int quiet)
{
    struct sock_filter code[] = {
        /* ethertype */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                  /*  0 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x0800, 1, 0),       /*  1 IPv4 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x86dd, 25, 46),     /*  2 IPv6 -> 28, drop -> 49 */
        /* IPv4: X = ihl */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 14),                  /*  3 */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0f),               /*  4 */
        BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 2),                  /*  5 */
        BPF_STMT(BPF_MISC | BPF_TAX, 0),                         /*  6 X=ihl */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),                  /*  7 ipproto */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 1, 0),            /*  8 tcp -> 10 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 10, 39),         /*  9 udp -> 20, drop */
        /* IPv4 TCP */
        BPF_STMT(BPF_LD | BPF_B | BPF_IND, 27),                  /* 10 flags = 14+ihl+13 */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x12),               /* 11 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 35, 0),        /* 12 SYN-only -> 48 */
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),                  /* 13 dport = 14+ihl+2 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53,   33, 0),        /* 14 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 80,   32, 0),        /* 15 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 443,  31, 0),        /* 16 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8080, 30, 0),        /* 17 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8443, 29, 0),        /* 18 */
        BPF_STMT(BPF_RET | BPF_K, 0),                            /* 19 drop */
        /* IPv4 UDP */
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),                  /* 20 dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53,   26, 0),        /* 21 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 443,  25, 0),        /* 22 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5353, 24, 0),        /* 23 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 853,  23, 0),        /* 24 */
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14),                  /* 25 sport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53,   21, 0),        /* 26 */
        BPF_STMT(BPF_RET | BPF_K, 0),                            /* 27 drop */
        /* IPv6 (fixed offsets, no extension-header walk, same as the parser) */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 20),                  /* 28 next header */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 6, 1, 0),            /* 29 tcp -> 31 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17, 10, 18),         /* 30 udp -> 41, drop */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 67),                  /* 31 flags = 54+13 */
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x12),               /* 32 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x02, 14, 0),        /* 33 SYN-only -> 48 */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 56),                  /* 34 dport = 54+2 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53,   12, 0),        /* 35 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 80,   11, 0),        /* 36 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 443,  10, 0),        /* 37 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8080,  9, 0),        /* 38 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 8443,  8, 0),        /* 39 */
        BPF_STMT(BPF_RET | BPF_K, 0),                            /* 40 drop */
        /* IPv6 UDP */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 56),                  /* 41 dport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53,    5, 0),        /* 42 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 443,   4, 0),        /* 43 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 5353,  3, 0),        /* 44 */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 853,   2, 0),        /* 45 */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 54),                  /* 46 sport */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 53,    0, 1),        /* 47 */
        BPF_STMT(BPF_RET | BPF_K, 512),                          /* 48 accept */
        BPF_STMT(BPF_RET | BPF_K, 0)                             /* 49 drop */
    };
    struct sock_fprog prog = { .len = (unsigned short)(sizeof(code) / sizeof(code[0])),
                               .filter = code };
    struct sockaddr_ll sa;
    /* 1 MB request (kernel doubles it). Before the BPF whitelist this needed
     * 4 MB to survive millisecond-scale bursts of bulk-traffic packets; now
     * only SYN/port-hit/DNS packets ever reach the queue, a few hundred per
     * second at worst, so even a 3 s idle round fits in well under 1 MB. */
    int idx, flags, rcvbuf = 1 * 1024 * 1024, got_buf = 0;
    socklen_t got_len = sizeof(got_buf);
    const char *ifn = ifname;

    if (!ifn || !*ifn) ifn = "br-lan";
    idx = (int)if_nametoindex(ifn);
    if (idx == 0) {
        /* br-lan is created by netifd and oaf-lite can win that race; the
         * caller retries, so only the first miss is worth a log line. */
        if (!quiet)
            ol_log("probe: interface %s not ready, will retry every 5s "
                   "(packet sampling off until then)", ifn);
        return -1;
    }
    if (strncmp(G.lan_if, ifn, sizeof(G.lan_if) - 1) != 0)
        strncpy(G.lan_if, ifn, sizeof(G.lan_if) - 1);
    pfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (pfd < 0) { ol_log("probe: socket: %s", strerror(errno)); return -1; }
    if (setsockopt(pfd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0) {
        ol_log("probe: BPF attach: %s", strerror(errno));
        close(pfd); pfd = -1; return -1;
    }
    /* PPE / HNAT 一旦接管一条流，它就不再路过 CPU —— 我们能拿到的只有它
     * 刚建立时的那几个包（SYN、ClientHello、DNS 查询）。所以「丢包」的
     * 代价不是少算流量（字节数由 conntrack 写回），而是这条流永远认不出
     * 应用：几十 GB 的下载最后全落进「未识别」。
     * 默认 256 KB 环形缓冲在千兆满速下只够装几毫秒的包，SYN 和
     * ClientHello 会被内核直接丢掉。这里用 SO_RCVBUFFORCE 拿到 4 MB
     * （root 才能绕过 net.core.rmem_max），拿不到就退回普通 SO_RCVBUF。 */
#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif
    if (setsockopt(pfd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
        setsockopt(pfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    getsockopt(pfd, SOL_SOCKET, SO_RCVBUF, &got_buf, &got_len);
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = idx;
    if (bind(pfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        ol_log("probe: bind %s: %s", ifn, strerror(errno));
        close(pfd); pfd = -1; return -1;
    }
    flags = fcntl(pfd, F_GETFL, 0);
    fcntl(pfd, F_SETFL, flags | O_NONBLOCK);
    bound_idx = (unsigned)idx;
    if (!quiet)
        ol_log("probe: AF_PACKET on %s, snaplen 512, rcvbuf %d KB, burst %d",
               ifn, got_buf / 1024, OL_MAX_PKT_ROUND);
    return 0;
}

int probe_init(const char *ifname) { return probe_open(ifname, 0); }

/* Called every round: attaches as soon as br-lan exists, and re-attaches when
 * netifd rebuilds the bridge under us (same name, new ifindex -- the bound
 * socket keeps working but silently captures nothing). */
void probe_retry(void)
{
    time_t now = time(NULL);

    if (pfd >= 0) {
        if (now - last_idx_chk < 30) return;
        last_idx_chk = now;
        if (if_nametoindex(G.lan_if) == bound_idx) return;
        ol_log("probe: %s index changed (was %u), reattaching", G.lan_if, bound_idx);
        probe_close();
    }
    if (now - last_retry < 5) return;
    last_retry = now;
    if (probe_open(G.lan_if, 1) == 0)
        ol_log("probe: attached to %s (%lds after start)", G.lan_if,
               (long)(now - G.boot_ts));
}

void probe_close(void)
{
    if (pfd >= 0) { close(pfd); pfd = -1; }
}

int probe_poll(int budget)
{
    int n = 0;
    probe_retry();                       /* cheap no-op once attached */
    if (pfd < 0) return 0;
    while (n < budget) {
        ssize_t got = recv(pfd, pktbuf, sizeof(pktbuf), 0);
        probe_result_t r;
        if (got <= 0) break;                 /* EAGAIN or socket closed */
        n++;
        if (probe_parse_frame(pktbuf, (int)got, &r)) {
            acct_bind_flow(&r);
            if (r.dns_ip[0] && r.dns_host[0])
                acct_cache_dns(r.dns_ip, r.dns_host);
        }
    }
    return n;
}

/* ---- built-in self test ----------------------------------------------- */

static int mk_frame(uint8_t *out, const char *src, const char *dst,
                    int ipproto, uint16_t sport, uint16_t dport,
                    const uint8_t *payload, int plen, uint8_t tcpflags)
{
    int l4len = (ipproto == 6) ? 20 : 8;
    int total = 14 + 20 + l4len + plen;
    uint8_t *ip = out + 14, *l4 = ip + 20;
    memset(out, 0, (size_t)total);
    out[12] = 0x08; out[13] = 0x00;
    out[0] = 0x00; out[1] = 0x11; out[2] = 0x22;
    out[3] = 0x33; out[4] = 0x44; out[5] = 0x55;
    out[6] = 0x66; out[7] = 0x77; out[8] = 0x88;
    out[9] = 0x99; out[10] = 0xaa; out[11] = 0xbb;
    ip[0] = 0x45; ip[1] = 0;
    ip[2] = (uint8_t)(((total - 14) >> 8) & 0xff);
    ip[3] = (uint8_t)((total - 14) & 0xff);
    ip[8] = 64; ip[9] = (uint8_t)ipproto;
    inet_pton(AF_INET, src, ip + 12);
    inet_pton(AF_INET, dst, ip + 16);
    l4[0] = (uint8_t)(sport >> 8); l4[1] = (uint8_t)(sport & 0xff);
    l4[2] = (uint8_t)(dport >> 8); l4[3] = (uint8_t)(dport & 0xff);
    if (ipproto == 6) { l4[12] = 0x50; l4[13] = tcpflags; }
    else { l4[4] = (uint8_t)((8 + plen) >> 8); l4[5] = (uint8_t)((8 + plen) & 0xff); }
    if (plen > 0) memcpy(l4 + l4len, payload, (size_t)plen);
    return total;
}

/* Minimal TLS 1.2 ClientHello carrying SNI "v.qq.com" */
static const uint8_t TLS_CH[] = {
    0x16, 0x03, 0x01, 0x00, 0x40,
    0x01, 0x00, 0x00, 0x3c, 0x03, 0x03,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x00,                    /* session id len */
    0x00, 0x02, 0x13, 0x01, /* cipher suites */
    0x01, 0x00,              /* compression */
    0x00, 0x11,              /* extensions len = 17 */
    0x00, 0x00, 0x00, 0x0d,  /* ext SNI, len 13 */
    0x00, 0x0b, 0x00, 0x00, 0x08,
    'v','.','q','q','.','c','o','m'
};

static const uint8_t DNS_Q[] = {
    0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
    0x03,'w','w','w', 0x02,'q','q', 0x03,'c','o','m', 0x00,
    0x00,0x01, 0x00,0x01
};
static const uint8_t DNS_NX[] = {
    0x12,0x34, 0x81,0x83, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
    0x03,'w','w','w', 0x03,'b','a','d', 0x00,
    0x00,0x01, 0x00,0x01
};
static const uint8_t QUIC_INIT[] = {
    0xc0, 0x00,0x00,0x00,0x01, 0x08, 0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08,
    0x00, 0x00, 0x44,0x9d,0x7f,0x3a,0x00,0x01,0x02,0x03,0x04
};

static int check(const char *name, const uint8_t *frame, int len,
                 int want_proto, const char *want_host, int want_appid)
{
    probe_result_t r;
    int ok;
    if (!probe_parse_frame(frame, len, &r)) {
        printf("FAIL %-16s frame rejected\n", name);
        return 1;
    }
    ok = (r.proto == want_proto) &&
         (!want_host || strcasecmp(r.host, want_host) == 0) &&
         (want_appid < 0 || r.appid == want_appid);
    printf("%s %-16s proto=%-6s host=%-16s appid=%d key=%s\n",
           ok ? "PASS" : "FAIL", name, ol_proto_names[r.proto],
           r.host[0] ? r.host : "-", r.appid, r.key);
    return ok ? 0 : 1;
}

int probe_selftest(void)
{
    uint8_t f[1024];
    int len, fail = 0;
    const char *http = "GET / HTTP/1.1\r\nHost: weixin.qq\r\nUser-Agent: selftest\r\n\r\n";

    len = mk_frame(f, "192.168.1.100", "1.2.3.4", 6, 51000, 443,
                   TLS_CH, (int)sizeof(TLS_CH), 0x18);
    fail += check("TLS SNI", f, len, PROTO_TLS, "v.qq.com", 3003);

    len = mk_frame(f, "192.168.1.100", "1.2.3.4", 6, 51001, 80,
                   (const uint8_t *)http, (int)strlen(http), 0x18);
    fail += check("HTTP Host", f, len, PROTO_HTTP, "weixin.qq", 1002);

    len = mk_frame(f, "192.168.1.100", "8.8.8.8", 17, 53000, 53,
                   DNS_Q, (int)sizeof(DNS_Q), 0);
    fail += check("DNS query", f, len, PROTO_DNS, "www.qq.com", -1);

    len = mk_frame(f, "8.8.8.8", "192.168.1.100", 17, 53, 53000,
                   DNS_NX, (int)sizeof(DNS_NX), 0);
    fail += check("DNS NXDOMAIN", f, len, PROTO_FAILED, NULL, -1);

    len = mk_frame(f, "192.168.1.100", "1.2.3.4", 17, 51002, 443,
                   QUIC_INIT, (int)sizeof(QUIC_INIT), 0);
    fail += check("QUIC initial", f, len, PROTO_QUIC, NULL, 0);

    len = mk_frame(f, "192.168.1.100", "1.2.3.4", 6, 51003, 443, NULL, 0, 0x04);
    fail += check("TCP RST", f, len, PROTO_FAILED, NULL, 0);

    len = mk_frame(f, "192.168.1.100", "1.2.3.4", 6, 51004, 9000,
                   (const uint8_t *)"hello", 5, 0x18);
    fail += check("plain TCP", f, len, PROTO_OTHER, NULL, 0);
    return fail;
}
