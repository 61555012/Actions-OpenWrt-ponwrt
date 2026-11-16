/* OAF feature.bin reader.
 *
 * The library is an encrypted text file:
 *   [0..3]   "FWXB"
 *   [4]      version  (1)
 *   [5]      algorithm (1 = XTEA-CTR)
 *   [6..7]   header size (24, LE)
 *   [8..11]  plaintext length (LE)
 *   [12..15] CRC32 of the plaintext (LE, zlib convention)
 *   [16..23] nonce / initial counter (LE 64-bit)
 *   [24..]   ciphertext
 *
 * Keystream = XTEA-encipher(counter_lo, counter_hi) for counter = nonce,
 * nonce+1, ... packed as two LE uint32 and XORed with 8 bytes at a time.
 * This mirrors fwx_feature.c in OpenAppFilter exactly; we only ever READ
 * the file, never push the rules into the kernel.
 *
 * Plaintext lines:  id~name:[proto;sport;dport;host_url;request;dict;search;ignore,...]
 * We build a longest-suffix domain index (host_url and search fields) and a
 * weak port index. Payload-hex and regex rules are intentionally ignored:
 * they need the whole packet stream, which hardware offload does not expose.
 */
#include "common.h"
#include <ctype.h>

static const uint32_t XTEA_KEY[4] = {
    0x8f4c29a1U, 0x73b6d502U, 0xc14e87f3U, 0x2ad95b60U
};
#define XTEA_DELTA 0x9e3779b9U

static domain_rule_t  domains[OL_MAX_RULES];
static int            n_domains;
static port_rule_t    ports[OL_MAX_PORTRULES];
static int            n_ports;
static appname_t      names[OL_MAX_NAMES];
static int            n_names;
static appclass_t     classes[OL_MAX_CLASSES];
static int            n_classes;
static int            cur_class_id;         /* #class section currently open */
static char           feature_version[32];
static char           feature_format[32];

static void xtea_enc(uint32_t v[2])
{
    uint32_t v0 = v[0], v1 = v[1], s = 0;
    int i;
    for (i = 0; i < 32; i++) {
        v0 += ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + XTEA_KEY[s & 3]));
        s += XTEA_DELTA;
        v1 += ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + XTEA_KEY[(s >> 11) & 3]));
    }
    v[0] = v0;
    v[1] = v1;
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

/* Lowercase + validate a domain-ish token. Returns 0 when it is a URL path,
 * a hex payload pattern, a regex or anything else we cannot suffix-match. */
static int clean_domain(const char *src, char *out, size_t cap)
{
    const char *p = src;
    size_t n = 0;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p == '^') p++;
    if (p[0] == '*' && p[1] == '.') p += 2;
    if (*p == '.') p++;
    for (; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
        if (c == '/' || c == '|' || c == '^' || c == '*' || c == '[' ||
            c == ']' || c == '(' || c == ')' || c == '\\' || c == '"') return 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')) return 0;
        if (n + 1 >= cap) return 0;
        out[n++] = (char)tolower(c);
    }
    out[n] = '\0';
    /* Need at least one dot and something meaningful on both sides */
    if (n < 4 || !strchr(out, '.')) return 0;
    if (out[0] == '.' || out[n - 1] == '.') return 0;
    return 1;
}

static void add_domain(const char *tok, int appid)
{
    char pat[64];
    int i, len;
    if (n_domains >= OL_MAX_RULES) return;
    if (!clean_domain(tok, pat, sizeof(pat))) return;
    len = (int)strlen(pat);
    for (i = 0; i < n_domains; i++) {
        if (domains[i].appid == appid && domains[i].len == len &&
            strcmp(domains[i].pat, pat) == 0) return;
    }
    strncpy(domains[n_domains].pat, pat, sizeof(domains[n_domains].pat) - 1);
    domains[n_domains].pat[sizeof(domains[n_domains].pat) - 1] = '\0';
    domains[n_domains].len = len;
    domains[n_domains].appid = appid;
    n_domains++;
}

static void add_port(const char *tok, int ipproto, int appid)
{
    int lo = 0, hi = 0;
    const char *dash;
    if (n_ports >= OL_MAX_PORTRULES) return;
    if (!tok || !*tok || !isdigit((unsigned char)tok[0])) return;
    dash = strchr(tok, '-');
    /* Ranges like 10000-65535 are far too broad to identify an app on their
     * own: they would label half the LAN as one game/video app. Only exact,
     * unusual single ports are kept as a weak fallback. */
    if (dash) return;
    lo = hi = atoi(tok);
    if (lo < 1 || lo > 65535) return;
    /* A bare 80/443/53 matches virtually everything: never use it as an
     * application rule, it would label the entire LAN as one app. */
    if (lo == hi && (lo == 80 || lo == 443 || lo == 53 || lo == 8080 || lo == 8443))
        return;
    ports[n_ports].lo = lo;
    ports[n_ports].hi = hi;
    ports[n_ports].ipproto = ipproto;
    ports[n_ports].appid = appid;
    n_ports++;
}

static void add_name(int id, const char *name)
{
    int i;
    if (id <= 0 || n_names >= OL_MAX_NAMES) return;
    for (i = 0; i < n_names; i++) if (names[i].id == id) return;
    names[n_names].id = id;
    names[n_names].class_id = cur_class_id;
    strncpy(names[n_names].name, name, sizeof(names[n_names].name) - 1);
    names[n_names].name[sizeof(names[n_names].name) - 1] = '\0';
    n_names++;
}

/* "#class chat 1 聊天" opens a section: every app line below it belongs to
 * that class until the next #class. Exported as classes.json so the LuCI
 * class filter works without oafd. */
static void add_class(const char *line)
{
    char key[32], name[64];
    int id = 0, i;
    if (n_classes >= OL_MAX_CLASSES) return;
    key[0] = name[0] = '\0';
    if (sscanf(line + 7, "%31s %d %63[^\r\n]", key, &id, name) < 2) return;
    ol_trim(name);
    if (id <= 0) return;
    for (i = 0; i < n_classes; i++)
        if (classes[i].id == id) { cur_class_id = id; return; }
    classes[n_classes].id = id;
    strncpy(classes[n_classes].key, key, sizeof(classes[n_classes].key) - 1);
    classes[n_classes].key[sizeof(classes[n_classes].key) - 1] = '\0';
    strncpy(classes[n_classes].name, name, sizeof(classes[n_classes].name) - 1);
    classes[n_classes].name[sizeof(classes[n_classes].name) - 1] = '\0';
    n_classes++;
    cur_class_id = id;
}

/* Split one [...] body into comma-separated sub-features and harvest the
 * 4th (host url) and 7th (search) semicolon fields. */
static void parse_features(const char *body, int appid)
{
    char work[2048];
    char *save1 = NULL, *sub;
    size_t n = strlen(body);
    if (n >= sizeof(work)) n = sizeof(work) - 1;
    memcpy(work, body, n);
    work[n] = '\0';

    sub = strtok_r(work, ",", &save1);
    while (sub) {
        /* Empty fields matter: host_url is field index 3 and search is index 6.
         * strtok_r would collapse them, so split manually on a private copy. */
        {
            char raw[512], *p, *start;
            int idx = 0;
            char *arr[9] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
            ol_trim(sub);
            strncpy(raw, sub, sizeof(raw) - 1);
            raw[sizeof(raw) - 1] = '\0';
            p = start = raw;
            while (idx < 9) {
                if (*p == ';' || *p == '\0') {
                    char end = *p;
                    *p = '\0';
                    arr[idx++] = start;
                    if (end == '\0') break;
                    start = p + 1;
                }
                p++;
            }
            {
                int ipproto = (arr[0] && strncmp(arr[0], "udp", 3) == 0) ? 17 : 6;
                if (arr[3] && *arr[3]) add_domain(arr[3], appid);
                if (arr[6] && *arr[6]) add_domain(arr[6], appid);
                if (arr[2] && *arr[2]) add_port(arr[2], ipproto, appid);
            }
        }
        sub = strtok_r(NULL, ",", &save1);
    }
}

/* Parse the plaintext v3/v4 format. `text` is modified in place by strtok_r. */
static int parse_plaintext(char *text)
{
    char *line, *save = NULL;
    line = strtok_r(text, "\n", &save);
    while (line) {
        char *tilde, *colon;
        ol_trim(line);
        if (!strncmp(line, "#version", 8)) {
            strncpy(feature_version, line + 9, sizeof(feature_version) - 1);
            feature_version[sizeof(feature_version) - 1] = '\0';
            ol_trim(feature_version);
        } else if (!strncmp(line, "#class ", 7)) {
            add_class(line);
        } else if (line[0] && line[0] != '#') {
            int id;
            char nm[128];
            tilde = strchr(line, '~');
            colon = tilde ? strchr(tilde, ':') : NULL;
            id = atoi(line);
            if (id > 0 && tilde && colon && colon[1] == '[') {
                size_t l = (size_t)(tilde - line);
                char *end = strchr(colon + 2, ']');
                if (!end) end = colon + 2 + strlen(colon + 2);
                *end = '\0';
                /* Name sits between '~' and ':': 1001~QQ:[...] -> "QQ" */
                l = (size_t)(colon - (tilde + 1));
                if (l >= sizeof(nm)) l = sizeof(nm) - 1;
                memcpy(nm, tilde + 1, l);
                nm[l] = '\0';
                ol_trim(nm);
                add_name(id, nm);
                parse_features(colon + 2, id);
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    if (n_names == 0) return -1;
    ol_log("feature: %s source=%s rules=%d ports=%d apps=%d",
           feature_version[0] ? feature_version : "unknown",
           feature_format, n_domains, n_ports, n_names);
    return 0;
}

/* Accept BOTH the official encrypted feature.bin and the plaintext
 * feature_v4_converted.cfg. The plaintext file is byte-identical to the
 * decrypted ciphertext, so the rule index is identical either way. Using the
 * plaintext file is the default: it can be edited/extended by the user
 * without the XTEA toolchain, and no kernel feature push is involved. */
int feature_load(const char *path)
{
    FILE *f;
    uint8_t *buf = NULL, *plain = NULL;
    char *text;
    long fsize;
    int rc = -1;

    n_domains = n_ports = n_names = n_classes = 0;
    cur_class_id = 0;
    feature_version[0] = '\0';

    f = fopen(path, "rb");
    if (!f) { ol_log("feature: cannot open %s", path); return -1; }
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize < 32) { fclose(f); return -1; }
    buf = (uint8_t *)malloc((size_t)fsize);
    if (!buf || fread(buf, 1, (size_t)fsize, f) != (size_t)fsize) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);

    if (memcmp(buf, "FWXB", 4) == 0) {
        uint32_t plen, crc;
        uint64_t nonce, counter;
        size_t off;
        if (buf[4] != 1 || buf[5] != 1 || rd32(buf + 8) == 0 ||
            (uint32_t)fsize < 24 + rd32(buf + 8)) {
            ol_log("feature: bad FWXB header");
            goto out;
        }
        plen = rd32(buf + 8);
        crc  = rd32(buf + 12);
        nonce = rd64(buf + 16);
        plain = (uint8_t *)malloc(plen + 1);
        if (!plain) goto out;
        memcpy(plain, buf + 24, plen);
        plain[plen] = '\0';
        counter = nonce;
        off = 0;
        while (off < plen) {
            uint32_t v[2];
            uint8_t ks[8];
            int b;
            v[0] = (uint32_t)(counter & 0xffffffffU);
            v[1] = (uint32_t)(counter >> 32);
            xtea_enc(v);
            ks[0] = (uint8_t)(v[0] & 0xff);
            ks[1] = (uint8_t)((v[0] >> 8) & 0xff);
            ks[2] = (uint8_t)((v[0] >> 16) & 0xff);
            ks[3] = (uint8_t)((v[0] >> 24) & 0xff);
            ks[4] = (uint8_t)(v[1] & 0xff);
            ks[5] = (uint8_t)((v[1] >> 8) & 0xff);
            ks[6] = (uint8_t)((v[1] >> 16) & 0xff);
            ks[7] = (uint8_t)((v[1] >> 24) & 0xff);
            for (b = 0; b < 8 && off < plen; b++, off++) plain[off] ^= ks[b];
            counter++;
        }
        if (ol_crc32(plain, plen) != crc) {
            ol_log("feature: CRC mismatch (got %08x want %08x)",
                   ol_crc32(plain, plen), crc);
            goto out;
        }
        strncpy(feature_format, "FWXB-XTEA (decrypted)", sizeof(feature_format) - 1);
        text = (char *)plain;
    } else {
        plain = (uint8_t *)malloc((size_t)fsize + 1);
        if (!plain) goto out;
        memcpy(plain, buf, (size_t)fsize);
        plain[fsize] = '\0';
        text = (char *)plain;
        if (fsize >= 3 && (uint8_t)text[0] == 0xef &&
            (uint8_t)text[1] == 0xbb && (uint8_t)text[2] == 0xbf) text += 3;
        strncpy(feature_format, "plaintext v4.0", sizeof(feature_format) - 1);
    }
    feature_format[sizeof(feature_format) - 1] = '\0';
    rc = parse_plaintext(text);
out:
    free(buf);
    free(plain);
    return rc;
}

/* 追加加载一份「本地补充特征」：不重置索引，按 id 合并。
 *
 * 官方库只有 500 多条域名，实测家里 72 个真实域名只命中 12 个 —— 国内的
 * 大流量基本全走 CDN，douyinstatic / xhscdn / bdstatic 这类域名官方库里
 * 根本没有，于是几十 GB 的下载全落进「未识别」。用户在自己的
 * feature.local.cfg 里用同一个 id 追加域名即可，不必动厂商文件：
 *   3001~抖音:[tcp;;;douyinstatic.com;;]
 * 解析器按 id 合并（add_name 遇到重复 id 直接跳过，域名/端口照加），
 * 所以既不会覆盖官方规则，也不影响应用名和分类。 */
int feature_load_extra(const char *path)
{
    FILE *f;
    char *text;
    long fsize;
    int rc, d0, p0, n0;

    f = fopen(path, "rb");
    if (!f) return -1;                      /* 没有补充库是正常情况，不报错 */
    fseek(f, 0, SEEK_END);
    fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > (1L << 20)) { fclose(f); return -1; }
    text = (char *)malloc((size_t)fsize + 1);
    if (!text) { fclose(f); return -1; }
    if (fread(text, 1, (size_t)fsize, f) != (size_t)fsize) {
        fclose(f); free(text); return -1;
    }
    fclose(f);
    text[fsize] = '\0';
    if (fsize >= 3 && (uint8_t)text[0] == 0xef &&
        (uint8_t)text[1] == 0xbb && (uint8_t)text[2] == 0xbf)
        memmove(text, text + 3, strlen(text + 3) + 1);

    d0 = n_domains; p0 = n_ports; n0 = n_names;
    rc = parse_plaintext(text);
    ol_log("feature: extra %s -> +%d domains +%d ports +%d apps (total %d/%d)",
           path, n_domains - d0, n_ports - p0, n_names - n0, n_domains, n_names);
    free(text);
    return rc == 0 ? 0 : -1;
}

/* Longest-suffix match. "v.qq.com" hits rule "qq.com" only at a dot boundary,
 * so "notqq.com" cannot match. */
int feature_lookup(const char *host, int dport, int ipproto, int *appid)
{
    int i, best = 0, bestlen = 0;
    size_t hl;
    if (appid) *appid = 0;
    if (host && *host) {
        hl = strlen(host);
        for (i = 0; i < n_domains; i++) {
            const domain_rule_t *d = &domains[i];
            if ((size_t)d->len > hl) continue;
            if (strcasecmp(host + hl - d->len, d->pat) != 0) continue;
            if ((size_t)d->len < hl && host[hl - d->len - 1] != '.') continue;
            if (d->len > bestlen) { bestlen = d->len; best = d->appid; }
        }
        if (best) { if (appid) *appid = best; return 1; }
    }
    /* Weak fallback: an unusual fixed port from the feature file. Deliberately
     * skipped for 80/443/53 (see add_port) and never used when a hostname is
     * present but unmatched -- that would mislabel unknown HTTPS as one app. */
    if (!host || !*host) {
        for (i = 0; i < n_ports; i++) {
            if (ports[i].ipproto == ipproto && dport >= ports[i].lo &&
                dport <= ports[i].hi) {
                if (appid) *appid = ports[i].appid;
                return 2;
            }
        }
    }
    return 0;
}

const char *feature_app_name(int appid)
{
    int i;
    for (i = 0; i < n_names; i++) if (names[i].id == appid) return names[i].name;
    return NULL;
}

int feature_rule_count(void) { return n_domains; }
int feature_name_count(void) { return n_names; }
const appname_t *feature_name_at(int i)
{
    return (i >= 0 && i < n_names) ? &names[i] : NULL;
}
int feature_class_count(void) { return n_classes; }
const appclass_t *feature_class_at(int i)
{
    return (i >= 0 && i < n_classes) ? &classes[i] : NULL;
}

int feature_selftest(const char *path)
{
    int id = 0, hit, fail = 0;
    if (feature_load(path) != 0) { printf("FAIL feature_load\n"); return 1; }
    if (n_domains < 100 || n_names < 100) {
        printf("FAIL too few rules: domains=%d names=%d\n", n_domains, n_names);
        fail++;
    }
    {
        const char *nm = feature_app_name(3003);
        printf("%s app name 3003 -> %s\n",
               (nm && strcmp(nm, "3003") != 0) ? "PASS" : "FAIL",
               nm ? nm : "?");
        if (!nm || strcmp(nm, "3003") == 0) fail++;
    }
    hit = feature_lookup("v.qq.com", 443, 6, &id);
    printf("%s suffix v.qq.com -> id=%d (%s)\n",
           (hit && id == 3003) ? "PASS" : "FAIL", id,
           feature_app_name(id) ? feature_app_name(id) : "?");
    if (!(hit && id == 3003)) fail++;
    hit = feature_lookup("weixin.qq", 443, 6, &id);
    printf("%s exact weixin.qq -> id=%d (%s)\n",
           (hit && id == 1002) ? "PASS" : "FAIL", id,
           feature_app_name(id) ? feature_app_name(id) : "?");
    if (!(hit && id == 1002)) fail++;
    hit = feature_lookup("notweixin.qq.com.evil.net", 443, 6, &id);
    printf("%s boundary evil.net -> %s\n",
           (hit && id == 1002) ? "FAIL" : "PASS", hit ? "matched" : "no match");
    if (hit && id == 1002) fail++;
    hit = feature_lookup("", 443, 6, &id);
    printf("%s common port is never an app -> %s\n",
           hit ? "FAIL" : "PASS", hit ? "matched" : "no match");
    if (hit) fail++;
    printf("%s #class sections=%d (1001 -> class %d)\n",
           n_classes >= 10 ? "PASS" : "FAIL", n_classes,
           feature_name_at(0) ? feature_name_at(0)->class_id : -1);
    if (n_classes < 10) fail++;
    return fail;
}
