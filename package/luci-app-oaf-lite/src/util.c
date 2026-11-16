/* Small shared helpers. No allocations on the hot path. */
#include "common.h"
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

const char *ol_proto_names[PROTO_MAX]  = {"TLS", "HTTP", "QUIC", "FAILED", "DNS", "OTHER"};
const char *ol_proto_colors[PROTO_MAX] = {
    "#E8B339",  /* TLS    yellow */
    "#F28C3C",  /* HTTP   orange */
    "#2FBF71",  /* QUIC   green  */
    "#E5484D",  /* FAILED red    */
    "#A63D5C",  /* DNS    dark red */
    "#3B82F6"   /* OTHER  blue   */
};

ol_ctx_t G;

uint32_t ol_crc32(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xffffffffU;
    size_t i;
    for (i = 0; i < n; i++) {
        int k;
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xedb88320U & (uint32_t)(-(int32_t)(crc & 1)));
    }
    return crc ^ 0xffffffffU;
}

uint32_t ol_hash_str(const char *s)
{
    uint32_t h = 2166136261U;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619U;
    }
    return h;
}

void ol_trim(char *s)
{
    char *p = s, *e;
    size_t n;
    if (!s) return;
    while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    e = s + n;
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
}

void ol_json_str(char *out, size_t cap, const char *s)
{
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)(s ? s : "");
    if (cap < 3) { if (cap) out[0] = '\0'; return; }
    out[n++] = '"';
    for (; *p && n + 3 < cap; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') { out[n++] = '\\'; out[n++] = (char)c; }
        else if (c == '\n') { out[n++] = '\\'; out[n++] = 'n'; }
        else if (c == '\r') { out[n++] = '\\'; out[n++] = 'r'; }
        else if (c == '\t') { out[n++] = '\\'; out[n++] = 't'; }
        else if (c < 0x20) { out[n++] = ' '; }
        else out[n++] = (char)c;
    }
    out[n++] = '"';
    out[n] = '\0';
}

void ol_atomic_write(const char *path, const char *body)
{
    char tmp[300];
    FILE *f;
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    f = fopen(tmp, "w");
    if (!f) return;
    fwrite(body, 1, strlen(body), f);
    fclose(f);
    if (rename(tmp, path) != 0) remove(tmp);
}

void ol_log(const char *fmt, ...)
{
    char path[300], line[1024];
    va_list ap;
    FILE *f;
    time_t t = time(NULL);
    struct tm tmv;
    char stamp[32];
    localtime_r(&t, &tmv);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &tmv);
    va_start(ap, fmt);
    vsnprintf(line + 0, sizeof(line), fmt, ap);
    va_end(ap);
    if (G.dir[0]) {
        snprintf(path, sizeof(path), "%s/oaf-lite.log", G.dir);
        f = fopen(path, "a");
        if (f) {
            fprintf(f, "%s %s\n", stamp, line);
            fclose(f);
        }
    }
    if (getenv("OAF_LITE_STDERR")) fprintf(stderr, "[oaf-lite] %s\n", line);
}

const char *ol_num(uint64_t v, char *buf, size_t n)
{
    snprintf(buf, n, "%llu", (unsigned long long)v);
    return buf;
}

double ol_wall(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

void ol_localdate(const char *fmt, time_t ts, char *out, size_t cap)
{
    struct tm tmv;
    time_t adj = ts + G.tz_offset;
    gmtime_r(&adj, &tmv);
    strftime(out, cap, fmt, &tmv);
}
