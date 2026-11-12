/* chdsweep: small helpers */
#include "chdsweep.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p) { fputs("chdsweep: out of memory\n", stderr); exit(EXIT_FAILED); }
    return p;
}

void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p) { fputs("chdsweep: out of memory\n", stderr); exit(EXIT_FAILED); }
    return p;
}

char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    return memcpy(xmalloc(n), s, n);
}

void sl_add(struct strlist *l, const char *s)
{
    l->v = xrealloc(l->v, (size_t)(l->n + 1) * sizeof *l->v);
    l->v[l->n++] = xstrdup(s);
}

static void sb_need(struct strbuf *b, size_t extra)
{
    if (b->len + extra + 1 <= b->cap) return;
    size_t cap = b->cap ? b->cap * 2 : 256;
    while (cap < b->len + extra + 1) cap *= 2;
    b->s = xrealloc(b->s, cap);
    b->cap = cap;
}

void sb_reset(struct strbuf *b) { b->len = 0; if (b->s) b->s[0] = 0; }
void sb_free(struct strbuf *b) { free(b->s); b->s = NULL; b->len = b->cap = 0; }

void sb_addn(struct strbuf *b, const char *s, size_t n)
{
    sb_need(b, n);
    memcpy(b->s + b->len, s, n);
    b->len += n;
    b->s[b->len] = 0;
}

void sb_add(struct strbuf *b, const char *s) { sb_addn(b, s, strlen(s)); }

void sb_printf(struct strbuf *b, const char *fmt, ...)
{
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n > 0) {
        sb_need(b, (size_t)n);
        vsnprintf(b->s + b->len, (size_t)n + 1, fmt, ap2);
        b->len += (size_t)n;
    }
    va_end(ap2);
}

/* Length of the valid UTF-8 sequence at p (1..4), or 0 when it is not valid. */
static int utf8_len(const unsigned char *p)
{
    if (p[0] < 0x80) return 1;
    int n;
    if (p[0] >= 0xC2 && p[0] <= 0xDF) n = 2;
    else if (p[0] >= 0xE0 && p[0] <= 0xEF) n = 3;
    else if (p[0] >= 0xF0 && p[0] <= 0xF4) n = 4;
    else return 0;
    for (int i = 1; i < n; i++)
        if ((p[i] & 0xC0) != 0x80) return 0;   /* also stops at the terminating NUL */
    if (p[0] == 0xE0 && p[1] < 0xA0) return 0;
    if (p[0] == 0xED && p[1] > 0x9F) return 0;
    if (p[0] == 0xF0 && p[1] < 0x90) return 0;
    if (p[0] == 0xF4 && p[1] > 0x8F) return 0;
    return n;
}

void sb_json_str(struct strbuf *b, const char *s)
{
    const unsigned char *p = (const unsigned char *)s;
    sb_addn(b, "\"", 1);
    while (*p) {
        if (*p == '"' || *p == '\\') {
            char e[2] = { '\\', (char)*p };
            sb_addn(b, e, 2);
            p++;
        } else if (*p < 0x20 || *p == 0x7f) {
            sb_printf(b, "\\u%04x", *p);
            p++;
        } else {
            int n = utf8_len(p);
            if (n == 0) { sb_add(b, "\\ufffd"); p++; }
            else { sb_addn(b, (const char *)p, (size_t)n); p += n; }
        }
    }
    sb_addn(b, "\"", 1);
}

void iso_time(time_t t, char out[24])
{
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, 24, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

uint64_t fnv1a64(const void *data, size_t n, uint64_t h)
{
    const unsigned char *p = data;
    if (!h) h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void smap_grow(struct smap *m)
{
    size_t oldcap = m->cap;
    char **ok = m->keys;
    int *ov = m->vals;
    m->cap = oldcap ? oldcap * 2 : 64;
    m->keys = xmalloc(m->cap * sizeof *m->keys);
    m->vals = xmalloc(m->cap * sizeof *m->vals);
    memset(m->keys, 0, m->cap * sizeof *m->keys);
    for (size_t i = 0; i < oldcap; i++) {
        if (!ok[i]) continue;
        size_t j = (size_t)fnv1a64(ok[i], strlen(ok[i]), 0) & (m->cap - 1);
        while (m->keys[j]) j = (j + 1) & (m->cap - 1);
        m->keys[j] = ok[i];
        m->vals[j] = ov[i];
    }
    free(ok);
    free(ov);
}

int smap_id(struct smap *m, const char *key, int *isnew)
{
    if ((m->n + 1) * 2 > m->cap) smap_grow(m);
    size_t i = (size_t)fnv1a64(key, strlen(key), 0) & (m->cap - 1);
    for (; m->keys[i]; i = (i + 1) & (m->cap - 1))
        if (!strcmp(m->keys[i], key)) {
            if (isnew) *isnew = 0;
            return m->vals[i];
        }
    m->keys[i] = xstrdup(key);
    m->vals[i] = (int)m->n;
    if (isnew) *isnew = 1;
    return (int)m->n++;
}

int smap_find(const struct smap *m, const char *key)
{
    if (!m->cap) return -1;
    size_t i = (size_t)fnv1a64(key, strlen(key), 0) & (m->cap - 1);
    for (; m->keys[i]; i = (i + 1) & (m->cap - 1))
        if (!strcmp(m->keys[i], key)) return m->vals[i];
    return -1;
}

void smap_free(struct smap *m)
{
    for (size_t i = 0; i < m->cap; i++) free(m->keys[i]);
    free(m->keys);
    free(m->vals);
    memset(m, 0, sizeof *m);
}

int csv_split(char *line, char **f, int max)
{
    int n = 0;
    char *p = line;
    while (n < max) {
        char *w = p;
        f[n++] = w;
        if (*p == '"') {
            p++;
            while (*p) {
                if (*p == '"') {
                    if (p[1] == '"') { *w++ = '"'; p += 2; }
                    else { p++; break; }
                } else *w++ = *p++;
            }
        } else {
            while (*p && *p != ',') p++;
            w = p;
        }
        while (*p && *p != ',') p++;
        int more = *p == ',';
        *w = 0;
        if (!more) break;
        p++;
    }
    return n;
}
