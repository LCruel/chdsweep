/* chdsweep: streaming scanner.
 *
 * The stream is read in blocks. The last TAIL bytes of a block are not searched
 * until the next block is there, and CTX bytes before them are kept as context,
 * so a number (and the text around it) across a block boundary is seen whole.
 * No global state: one scan_opts buffer per thread.
 */
#include "chdsweep.h"

#include <ctype.h>
#include <string.h>

#define CTX 64     /* bytes kept before the search position: boundary, keyword, token checks */
#define TAIL 128   /* look-ahead: longest grouped number plus what follows it */

struct scanner {
    const struct scan_opts *o;
    struct scan_result *res;
    const unsigned char *buf;
    size_t len;
    uint64_t base;   /* stream offset of buf[0] */
};

static inline int gc(const struct scanner *s, long i)
{
    return (i < 0 || (size_t)i >= s->len) ? -1 : s->buf[i];
}
static inline int isd(int c) { return c >= '0' && c <= '9'; }
static inline int isword(int c)
{
    return isd(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}
static inline int nonprint(int c)
{
    return c >= 0 && (c == 0x7f || (c < 0x20 && c != '\t' && c != '\n' && c != '\r'));
}

static void add_hit(struct scan_result *res, const struct hit *h)
{
    if (res->n == res->cap) {
        res->cap = res->cap ? res->cap * 2 : 16;
        res->hits = xrealloc(res->hits, res->cap * sizeof *res->hits);
    }
    res->hits[res->n++] = *h;
}

void scan_result_reset(struct scan_result *res)
{
    res->n = 0;
    res->cand_total = res->cand_luhn = res->bytes = res->dropped = 0;
    res->binary_db = 0;
}

/* id-keyword: a key name on the same line, in the window before the number. */
static int find_keyword(const struct scanner *s, long start, char *out, size_t outlen)
{
    const struct rules *r = s->o->rules;
    char win[CTX + 1];
    int n = 0;
    long from = start - r->kw_window;
    if (from < 0) from = 0;
    for (long i = from; i < start; i++) {
        int c = s->buf[i];
        if (c == '\n' || c == '\r') { n = 0; continue; }   /* same line only */
        win[n++] = (char)tolower(c);
    }
    win[n] = 0;
    for (int i = 0; i < r->keywords.n; i++)
        if (memmem(win, (size_t)n, r->keywords.v[i], strlen(r->keywords.v[i]))) {
            snprintf(out, outlen, "%s", r->keywords.v[i]);
            return 1;
        }
    return 0;
}

static int is_joiner(int c) { return c == '.' || c == '/' || c == ':' || c == '='; }

/* A number of nd digits at [start, end). Returns 1 when it is recorded as a hit. */
static int evaluate(struct scanner *s, long start, long end, const char *d, int nd, int grouped)
{
    const struct rules *r = s->o->rules;
    const char *brand = brand_lookup(d, nd);
    if (!brand) return 0;

    int before = gc(s, start - 1), after = gc(s, end);
    int track = 0;
    if (!grouped && before == 'B' && gc(s, start - 2) == '%' && after == '^') track = 1;
    else if (isword(before) || isword(after)) return 0;

    s->res->cand_total++;
    if (!luhn_ok(d, nd)) return 0;
    s->res->cand_luhn++;

    if (!track && !grouped && after == '=' && isd(gc(s, end + 1)) && isd(gc(s, end + 2)) &&
        isd(gc(s, end + 3)) && isd(gc(s, end + 4)))
        track = 2;

    /* Over the limit for this file: counted, not kept, so one file full of numbers
     * cannot use up the memory or fill the disk with its run file. */
    if (s->o->hit_limit && s->res->n >= s->o->hit_room) { s->res->dropped++; return 1; }

    struct hit h;
    memset(&h, 0, sizeof h);
    h.offset = s->base + (uint64_t)start;
    h.ndigits = nd;
    h.track = track;
    h.brand = brand;
    mask_number(d, nd, s->o->keep_leading, h.masked);

    if (r->on[R_TEST_CARD] && is_test_card(d, nd)) h.marks |= 1u << R_TEST_CARD;
    if (r->on[R_REPEAT] && is_repeat_digits(d, nd)) h.marks |= 1u << R_REPEAT;
    if (r->on[R_SEQUENCE] && is_sequence(d, nd)) h.marks |= 1u << R_SEQUENCE;
    if (!track) {
        if (r->on[R_ID_KEYWORD] && find_keyword(s, start, h.keyword, sizeof h.keyword))
            h.marks |= 1u << R_ID_KEYWORD;
        /* A dash joins too, as in "tmp-1793453611-30163-4337571408139", but only for a number
         * written without separators: in 4539-1488-0343-6467 the dashes are the card's own. */
        int jb = is_joiner(before) || (!grouped && before == '-');
        int ja = is_joiner(after) || (!grouped && after == '-');
        if (r->on[R_INSIDE_TOKEN] && ((jb && isd(gc(s, start - 2))) || (ja && isd(gc(s, end + 1)))))
            h.marks |= 1u << R_INSIDE_TOKEN;
    }
    if (r->on[R_BINARY] && !s->res->binary_db) {
        int b = 0, a = 0;
        for (int i = 1; i <= 8; i++) {
            if (nonprint(gc(s, start - i))) b = 1;
            if (nonprint(gc(s, end + i - 1))) a = 1;
        }
        if (a && b) h.marks |= 1u << R_BINARY;
    }

    add_hit(s->res, &h);
    return 1;
}

/* A digit run starts at pos. Returns how far to advance. */
static long try_candidate(struct scanner *s, long pos)
{
    char d[24];
    int run = 0;
    while (run < 20 && isd(gc(s, pos + run))) run++;
    if (run >= 20) return run;          /* too long for a card; the rest is skipped digit by digit */

    if (run >= 12) {
        for (int i = 0; i < run; i++) d[i] = (char)s->buf[pos + i];
        evaluate(s, pos, pos + run, d, run, 0);
        memset(d, 0, sizeof d);
        return run;
    }
    if (run == 4) {
        /* Real card groupings only, with the same separator throughout. */
        static const int pats[3][6] = { { 4, 4, 4, 4, 3, 0 }, { 4, 4, 4, 4, 0 }, { 4, 6, 5, 0 } };
        int sep = gc(s, pos + 4);
        if (sep == ' ' || sep == '-') {
            for (int p = 0; p < 3; p++) {
                long q = pos;
                int nd = 0, ok = 1;
                for (int g = 0; pats[p][g] && ok; g++) {
                    if (g > 0) { if (gc(s, q) != sep) { ok = 0; break; } q++; }
                    for (int k = 0; k < pats[p][g]; k++, q++) {
                        if (!isd(gc(s, q))) { ok = 0; break; }
                        d[nd++] = (char)s->buf[q];
                    }
                }
                if (ok && !isd(gc(s, q)) && evaluate(s, pos, q, d, nd, 1)) {
                    memset(d, 0, sizeof d);
                    return q - pos;
                }
            }
            memset(d, 0, sizeof d);
        }
    }
    return run;
}

static int is_binary_db(const unsigned char *b, size_t len)
{
    if (len >= 16 && memcmp(b, "SQLite format 3", 16) == 0) return 1;
    if (len >= 16) {   /* Berkeley DB: magic at offset 12, either byte order */
        static const unsigned char magics[][4] = {
            { 0x00, 0x05, 0x31, 0x62 }, { 0x62, 0x31, 0x05, 0x00 },   /* btree */
            { 0x00, 0x06, 0x15, 0x61 }, { 0x61, 0x15, 0x06, 0x00 },   /* hash */
            { 0x00, 0x04, 0x22, 0x53 }, { 0x53, 0x22, 0x04, 0x00 },   /* queue */
        };
        for (size_t i = 0; i < sizeof magics / sizeof magics[0]; i++)
            if (memcmp(b + 12, magics[i], 4) == 0) return 1;
    }
    return 0;
}

int scan_stream(const struct scan_opts *o, scan_read_fn rd, void *cookie, struct scan_result *res)
{
    struct scanner s = { .o = o, .res = res, .buf = o->buf, .len = 0, .base = 0 };
    unsigned char *buf = o->buf;
    size_t pos = 0;
    int eof = 0, first = 1, rc = 0;

    while (!eof) {
        while (!eof && s.len < SCAN_BUF_SIZE) {
            ssize_t r = rd(cookie, buf + s.len, SCAN_BUF_SIZE - s.len);
            if (r < 0) { rc = -1; eof = 1; }       /* search what was read, then report */
            else if (r == 0) eof = 1;
            else { s.len += (size_t)r; res->bytes += (uint64_t)r; }
        }
        if (first) { res->binary_db = is_binary_db(buf, s.len); first = 0; }

        size_t limit = eof ? s.len : s.len - TAIL;
        while (pos < limit) {
            if (isd(buf[pos]) && (pos == 0 || !isd(buf[pos - 1])))
                pos += (size_t)try_candidate(&s, (long)pos);
            else
                pos++;
        }
        if (eof) break;

        size_t keep = limit > CTX ? limit - CTX : 0;
        memmove(buf, buf + keep, s.len - keep);
        s.base += keep;
        s.len -= keep;
        pos -= keep;
    }
    return rc;
}
