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
#define TAIL 128   /* look-ahead: longest grouped number plus what follows it, also as UTF-16 */

struct scanner {
    const struct scan_opts *o;
    struct scan_result *res;
    const unsigned char *buf;
    size_t len;
    uint64_t base;   /* stream offset of buf[0] */
    int wide;        /* buf holds UTF-16 text read into single bytes: no second level */
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

static void wipe(void *p, size_t n) { memset(p, 0, n); }

/* The space between two groups in the text of a PDF. pdftotext keeps the layout of the page:
 * groups in table cells or at tab stops come out several spaces apart, not always the same
 * number, and a number that runs over the end of a line continues on the next one, after
 * its indent. So: a run of spaces, with at most one line break in the whole number. Returns
 * the length of the gap when a digit follows it, else 0. */
#define GAP_MAX 24
static int pdf_gap(const struct scanner *s, long q, int *breaks)
{
    int n = 0, br = *breaks;
    while (n < GAP_MAX) {
        int c = gc(s, q + n);
        if (c == ' ') n++;
        else if (c == '\n' && !br) { br = 1; n++; }
        else if (c == '\r' && gc(s, q + n + 1) == '\n' && !br) { br = 1; n += 2; }
        else break;
    }
    if (n == 0 || n >= GAP_MAX || !isd(gc(s, q + n))) return 0;
    *breaks = br;
    return n;
}

/* try_grouped() for the text of a PDF, where the groups are a pdf_gap() apart. */
static long try_grouped_pdf(struct scanner *s, long pos)
{
    char d[24];
    for (int i = 0; i < 4; i++) d[i] = (char)s->buf[pos + i];
    long got = 0, ends[5];
    int tot[5], ng = 1, nd = 4, breaks = 0;
    ends[0] = pos + 4;
    tot[0] = 4;
    long q = pos + 4;
    int gap = pdf_gap(s, q, &breaks), run = 0;
    if (!gap) return 0;
    while (run < 7 && isd(gc(s, q + gap + run))) run++;

    if (run == 6) {                                     /* 4-6-5 and 4-6-4 */
        long m = q + gap, t = m + 6;
        int g2 = pdf_gap(s, t, &breaks), last = 0;
        while (g2 && last < 6 && isd(gc(s, t + g2 + last))) last++;
        if (last == 5 || last == 4) {
            for (int i = 0; i < 6; i++) d[4 + i] = (char)s->buf[m + i];
            for (int i = 0; i < last; i++) d[10 + i] = (char)s->buf[t + g2 + i];
            if (evaluate(s, pos, t + g2 + last, d, 10 + last, 1)) got = t + g2 + last - pos;
        }
    } else if (run >= 1 && run <= 4) {                  /* groups of four */
        while (ng < 5 && gap) {
            long t = q + gap;
            run = 0;
            while (run < 5 && isd(gc(s, t + run))) run++;
            if (run == 0 || run > 4 || nd + run > 19) break;
            for (int i = 0; i < run; i++) d[nd + i] = (char)s->buf[t + i];
            nd += run;
            q = t + run;
            ends[ng] = q;
            tot[ng] = nd;
            ng++;
            if (run < 4) break;
            gap = pdf_gap(s, q, &breaks);
        }
        for (int k = ng - 1; k >= 0 && tot[k] >= 12 && !got; k--)
            if (evaluate(s, pos, ends[k], d, tot[k], 1)) got = ends[k] - pos;
    }
    wipe(d, sizeof d);
    return got;
}

/* A number written in groups, starting with the four digits at pos. Returns its length in
 * bytes when it is recorded as a hit, else 0.
 *
 * The layouts are those of real cards: groups of four with a shorter last group where the
 * length asks for it (4-4-4-4, 4-4-4-4-3, 4-4-4-1, ...), and 4-6-5 and 4-6-4 as American
 * Express and Diners print them. Between the groups: one space, dash, dot or tab, or two
 * spaces, or a space as a web form and a URL write it (+ and %20), and the same one
 * throughout. */
static long try_grouped(struct scanner *s, long pos)
{
    char d[24];
    int c = gc(s, pos + 4), c1 = c, c2 = c, sl = 1;
    if (s->o->pdf_text && (c == ' ' || c == '\n' || c == '\r')) return try_grouped_pdf(s, pos);
    if (c == ' ' && gc(s, pos + 5) == ' ') sl = 2;
    else if (c == '%' && gc(s, pos + 5) == '2' && gc(s, pos + 6) == '0') { sl = 3; c1 = '2'; c2 = '0'; }
    else if (c != ' ' && c != '-' && c != '.' && c != '\t' && c != '+') return 0;
#define SEP_AT(q) (gc(s, (q)) == c && (sl < 2 || gc(s, (q) + 1) == c1) && (sl < 3 || gc(s, (q) + 2) == c2))
    for (int i = 0; i < 4; i++) d[i] = (char)s->buf[pos + i];
    long got = 0, q = pos + 4 + sl;
    int run = 0;
    while (run < 7 && isd(gc(s, q + run))) run++;

    if (run == 6 && SEP_AT(q + 6)) {                    /* 4-6-5 and 4-6-4 */
        long t = q + 6 + sl;
        int last = 0;
        while (last < 6 && isd(gc(s, t + last))) last++;
        if (last == 5 || last == 4) {
            for (int i = 0; i < 6; i++) d[4 + i] = (char)s->buf[q + i];
            for (int i = 0; i < last; i++) d[10 + i] = (char)s->buf[t + i];
            if (evaluate(s, pos, t + last, d, 10 + last, 1)) got = t + last - pos;
        }
    } else if (run >= 1 && run <= 4) {                  /* groups of four */
        long ends[5];
        int tot[5], ng = 1, nd = 4;
        ends[0] = pos + 4;
        tot[0] = 4;
        q = pos + 4;
        while (ng < 5 && SEP_AT(q)) {
            long t = q + sl;
            run = 0;
            while (run < 5 && isd(gc(s, t + run))) run++;
            if (run == 0 || run > 4 || nd + run > 19) break;
            for (int i = 0; i < run; i++) d[nd + i] = (char)s->buf[t + i];
            nd += run;
            q = t + run;
            ends[ng] = q;
            tot[ng] = nd;
            ng++;
            if (run < 4) break;                         /* a shorter group is the last one */
        }
        /* The longest reading first: 4-4-4-4-3 before the 4-4-4-4 it starts with. */
        for (int k = ng - 1; k >= 0 && tot[k] >= 12 && !got; k--)
            if (evaluate(s, pos, ends[k], d, tot[k], 1)) got = ends[k] - pos;
    }
#undef SEP_AT
    wipe(d, sizeof d);
    return got;
}

static long try_candidate(struct scanner *s, long pos);

/* UTF-16 text: every character is two bytes, so a number reads 4 \0 5 \0 3 \0 ... and is
 * not a run of digits. Where a digit is followed by a zero byte and another digit, the
 * characters around it are read as UTF-16 into a small buffer, with anything outside ASCII
 * as one non-word byte, and the same matcher runs on that. It works anywhere in a file,
 * with or without a byte-order mark: a Windows text file, or a text column inside a
 * database file. Returns the length in bytes when a hit was recorded, else 0. */
#define WIDE_BEFORE 64   /* characters before: boundary, keyword and token checks */
#define WIDE_AFTER 48    /* the longest grouped number is 27 characters, plus what follows */
static long try_wide(struct scanner *s, long pos)
{
    if (s->wide) return 0;
    if (gc(s, pos - 1) == 0 && isd(gc(s, pos - 2))) return 0;   /* inside a number already tried */
    unsigned char w[WIDE_BEFORE + WIDE_AFTER];
    struct scan_result *res = s->res;
    long got = 0;
    /* hi: where the second byte of a character is. +1 is little endian, what Windows writes. */
    for (int hi = 1; hi >= -1 && !got; hi -= 2) {
        int n = 0, start;
        for (int i = -WIDE_BEFORE; i < 0; i++) {
            int c = gc(s, pos + 2L * i), h = gc(s, pos + 2L * i + hi);
            if (c < 0 || h < 0) { n = 0; continue; }            /* before the buffer: start later */
            w[n++] = (unsigned char)(h == 0 ? c : 0x80);
        }
        start = n;
        for (int i = 0; i < WIDE_AFTER; i++) {
            int c = gc(s, pos + 2L * i), h = gc(s, pos + 2L * i + hi);
            if (c < 0 || h < 0) break;
            w[n++] = (unsigned char)(h == 0 ? c : 0x80);
        }
        if (n - start < 12 || !isd(w[start]) || (start > 0 && isd(w[start - 1]))) continue;
        struct scanner t = { .o = s->o, .res = res, .buf = w, .len = (size_t)n, .base = 0, .wide = 1 };
        size_t n0 = res->n;
        uint64_t drop0 = res->dropped, ct = res->cand_total, cl = res->cand_luhn;
        long adv = try_candidate(&t, start);
        if (res->n > n0 || res->dropped > drop0) {
            if (res->n > n0) res->hits[n0].offset = s->base + (uint64_t)pos;
            got = adv * 2;
        } else {                                                /* not counted twice */
            res->cand_total = ct;
            res->cand_luhn = cl;
        }
    }
    wipe(w, sizeof w);
    return got;
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
        wipe(d, sizeof d);
        return run;
    }
    long got = 0;
    if (run == 4) got = try_grouped(s, pos);
    else if (run == 1 && gc(s, pos + 1) == 0 && isd(gc(s, pos + 2))) got = try_wide(s, pos);
    return got ? got : run;
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
