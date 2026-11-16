/* chdsweep unit tests: Luhn, brand table, masking, groupings, boundaries, block
 * boundaries, track data and each rule that works on the number or its context. */
#include "chdsweep.h"

#include <stdlib.h>
#include <string.h>

static int failures, checks;
#define CHECK(cond) \
    do { checks++; if (!(cond)) { failures++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } } while (0)

struct mem { const char *data; size_t len, pos, chunk; };

static ssize_t mem_read(void *cookie, void *buf, size_t n)
{
    struct mem *m = cookie;
    size_t k = m->len - m->pos;
    if (k > n) k = n;
    if (m->chunk && k > m->chunk) k = m->chunk;
    memcpy(buf, m->data + m->pos, k);
    m->pos += k;
    return (ssize_t)k;
}

static struct rules R;
static unsigned char *workbuf;
static struct scan_result res;

static int as_pdf_text;   /* 1: scan as the text of a PDF */

static size_t scan_n(const char *data, size_t len, size_t chunk)
{
    struct scan_opts o = { .rules = &R, .keep_leading = 0, .buf = workbuf, .pdf_text = as_pdf_text };
    struct mem m = { data, len, 0, chunk };
    scan_result_reset(&res);
    CHECK(scan_stream(&o, mem_read, &m, &res) == 0);
    return res.n;
}
static size_t scan(const char *text) { return scan_n(text, strlen(text), 0); }
static int marked(size_t i, int rule) { return i < res.n && (res.hits[i].marks & (1u << rule)) != 0; }

/* A Luhn-valid number with this prefix and length; the middle digits are random. */
static void make_card(const char *prefix, int n, char *out)
{
    int p = (int)strlen(prefix);
    memcpy(out, prefix, (size_t)p);
    do {
        for (int i = p; i < n - 1; i++) out[i] = (char)('0' + rand() % 10);
        out[n] = 0;
        for (int c = 0; c < 10; c++) {
            out[n - 1] = (char)('0' + c);
            if (luhn_ok(out, n)) break;
        }
    } while (is_repeat_digits(out, n) || is_sequence(out, n) || is_test_card(out, n));
}

static void test_number_checks(void)
{
    CHECK(luhn_ok("4111111111111111", 16));
    CHECK(!luhn_ok("4111111111111112", 16));
    CHECK(luhn_ok("378282246310005", 15));

    CHECK(!strcmp(brand_lookup("4111111111111111", 16), "visa"));
    CHECK(!strcmp(brand_lookup("4222222222222", 13), "visa"));
    CHECK(brand_lookup("41111111111111", 14) == NULL);            /* visa has no 14 digits */
    CHECK(!strcmp(brand_lookup("5555555555554444", 16), "mastercard"));
    CHECK(!strcmp(brand_lookup("2223003122003222", 16), "mastercard"));
    CHECK(brand_lookup("2220000000000000", 16) == NULL);          /* just below the 2-series */
    CHECK(!strcmp(brand_lookup("378282246310005", 15), "amex"));
    CHECK(!strcmp(brand_lookup("6011111111111117", 16), "discover"));
    CHECK(!strcmp(brand_lookup("3530111333300000", 16), "jcb"));
    CHECK(!strcmp(brand_lookup("36227206271667", 14), "diners"));
    CHECK(!strcmp(brand_lookup("6200000000000005", 16), "unionpay"));
    CHECK(!strcmp(brand_lookup("501800000009", 12), "maestro"));
    CHECK(brand_lookup("1234567890123456", 16) == NULL);
    CHECK(brand_lookup("41111111111", 11) == NULL);

    char m[24];
    mask_number("4111111111111111", 16, 0, m);
    CHECK(!strcmp(m, "41111111****1111"));
    mask_number("4111111111111111", 16, 6, m);
    CHECK(!strcmp(m, "411111******1111"));
    mask_number("378282246310005", 15, 0, m);                      /* under 16 digits: six, never eight */
    CHECK(!strcmp(m, "378282*****0005"));
    mask_number("4222222222222", 13, 0, m);
    CHECK(!strcmp(m, "422222***2222"));

    CHECK(is_test_card("4242424242424242", 16));
    CHECK(!is_test_card("4242424242424241", 16));
    CHECK(is_repeat_digits("4000000000000002", 16));
    CHECK(!is_repeat_digits("4539148803436467", 16));
    CHECK(is_sequence("1234567890123452", 16));
    CHECK(is_sequence("9876543210987654", 16));
    CHECK(!is_sequence("4539148803436467", 16));
}

static void test_formats(void)
{
    char c[24], text[200];
    make_card("4539", 16, c);

    snprintf(text, sizeof text, "card %s end", c);
    CHECK(scan(text) == 1);
    CHECK(res.hits[0].offset == 5 && res.hits[0].ndigits == 16 && res.hits[0].marks == 0);
    CHECK(res.hits[0].track == 0 && !strcmp(res.hits[0].brand, "visa"));
    CHECK(strlen(res.hits[0].masked) == 16 && !memcmp(res.hits[0].masked + 8, "****", 4));

    snprintf(text, sizeof text, "%s", c);                           /* whole file is the number */
    CHECK(scan(text) == 1);

    snprintf(text, sizeof text, "x %.4s %.4s %.4s %.4s y", c, c + 4, c + 8, c + 12);
    CHECK(scan(text) == 1 && res.hits[0].marks == 0);
    snprintf(text, sizeof text, "x %.4s-%.4s-%.4s-%.4s y", c, c + 4, c + 8, c + 12);
    CHECK(scan(text) == 1);
    snprintf(text, sizeof text, "x %.4s-%.4s %.4s-%.4s y", c, c + 4, c + 8, c + 12);   /* mixed separators */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s  %.4s  %.4s  %.4s y", c, c + 4, c + 8, c + 12); /* two spaces */
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 16 && res.hits[0].offset == 2);
    snprintf(text, sizeof text, "x %.4s  %.4s %.4s  %.4s y", c, c + 4, c + 8, c + 12);  /* two, then one */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s   %.4s   %.4s   %.4s y", c, c + 4, c + 8, c + 12); /* three spaces */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x\t%.4s\t%.4s\t%.4s\t%.4s\ty", c, c + 4, c + 8, c + 12); /* tabs: columns */
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 16);
    snprintf(text, sizeof text, "x %.4s.%.4s.%.4s.%.4s y", c, c + 4, c + 8, c + 12);     /* dots */
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 16 && res.hits[0].marks == 0);
    /* A space as a web form and a URL write it, as it ends up in an access log. */
    snprintf(text, sizeof text, "GET /pay?card=%.4s+%.4s+%.4s+%.4s&cvc=123 HTTP/1.1", c, c + 4, c + 8, c + 12);
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 16 && res.hits[0].marks == 0);
    snprintf(text, sizeof text, "/pay?card=%.4s%%20%.4s%%20%.4s%%20%.4s&x=1", c, c + 4, c + 8, c + 12);
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 16 && res.hits[0].offset == 10);
    snprintf(text, sizeof text, "x %.4s%%20%.4s+%.4s%%20%.4s y", c, c + 4, c + 8, c + 12);    /* mixed */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s%%2B%.4s%%2B%.4s%%2B%.4s y", c, c + 4, c + 8, c + 12); /* an encoded plus sign */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s/%.4s/%.4s/%.4s y", c, c + 4, c + 8, c + 12);     /* not a separator */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s - %.4s - %.4s - %.4s y", c, c + 4, c + 8, c + 12);
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.6s-%.4s-%.6s y", c, c + 6, c + 10);                 /* not a card grouping */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s %.4s %.4s y", c, c + 4, c + 8);                  /* three groups of a 16 */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.8s %.8s y", c, c + 8);                             /* not a card grouping */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s %.4s %.4s %.4s 123 y", c, c + 4, c + 8, c + 12); /* card, then a CVV */
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 16);

    make_card("3714", 15, c);
    snprintf(text, sizeof text, "amex %.4s %.6s %.5s.", c, c + 4, c + 10);
    CHECK(scan(text) == 1 && !strcmp(res.hits[0].brand, "amex") && res.hits[0].ndigits == 15);

    make_card("4539", 19, c);
    snprintf(text, sizeof text, "%.4s %.4s %.4s %.4s %.3s", c, c + 4, c + 8, c + 12, c + 16);
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 19);

    make_card("5018", 12, c);
    snprintf(text, sizeof text, "<%s>", c);
    CHECK(scan(text) == 1 && !strcmp(res.hits[0].brand, "maestro"));
}

/* Groups of four for every length a brand issues, and the layouts printed on the card. */
static void test_brand_layouts(void)
{
    static const struct { const char *prefix; int n; int g[6]; const char *brand; } lay[] = {
        { "4539", 13, { 4, 4, 4, 1 }, "visa" },       { "5018", 12, { 4, 4, 4 }, "maestro" },
        { "3605", 14, { 4, 4, 4, 2 }, "diners" },     { "3605", 14, { 4, 6, 4 }, "diners" },
        { "3714", 15, { 4, 4, 4, 3 }, "amex" },       { "3714", 15, { 4, 6, 5 }, "amex" },
        { "6759", 18, { 4, 4, 4, 4, 2 }, "maestro" }, { "6221", 17, { 4, 4, 4, 4, 1 }, "unionpay" },
        { "6500", 19, { 4, 4, 4, 4, 3 }, "discover" },
    };
    static const char *const seps[] = { " ", "-", ".", "\t", "  ", "+", "%20" };
    char c[24], text[200];
    for (size_t i = 0; i < sizeof lay / sizeof lay[0]; i++)
        for (size_t k = 0; k < sizeof seps / sizeof seps[0]; k++) {
            make_card(lay[i].prefix, lay[i].n, c);
            int len = snprintf(text, sizeof text, "paid ");
            for (int g = 0, at = 0; g < 6 && lay[i].g[g]; at += lay[i].g[g], g++)
                len += snprintf(text + len, sizeof text - (size_t)len, "%s%.*s", g ? seps[k] : "", lay[i].g[g], c + at);
            snprintf(text + len, sizeof text - (size_t)len, " ok");
            size_t n = scan(text);
            CHECK(n == 1 && res.hits[0].ndigits == lay[i].n && !strcmp(res.hits[0].brand, lay[i].brand) &&
                  res.hits[0].offset == 5);
            if (n != 1) printf("  layout %zu separator %zu: %zu hits\n", i, k, n);
        }
    /* A layout no card has: 4-6-5 is American Express only, and its prefix is not Visa's. */
    make_card("4539", 15, c);
    snprintf(text, sizeof text, "x %.4s %.6s %.5s y", c, c + 4, c + 10);
    CHECK(scan(text) == 0);
}

/* UTF-16: text as Windows writes it, and as a column inside a database file. */
static size_t scan16(const char *text, int big, int bom, const char *lead, size_t leadlen, size_t chunk)
{
    static char b[140000];
    size_t n = 0;
    memcpy(b, lead, leadlen);
    n = leadlen;
    if (bom) { b[n++] = (char)(big ? 0xFE : 0xFF); b[n++] = (char)(big ? 0xFF : 0xFE); }
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        /* '~' stands for a letter outside ASCII (U+0416): both of its bytes are set */
        unsigned lo = *p == '~' ? 0x16 : *p, hi = *p == '~' ? 0x04 : 0;
        b[n++] = (char)(big ? hi : lo);
        b[n++] = (char)(big ? lo : hi);
    }
    return scan_n(b, n, chunk);
}

static void test_utf16(void)
{
    static char lead[70000];
    char c[24], text[300];
    make_card("4539", 16, c);
    for (int big = 0; big <= 1; big++)
        for (int bom = 0; bom <= 1; bom++) {
            snprintf(text, sizeof text, "card %s paid", c);
            CHECK(scan16(text, big, bom, "", 0, 0) == 1);
            CHECK(res.hits[0].ndigits == 16 && !strcmp(res.hits[0].brand, "visa") && res.hits[0].marks == 0);
            CHECK(res.hits[0].offset == (uint64_t)(bom ? 2 : 0) + 10 + (uint64_t)big);   /* the first digit's byte */
            snprintf(text, sizeof text, "%s", c);                                         /* the whole file */
            CHECK(scan16(text, big, bom, "", 0, 0) == 1);
            snprintf(text, sizeof text, "x %.4s %.4s %.4s %.4s y\r\n", c, c + 4, c + 8, c + 12);
            CHECK(scan16(text, big, bom, "", 0, 0) == 1 && res.hits[0].ndigits == 16);
            snprintf(text, sizeof text, "x\t%.4s-%.4s-%.4s-%.4s\ty", c, c + 4, c + 8, c + 12);
            CHECK(scan16(text, big, bom, "", 0, 0) == 1);
            snprintf(text, sizeof text, "~%s~", c);                  /* letters outside ASCII are not word characters */
            CHECK(scan16(text, big, bom, "", 0, 0) == 1);
            snprintf(text, sizeof text, "ref%s paid", c);            /* glued to a word */
            CHECK(scan16(text, big, bom, "", 0, 0) == 0);
            snprintf(text, sizeof text, "paid %sabc", c);
            CHECK(scan16(text, big, bom, "", 0, 0) == 0);
            snprintf(text, sizeof text, "paid 9%s7 x", c);           /* inside a longer number */
            CHECK(scan16(text, big, bom, "", 0, 0) == 0);
            snprintf(text, sizeof text, "paid %.15s%c x", c, c[15] == '9' ? '0' : c[15] + 1);
            CHECK(scan16(text, big, bom, "", 0, 0) == 0);            /* check digit wrong */
            snprintf(text, sizeof text, "a %s b %s c", c, c);        /* two numbers, each once */
            CHECK(scan16(text, big, bom, "", 0, 0) == 2);
            snprintf(text, sizeof text, "imei: %s\r\n", c);
            CHECK(scan16(text, big, bom, "", 0, 0) == 1 && marked(0, R_ID_KEYWORD));
        }
    /* Inside a binary file, after bytes of something else, at an odd and an even offset, and
     * across the block boundary whatever the size of the reads. */
    memset(lead, 0xC3, sizeof lead);
    snprintf(text, sizeof text, " %s ", c);
    for (size_t at = 0; at < 2; at++)
        for (size_t chunk = 0; chunk <= 7; chunk += 7) {
            CHECK(scan16(text, 0, 0, lead, 1000 + at, chunk) == 1 && res.hits[0].offset == 1000 + at + 2);
            for (size_t near = 65536 - 140; near < 65536 + 8; near += 3)
                CHECK(scan16(text, 0, 0, lead, near + at, chunk) == 1);
        }
    /* Plain text is read as before: a digit, a zero byte and a digit do not make it UTF-16. */
    CHECK(scan_n("4\0005\0003", 5, 0) == 0);
    snprintf(text, sizeof text, "card %s paid", c);
    CHECK(scan(text) == 1 && res.hits[0].offset == 5);
}

/* The text of a PDF as pdftotext lays it out: groups several spaces or one line break apart. */
static void test_pdf_text(void)
{
    char c[24], a[24], text[400];
    make_card("4539", 16, c);
    make_card("3714", 15, a);
    static const char *const fmt[] = {
        "Jansen        %.4s      %.4s    %.4s     %.4s     10,00",      /* table cells, uneven gaps */
        "tabs:   %.4s    %.4s                      %.4s      %.4s",       /* tab stops */
        "the card number %.4s %.4s\n%.4s %.4s is broken over two lines",  /* end of a line */
        "the card number %.4s %.4s\r\n    %.4s %.4s after an indent",
        "number %.4s\n%.4s %.4s %.4s.",
        "plain %.4s %.4s %.4s %.4s too",
    };
    for (size_t i = 0; i < sizeof fmt / sizeof fmt[0]; i++) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        snprintf(text, sizeof text, fmt[i], c, c + 4, c + 8, c + 12);
#pragma GCC diagnostic pop
        as_pdf_text = 1;
        size_t n = scan(text);
        CHECK(n == 1 && res.hits[0].ndigits == 16 && res.hits[0].marks == 0);
        if (n != 1) printf("  pdf text %zu: %zu hits\n", i, n);
        as_pdf_text = 0;                                  /* in any other file only the last one is a number */
        CHECK(scan(text) == (i == 5 ? 1u : 0u));
    }
    as_pdf_text = 1;
    snprintf(text, sizeof text, "amex   %.4s    %.6s   %.5s  paid", a, a + 4, a + 10);
    CHECK(scan(text) == 1 && res.hits[0].ndigits == 15);
    snprintf(text, sizeof text, "x %.4s-%.4s-%.4s-%.4s y", c, c + 4, c + 8, c + 12);     /* the other separators as ever */
    CHECK(scan(text) == 1);
    snprintf(text, sizeof text, "x %.4s\n%.4s\n%.4s\n%.4s y", c, c + 4, c + 8, c + 12);  /* a column of numbers */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s %.4s\n\n%.4s %.4s y", c, c + 4, c + 8, c + 12);  /* an empty line between */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s %.4s\f%.4s %.4s y", c, c + 4, c + 8, c + 12);    /* the next page */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s %.4s%30s%.4s %.4s y", c, c + 4, "", c + 8, c + 12); /* too far apart */
    CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "x %.4s  %.4s  %.4s  %.4s\n123 y", c, c + 4, c + 8, c + 12); /* then a short line */
    /* One hit: the 16 digits, or all 19 when those happen to be a valid number too. */
    CHECK(scan(text) == 1 && (res.hits[0].ndigits == 16 || res.hits[0].ndigits == 19));
    as_pdf_text = 0;
}

static void test_boundaries(void)
{
    char c[24], text[200];
    make_card("5412", 16, c);
    snprintf(text, sizeof text, "a%s", c);   CHECK(scan(text) == 0);    /* letter before */
    snprintf(text, sizeof text, "%sa", c);   CHECK(scan(text) == 0);    /* letter after */
    snprintf(text, sizeof text, "_%s", c);   CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "%s_", c);   CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "9%s", c);   CHECK(scan(text) == 0);    /* part of a longer number */
    snprintf(text, sizeof text, "%s9", c);   CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "12345678%s12345678", c);  CHECK(scan(text) == 0);
    snprintf(text, sizeof text, "\"%s\",", c);  CHECK(scan(text) == 1);
    snprintf(text, sizeof text, "(%s)", c);     CHECK(scan(text) == 1);
    snprintf(text, sizeof text, "deadbeef%scafe", c);  CHECK(scan(text) == 0);  /* inside a hash */
    c[15] = (char)(c[15] == '9' ? '0' : c[15] + 1);                      /* break the check digit */
    snprintf(text, sizeof text, " %s ", c);  CHECK(scan(text) == 0);
}

/* The number must be found wherever the block boundary falls, with any read size. */
static void test_block_boundaries(void)
{
    char c[24];
    make_card("4539", 16, c);
    size_t size = 3 * 64 * 1024 + 4096;
    char *data = malloc(size);
    static const size_t chunks[] = { 0, 1000, 65536, 7 };
    for (long shift = -40; shift <= 40; shift++) {
        for (int g = 0; g < 2; g++) {
            memset(data, 'x', size);
            for (size_t i = 99; i < size; i += 100) data[i] = '\n';
            /* around the first fill size and around a later carry point */
            size_t at[2] = { (size_t)((long)SCAN_BUF_SIZE - 128 + shift), (size_t)(2 * 65536L + shift) };
            for (int k = 0; k < 2; k++) {
                char *p = data + at[k];
                p[-1] = ' ';
                if (g) p += sprintf(p, "%.4s %.4s %.4s %.4s", c, c + 4, c + 8, c + 12);
                else p += sprintf(p, "%s", c);
                *p = ' ';
            }
            size_t chunk = chunks[(shift + 40) % 4];
            if (chunk == 7 && shift % 8) chunk = 4096;   /* tiny reads are slow; a few are enough */
            size_t n = scan_n(data, size, chunk);
            CHECK(n == 2);
            if (n == 2) {
                CHECK(res.hits[0].offset == at[0] && res.hits[1].offset == at[1]);
                CHECK(res.hits[0].marks == 0 && res.hits[1].marks == 0);
            } else {
                printf("  shift %ld grouped %d: %zu hits\n", shift, g, n);
            }
        }
    }
    free(data);
}

static void test_tracks(void)
{
    char c[24], text[200];
    make_card("4539", 16, c);
    snprintf(text, sizeof text, "%%B%s^DOE/JOHN^2512101000000000?", c);
    CHECK(scan(text) == 1 && res.hits[0].track == 1 && res.hits[0].marks == 0);
    snprintf(text, sizeof text, ";%s=25121010000000000000?", c);
    CHECK(scan(text) == 1 && res.hits[0].track == 2 && res.hits[0].marks == 0);
    snprintf(text, sizeof text, "B%s^", c);          /* no start sentinel: the letter is a boundary */
    CHECK(scan(text) == 0);
}

static void test_rules(void)
{
    char c[24], text[400];

    CHECK(scan("pay with 4111111111111111 please") == 1);
    CHECK(marked(0, R_TEST_CARD) && marked(0, R_REPEAT));
    CHECK(scan("5555 5555 5555 4444") == 1 && marked(0, R_TEST_CARD));

    make_card("4539", 16, c);
    snprintf(text, sizeof text, "{\"order_id\": \"%s\"}", c);
    CHECK(scan(text) == 1 && marked(0, R_ID_KEYWORD) && !strcmp(res.hits[0].keyword, "order_id"));
    snprintf(text, sizeof text, "IMEI=%s", c);                               /* any letter case */
    CHECK(scan(text) == 1 && marked(0, R_ID_KEYWORD));
    snprintf(text, sizeof text, "imei here\nnumber %s", c);                  /* keyword on another line */
    CHECK(scan(text) == 1 && !marked(0, R_ID_KEYWORD));
    snprintf(text, sizeof text, "serial and then a very long stretch of other text %s", c);  /* outside the window */
    CHECK(scan(text) == 1 && !marked(0, R_ID_KEYWORD));
    snprintf(text, sizeof text, "{\"pan\": \"%s\"}", c);
    CHECK(scan(text) == 1 && res.hits[0].marks == 0);

    snprintf(text, sizeof text, "version 1.%s.7", c);
    CHECK(scan(text) == 1 && marked(0, R_INSIDE_TOKEN));
    snprintf(text, sizeof text, "/ids/77/%s", c);
    CHECK(scan(text) == 1 && marked(0, R_INSIDE_TOKEN));
    snprintf(text, sizeof text, "mkdir ansible-tmp-1793453611.0638397-30163-%s && echo", c);  /* seen on a real server */
    CHECK(scan(text) == 1 && marked(0, R_INSIDE_TOKEN));
    snprintf(text, sizeof text, "%s-20261112 rotated", c);
    CHECK(scan(text) == 1 && marked(0, R_INSIDE_TOKEN));
    snprintf(text, sizeof text, "pan-%s;", c);                               /* a word before the dash is a label */
    CHECK(scan(text) == 1 && res.hits[0].marks == 0);
    snprintf(text, sizeof text, "id 77 %.4s-%.4s-%.4s-%.4s end", c, c + 4, c + 8, c + 12);   /* the card's own dashes */
    CHECK(scan(text) == 1 && res.hits[0].marks == 0);
    snprintf(text, sizeof text, "card=%s;", c);                              /* key=value is not a token */
    CHECK(scan(text) == 1 && !marked(0, R_INSIDE_TOKEN));
    snprintf(text, sizeof text, "Number: %s.", c);                           /* end of a sentence */
    CHECK(scan(text) == 1 && res.hits[0].marks == 0);

    int n = snprintf(text, sizeof text, "ab%c%c%s%c%ccd", 1, 2, c, 3, 4);
    CHECK(scan_n(text, (size_t)n, 0) == 1 && marked(0, R_BINARY));
    char db[200] = "SQLite format 3";                                        /* binary database: real data */
    n = 16 + snprintf(db + 16, sizeof db - 16, "%c%c%s%c%c", 1, 2, c, 3, 4);
    CHECK(scan_n(db, (size_t)n, 0) == 1 && !marked(0, R_BINARY));

    /* A switched-off rule leaves the hit open. */
    R.on[R_TEST_CARD] = R.on[R_REPEAT] = 0;
    CHECK(scan("4111111111111111") == 1 && res.hits[0].marks == 0);
    R.on[R_TEST_CARD] = R.on[R_REPEAT] = 1;
}

static void test_file_rules(void)
{
    char c[24];
    struct strbuf b = { 0 };

    /* A table of random numbers: about one in ten passes Luhn. */
    srand(7);
    for (int i = 0; i < 400; i++) {
        sb_add(&b, "4");
        for (int k = 0; k < 15; k++) sb_printf(&b, "%d", rand() % 10);
        sb_add(&b, "\n");
    }
    size_t n = scan_n(b.s, b.len, 0);
    CHECK(res.cand_total == 400 && n > 10 && n < 90);
    rules_finalize(&R, "/data/table.csv", NULL, NULL, &res);
    for (size_t i = 0; i < n; i++) CHECK(marked(i, R_LOW_LUHN));
    char reason[200];
    mark_reason(R_LOW_LUHN, &res.hits[0], &res, NULL, reason, sizeof reason);
    CHECK(strstr(reason, "of 400") != NULL);

    /* A real card list: every candidate passes, nothing is marked. */
    sb_reset(&b);
    for (int i = 0; i < 50; i++) { make_card("5412", 16, c); sb_printf(&b, "%s\n", c); }
    n = scan_n(b.s, b.len, 0);
    CHECK(n == 50);
    rules_finalize(&R, "/data/cards.csv", NULL, NULL, &res);
    for (size_t i = 0; i < n; i++) CHECK(res.hits[i].marks == 0);

    /* test-path only marks together with another rule. */
    make_card("4539", 16, c);
    sb_reset(&b);
    sb_printf(&b, "%s\n4111111111111111\n", c);
    CHECK(scan_n(b.s, b.len, 0) == 2);
    rules_finalize(&R, "/srv/app/tests/data.txt", NULL, NULL, &res);
    CHECK(res.hits[0].marks == 0);
    CHECK(marked(1, R_TEST_PATH) && marked(1, R_TEST_CARD));
    mark_reason(R_TEST_PATH, &res.hits[1], &res, NULL, reason, sizeof reason);
    CHECK(!strcmp(reason, "Test or library file, and known test card number"));

    CHECK(scan_n(b.s, b.len, 0) == 2);
    rules_finalize(&R, "/usr/share/doc/x", NULL, "libfoo", &res);
    CHECK(marked(0, R_PACKAGE_FILE) && marked(1, R_PACKAGE_FILE));
    sb_free(&b);
}

static void test_json(void)
{
    struct strbuf b = { 0 };
    sb_json_str(&b, "a\"b\\c\n\x01 \xc3\xa9 \xff end");
    CHECK(!strcmp(b.s, "\"a\\\"b\\\\c\\u000a\\u0001 \xc3\xa9 \\ufffd end\""));
    sb_free(&b);
}

int main(void)
{
    srand(42);
    workbuf = malloc(SCAN_BUF_SIZE);
    rules_defaults(&R);
    test_number_checks();
    test_formats();
    test_brand_layouts();
    test_utf16();
    test_pdf_text();
    test_boundaries();
    test_block_boundaries();
    test_tracks();
    test_rules();
    test_file_rules();
    test_json();
    free(workbuf);
    free(res.hits);
    printf("unit tests: %d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}
