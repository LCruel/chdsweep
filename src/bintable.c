/* chdsweep: BIN table. Issuer lookup at report time, offline only.
 *
 * Table format (also data/bin-table.csv.gz, the built-in base set): gzip or plain text.
 *   # chdsweep BIN table; source=...; upstream_commit=...; pulled=YYYY-MM-DD; entries=N
 *   prefix,brand,type,category,issuer,country
 * An overrides file has the same lines and is applied on top.
 */
#include "chdsweep.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>

extern const unsigned char bin_table_gz[], bin_table_gz_end[];

/* ---- reading ---- */

static char *inflate_blob(const unsigned char *src, size_t srclen, size_t *outlen)
{
    z_stream z;
    memset(&z, 0, sizeof z);
    if (inflateInit2(&z, 16 + MAX_WBITS) != Z_OK) return NULL;
    size_t cap = srclen * 10 + 4096;
    char *out = xmalloc(cap + 1);
    z.next_in = (unsigned char *)(uintptr_t)src;
    z.avail_in = (uInt)srclen;
    int r;
    do {
        if (z.total_out == cap) { cap *= 2; out = xrealloc(out, cap + 1); }
        z.next_out = (unsigned char *)out + z.total_out;
        z.avail_out = (uInt)(cap - z.total_out);
        r = inflate(&z, Z_NO_FLUSH);
    } while (r == Z_OK);
    inflateEnd(&z);
    if (r != Z_STREAM_END) { free(out); return NULL; }
    *outlen = z.total_out;
    out[*outlen] = 0;
    return out;
}

/* Whole file into memory; gzread also reads a plain file as it is. */
static char *read_file(const char *path, size_t *outlen)
{
    gzFile g = gzopen(path, "rb");
    if (!g) return NULL;
    size_t cap = 1 << 20, len = 0;
    char *out = xmalloc(cap + 1);
    int r;
    while ((r = gzread(g, out + len, (unsigned)(cap - len))) > 0) {
        len += (size_t)r;
        if (len == cap) { cap *= 2; out = xrealloc(out, cap + 1); }
    }
    gzclose(g);
    if (r < 0) { free(out); return NULL; }
    out[len] = 0;
    *outlen = len;
    return out;
}

static void header_field(const char *line, const char *name, char *out, size_t outlen)
{
    const char *p = strstr(line, name);
    if (!p) return;
    p += strlen(name);
    size_t n = strcspn(p, ";\r\n");
    if (n >= outlen) n = outlen - 1;
    memcpy(out, p, n);
    out[n] = 0;
}

static int cmp_entry(const void *a, const void *b)
{
    return strcmp(((const struct bin_entry *)a)->prefix, ((const struct bin_entry *)b)->prefix);
}

/* Parses the lines in buf in place; the entries point into buf, which is kept. */
static struct bin_entry *parse_table(char *buf, size_t *n_out, struct bin_table *meta)
{
    size_t cap = 1024, n = 0;
    struct bin_entry *e = xmalloc(cap * sizeof *e);
    for (char *line = buf; line && *line;) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t ll = strlen(line);
        if (ll && line[ll - 1] == '\r') line[ll - 1] = 0;
        if (line[0] == '#') {
            if (meta && !meta->pulled[0]) {
                header_field(line, "source=", meta->source, sizeof meta->source);
                header_field(line, "upstream_commit=", meta->commit, sizeof meta->commit);
                header_field(line, "pulled=", meta->pulled, sizeof meta->pulled);
            }
        } else if (line[0]) {
            char *f[6] = { "", "", "", "", "", "" };
            int nf = csv_split(line, f, 6);
            size_t pl = strlen(f[0]);
            if (nf >= 2 && pl >= 6 && pl <= 8 && strspn(f[0], "0123456789") == pl) {
                if (n == cap) { cap *= 2; e = xrealloc(e, cap * sizeof *e); }
                memcpy(e[n].prefix, f[0], pl + 1);
                e[n].brand = f[1]; e[n].type = f[2]; e[n].category = f[3];
                e[n].issuer = f[4]; e[n].country = f[5];
                n++;
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    qsort(e, n, sizeof *e, cmp_entry);
    *n_out = n;
    return e;
}

/* The newest table file in dir ("bin-table-YYYY-MM-DD.csv.gz"), or "" when there is none. */
static void newest_file(const char *dir, char *out, size_t outlen)
{
    out[0] = 0;
    DIR *d = dir ? opendir(dir) : NULL;
    if (!d) return;
    char best[256] = "";
    struct dirent *de;
    while ((de = readdir(d)))
        if (!strncmp(de->d_name, "bin-table-", 10) && strstr(de->d_name, ".csv") &&
            strlen(de->d_name) < sizeof best && strcmp(de->d_name, best) > 0)
            snprintf(best, sizeof best, "%s", de->d_name);
    closedir(d);
    if (best[0]) snprintf(out, outlen, "%s/%s", dir, best);
}

int bin_load(struct bin_table *t, const char *file, const char *dir, const char *overrides,
             char *err, size_t errlen)
{
    memset(t, 0, sizeof *t);
    size_t len = 0;
    char *buf = NULL;
    char newest[4200];

    if (!file) {
        /* A file from bin-update replaces the built-in set when it is newer. */
        struct bin_table probe;
        newest_file(dir, newest, sizeof newest);
        if (newest[0] && (buf = read_file(newest, &len))) {
            memset(&probe, 0, sizeof probe);
            if (buf[0] == '#') header_field(buf, "pulled=", probe.pulled, sizeof probe.pulled);
            char *base = inflate_blob(bin_table_gz, (size_t)(bin_table_gz_end - bin_table_gz), &len);
            char base_pulled[16] = "";
            if (base) header_field(base, "pulled=", base_pulled, sizeof base_pulled);
            free(base);
            if (strcmp(probe.pulled, base_pulled) > 0) file = newest;
            else { free(buf); buf = NULL; }
        }
    } else if (!(buf = read_file(file, &len))) {
        snprintf(err, errlen, "BIN table %s: cannot read", file);
        return -1;
    }
    if (buf) snprintf(t->origin, sizeof t->origin, "%s", file);
    else {
        buf = inflate_blob(bin_table_gz, (size_t)(bin_table_gz_end - bin_table_gz), &len);
        if (!buf) { snprintf(err, errlen, "built-in BIN table: cannot unpack"); return -1; }
        snprintf(t->origin, sizeof t->origin, "built-in");
    }
    t->e = parse_table(buf, &t->n, t);
    if (!t->n) { snprintf(err, errlen, "BIN table %s: no entries", t->origin); return -1; }

    if (overrides) {
        char *ob = read_file(overrides, &len);
        if (!ob) { snprintf(err, errlen, "BIN overrides %s: cannot read", overrides); return -1; }
        t->ov = parse_table(ob, &t->nov, NULL);
        snprintf(t->overrides, sizeof t->overrides, "%s", overrides);
    }
    return 0;
}

const struct bin_entry *bin_lookup(const struct bin_table *t, const char *masked)
{
    struct bin_entry key;
    size_t lead = strspn(masked, "0123456789");
    if (lead > 8) lead = 8;
    /* Longest prefix wins; an override beats the table at the same length. */
    for (size_t l = lead; l >= 6; l--) {
        memcpy(key.prefix, masked, l);
        key.prefix[l] = 0;
        const struct bin_entry *e = t->nov ? bsearch(&key, t->ov, t->nov, sizeof key, cmp_entry) : NULL;
        if (!e) e = bsearch(&key, t->e, t->n, sizeof key, cmp_entry);
        if (e) return e;
    }
    return NULL;
}

/* ---- bin-update: a downloaded upstream CSV becomes a dated table file ---- */

struct row { char *line; char prefix[9]; size_t order; };

static int cmp_row(const void *a, const void *b)
{
    const struct row *x = a, *y = b;
    int c = strcmp(x->prefix, y->prefix);
    return c ? c : (x->order > y->order) - (x->order < y->order);
}

static void csv_field(struct strbuf *b, const char *s)
{
    /* whitespace runs become one space, as in the base set */
    struct strbuf v = { 0 };
    sb_addn(&v, "", 0);
    for (const char *p = s; *p; p++) {
        if (isspace((unsigned char)*p)) { if (v.len && v.s[v.len - 1] != ' ') sb_addn(&v, " ", 1); }
        else sb_addn(&v, p, 1);
    }
    while (v.len && v.s[v.len - 1] == ' ') v.s[--v.len] = 0;
    if (strpbrk(v.s, ",\"")) {
        sb_addn(b, "\"", 1);
        for (const char *p = v.s; *p; p++) { if (*p == '"') sb_addn(b, "\"", 1); sb_addn(b, p, 1); }
        sb_addn(b, "\"", 1);
    } else sb_add(b, v.s);
    sb_free(&v);
}

int cmd_bin_update(int argc, char **argv)
{
    const char *dir = "/var/lib/chdsweep/bin", *commit = "unknown", *src = NULL;
    char date[16];
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(date, sizeof date, "%Y-%m-%d", &tm);
    for (int i = 2; i < argc; i++) {
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(argv[i], "--dir") && v) { dir = v; i++; }
        else if (!strcmp(argv[i], "--commit") && v) { commit = v; i++; }
        else if (!strcmp(argv[i], "--date") && v && strlen(v) == 10) { snprintf(date, sizeof date, "%s", v); i++; }
        else if (argv[i][0] != '-' && !src) src = argv[i];
        else { fprintf(stderr, "chdsweep: bin-update: bad option %s\n", argv[i]); return EXIT_FAILED; }
    }
    if (!src) {
        fputs("usage: chdsweep bin-update [--dir DIR] [--commit HASH] [--date YYYY-MM-DD] bin-list-data.csv\n"
              "  Turns a downloaded copy of the upstream data set into a dated table file in DIR\n"
              "  (default /var/lib/chdsweep/bin). chdsweep itself never downloads anything.\n", stderr);
        return EXIT_FAILED;
    }
    /* static: still reachable on the early exits below */
    static char *buf;
    static struct row *rows;
    static struct strbuf b;
    size_t len = 0;
    buf = read_file(src, &len);
    if (!buf) { fprintf(stderr, "chdsweep: bin-update: cannot read %s\n", src); return EXIT_FAILED; }

    /* Columns by name from the header line. */
    static const char *const want[6] = { "BIN", "Brand", "Type", "Category", "Issuer", "isoCode2" };
    int col[6] = { -1, -1, -1, -1, -1, -1 };
    size_t cap = 1 << 16, n = 0;
    rows = xmalloc(cap * sizeof *rows);
    int first = 1;
    for (char *line = buf; line && *line;) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *f[16];
        int nf = csv_split(line, f, 16);
        if (first) {
            for (int i = 0; i < nf; i++) {
                size_t fl = strlen(f[i]);
                if (fl && f[i][fl - 1] == '\r') f[i][fl - 1] = 0;
                for (int k = 0; k < 6; k++) if (!strcmp(f[i], want[k])) col[k] = i;
            }
            for (int k = 0; k < 6; k++)
                if (col[k] < 0) {
                    fprintf(stderr, "chdsweep: bin-update: %s has no column %s\n", src, want[k]);
                    return EXIT_FAILED;
                }
            first = 0;
        } else {
            const char *p = col[0] < nf ? f[col[0]] : "";
            size_t pl = strlen(p);
            if (pl >= 6 && pl <= 8 && strspn(p, "0123456789") == pl) {
                sb_reset(&b);
                for (int k = 0; k < 6; k++) {
                    if (k) sb_addn(&b, ",", 1);
                    csv_field(&b, col[k] < nf ? f[col[k]] : "");
                }
                if (n == cap) { cap *= 2; rows = xrealloc(rows, cap * sizeof *rows); }
                rows[n].line = xstrdup(b.s);
                memcpy(rows[n].prefix, p, pl + 1);
                rows[n].order = n;
                n++;
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    if (!n) { fprintf(stderr, "chdsweep: bin-update: no entries in %s\n", src); return EXIT_FAILED; }
    qsort(rows, n, sizeof *rows, cmp_row);
    size_t kept = 0;
    for (size_t i = 0; i < n; i++)
        if (i == 0 || strcmp(rows[i].prefix, rows[i - 1].prefix)) kept++;

    char out[4200];
    mkdir(dir, 0755);
    snprintf(out, sizeof out, "%s/bin-table-%s.csv.gz", dir, date);
    gzFile g = gzopen(out, "wb9");
    if (!g) { fprintf(stderr, "chdsweep: bin-update: cannot write %s: %s\n", out, strerror(errno)); return EXIT_FAILED; }
    gzprintf(g, "# chdsweep BIN table; source=venelinkochev/bin-list-data; licence=CC BY 4.0; "
                "changed=trimmed to six fields; upstream_commit=%s; pulled=%s; entries=%zu\n",
             commit, date, kept);
    for (size_t i = 0; i < n; i++)
        if (i == 0 || strcmp(rows[i].prefix, rows[i - 1].prefix)) {
            gzputs(g, rows[i].line);
            gzputs(g, "\n");
        }
    if (gzclose(g) != Z_OK) { fprintf(stderr, "chdsweep: bin-update: write to %s failed\n", out); return EXIT_FAILED; }
    printf("%zu entries written to %s\nEarlier table files in %s are kept; the report uses the newest.\n", kept, out, dir);
    for (size_t i = 0; i < n; i++) free(rows[i].line);
    free(rows);
    free(buf);
    sb_free(&b);
    return 0;
}
