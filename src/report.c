/* chdsweep report: merges run files from several hosts and dates into one report
 * (Markdown, HTML, and a CSV with every hit).
 *
 * The newest run of each host is its current state: all counts come from it.
 * Older runs of the same host are used for the trend and for the differences.
 * The triage file is applied here only; the run files stay as they are.
 */
#include "chdsweep.h"

#include <errno.h>
#include <fnmatch.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SEP "\x1f"
enum { ST_OPEN, ST_LIKELY, ST_ACCEPTED };
static const char *const status_names[] = { "suspected PAN", "likely false positive", "accepted false positive" };

struct rhit {
    int run, brand, digits, track, status, triage;
    long long offset;
    char *path, *member, *masked, *mtime;
    char *marks, *reasons;            /* rule ids and reasons, each joined with SEP */
    const struct bin_entry *bin;
};
struct skip { int run; char *path, *member, *reason; };
struct run {
    char *file, *host, *start, *end, *version, *keep, *coverage, *messages, *rules, *not_entered;
    int complete, latest, prev;
    struct strlist paths, excludes;   /* the paths the run was given, and what it left out */
    long long max_file_size, max_unpacked, max_depth, max_ratio, max_members, max_file_seconds,
              max_hits_per_file;
    long long files, bytes, archives, skipped;
    long open, likely, accepted;
};
struct triage { char *host, *path, *masked, *reason, *who, *date, *ticket; long matched; };

struct grp { char *key; long hits, files, hosts; unsigned brands; int flag; char *note; };
struct grouping { struct smap ids, seen; struct grp *g; int n, cap; };

static struct {
    struct run *runs; int nruns;
    struct rhit *hits; size_t nhits, caphits;
    struct skip *skips; size_t nskips, capskips;
    struct triage *tri; int ntri;
    struct strlist brands;
    struct bin_table bin;
    /* options */
    const char *prefix, *triage_file, *bin_file, *bin_dir, *bin_overrides;
    int show_marked, depth, top, triage_age, bin_age;
    time_t now;
} R;

/* ---- small helpers ---- */

static const char *N(long long v)
{
    static char ring[16][32];
    static int at;
    char *s = ring[at++ % 16];
    snprintf(s, 32, "%lld", v);
    return s;
}


static int parse_date(const char *s, int *y, int *m, int *d)
{
    return s && sscanf(s, "%4d-%2d-%2d", y, m, d) == 3 && *m >= 1 && *m <= 12 && *d >= 1 && *d <= 31;
}

static long days_since(const char *date, time_t now)
{
    int y, m, d;
    if (!parse_date(date, &y, &m, &d)) return -1;
    struct tm tm = { .tm_year = y - 1900, .tm_mon = m - 1, .tm_mday = d };
    return (long)((now - timegm(&tm)) / 86400);
}

/* Masked numbers from runs with different keep_leading compare on six and four. */
static void norm_masked(const char *masked, char out[32])
{
    size_t n = strlen(masked);
    if (n < 10 || n > 19) { snprintf(out, 32, "%.31s", masked); return; }
    snprintf(out, 32, "%.6s|%s|%zu", masked, masked + n - 4, n);
}

static int brand_id(const char *name)
{
    for (int i = 0; i < R.brands.n; i++)
        if (!strcmp(R.brands.v[i], name)) return i;
    if (R.brands.n >= 31) return 30;
    sl_add(&R.brands, name);
    return R.brands.n - 1;
}

static const char *brand_list(unsigned mask)
{
    static struct strbuf b;
    sb_reset(&b);
    sb_addn(&b, "", 0);
    for (int i = 0; i < R.brands.n; i++)
        if (mask & (1u << i)) { if (b.len) sb_add(&b, ", "); sb_add(&b, R.brands.v[i]); }
    return b.s;
}

/* ---- reading run files ---- */

static char *dup_or_null(const char *s) { return s ? xstrdup(s) : NULL; }

static int load_run(const char *file)
{
    FILE *f = fopen(file, "r");
    if (!f) { fprintf(stderr, "chdsweep: report: %s: %s\n", file, strerror(errno)); return -1; }
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0, run = -1;
    struct strbuf marks = { 0 }, reasons = { 0 };
    while (getline(&line, &cap, f) > 0) {
        lineno++;
        if (line[0] == '\n' || !line[0]) continue;
        struct jv *v = json_parse(line);
        const char *type = json_str(v, "type", NULL);
        if (!v || !type || (run < 0 && strcmp(type, "header"))) {
            fprintf(stderr, "chdsweep: report: %s:%d: not a chdsweep run file\n", file, lineno);
            json_free(v);
            free(line);
            fclose(f);
            return -1;
        }
        if (!strcmp(type, "header")) {
            R.runs = xrealloc(R.runs, (size_t)(R.nruns + 1) * sizeof *R.runs);
            run = R.nruns++;
            struct run *r = &R.runs[run];
            memset(r, 0, sizeof *r);
            r->file = xstrdup(file);
            r->host = xstrdup(json_str(v, "host", "unknown"));
            r->start = xstrdup(json_str(v, "start", ""));
            r->version = xstrdup(json_str(v, "version", "?"));
            r->keep = xstrdup(json_str(v, "keep_leading", "?"));
            r->messages = dup_or_null(json_str(v, "messages", NULL));
            r->rules = xstrdup(json_str(json_get(v, "rules"), "checksum", "?"));
            const struct jv *ps = json_get(v, "paths");
            for (const struct jv *e = ps ? ps->child : NULL; e; e = e->next)
                if (e->type == J_STR) sl_add(&r->paths, e->s);
            const struct jv *lim = json_get(v, "limits");
            r->max_file_size = json_num(lim, "max_file_size", 0);
            r->max_unpacked = json_num(lim, "max_unpacked", 0);
            r->max_depth = json_num(lim, "max_depth", 0);
            r->max_ratio = json_num(lim, "max_ratio", 0);
            r->max_members = json_num(lim, "max_members", 0);
            r->max_file_seconds = json_num(lim, "max_file_seconds", 0);
            r->max_hits_per_file = json_num(lim, "max_hits_per_file", 0);
            int jd = (int)json_num(v, "journal_days", 0);
            if (jd > 0) {
                char jn[64];
                snprintf(jn, sizeof jn, "journal (last %d days)", jd);
                sl_add(&r->paths, jn);
            }
            ps = json_get(v, "excludes");
            for (const struct jv *e = ps ? ps->child : NULL; e; e = e->next)
                if (e->type == J_STR) sl_add(&r->excludes, e->s);
            r->coverage = xstrdup("incomplete");
            r->end = xstrdup("");
            r->prev = -1;
        } else if (!strcmp(type, "hit")) {
            if (R.nhits == R.caphits) {
                R.caphits = R.caphits ? R.caphits * 2 : 1024;
                R.hits = xrealloc(R.hits, R.caphits * sizeof *R.hits);
            }
            struct rhit *h = &R.hits[R.nhits++];
            memset(h, 0, sizeof *h);
            h->run = run;
            h->triage = -1;
            h->path = xstrdup(json_str(v, "path", ""));
            h->member = dup_or_null(json_str(v, "member", NULL));
            h->masked = xstrdup(json_str(v, "masked", ""));
            h->mtime = xstrdup(json_str(v, "mtime", ""));
            h->brand = brand_id(json_str(v, "brand", "unknown"));
            h->digits = (int)json_num(v, "digits", 0);
            h->track = (int)json_num(v, "track", 0);
            h->offset = json_num(v, "offset", 0);
            sb_reset(&marks);
            sb_reset(&reasons);
            sb_addn(&marks, "", 0);
            sb_addn(&reasons, "", 0);
            const struct jv *ms = json_get(v, "marks");
            for (const struct jv *m = ms ? ms->child : NULL; m; m = m->next) {
                if (marks.len) { sb_add(&marks, SEP); sb_add(&reasons, SEP); }
                sb_add(&marks, json_str(m, "rule", "?"));
                sb_add(&reasons, json_str(m, "reason", ""));
            }
            h->marks = xstrdup(marks.s);
            h->reasons = xstrdup(reasons.s);
        } else if (!strcmp(type, "skip")) {
            if (R.nskips == R.capskips) {
                R.capskips = R.capskips ? R.capskips * 2 : 256;
                R.skips = xrealloc(R.skips, R.capskips * sizeof *R.skips);
            }
            struct skip *s = &R.skips[R.nskips++];
            s->run = run;
            s->path = xstrdup(json_str(v, "path", ""));
            s->member = dup_or_null(json_str(v, "member", NULL));
            s->reason = xstrdup(json_str(v, "reason", ""));
        } else if (!strcmp(type, "end")) {
            struct run *r = &R.runs[run];
            const struct jv *c = json_get(v, "counters");
            free(r->end);
            free(r->coverage);
            r->end = xstrdup(json_str(v, "end", ""));
            r->coverage = xstrdup(json_str(v, "coverage", "?"));
            r->complete = (int)json_num(v, "complete", 0);
            r->files = json_num(c, "files", 0);
            r->bytes = json_num(c, "bytes", 0);
            r->archives = json_num(c, "archives", 0);
            r->skipped = json_num(c, "skipped", 0);
            const struct jv *ne = json_get(v, "not_entered");
            struct strbuf nb = { 0 };
            for (const struct jv *e = ne ? ne->child : NULL; e; e = e->next)
                if (e->type == J_STR) { if (nb.len) sb_add(&nb, ", "); sb_add(&nb, e->s); }
            r->not_entered = nb.s;   /* NULL when there are none */
        }
        json_free(v);
    }
    free(line);
    fclose(f);
    sb_free(&marks);
    sb_free(&reasons);
    if (run < 0) { fprintf(stderr, "chdsweep: report: %s: empty file\n", file); return -1; }
    return 0;
}

/* Triage file: CSV lines "host,path,masked,reason,who,date,ticket". host and masked may
 * be "*"; path may be a glob. Lines starting with '#' are comments. */
static int load_triage(const char *file)
{
    FILE *f = fopen(file, "r");
    if (!f) { fprintf(stderr, "chdsweep: report: triage file %s: %s\n", file, strerror(errno)); return -1; }
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0;
    while (getline(&line, &cap, f) > 0) {
        lineno++;
        line[strcspn(line, "\r\n")] = 0;
        if (!line[0] || line[0] == '#' || !strncmp(line, "host,", 5)) continue;
        char *fl[7] = { "", "", "", "", "", "", "" };
        int y, m, d;
        if (csv_split(line, fl, 7) < 6 || !fl[3][0] || !parse_date(fl[5], &y, &m, &d)) {
            fprintf(stderr, "chdsweep: report: %s:%d: expected host,path,masked,reason,who,YYYY-MM-DD[,ticket]\n",
                    file, lineno);
            free(line);
            fclose(f);
            return -1;
        }
        R.tri = xrealloc(R.tri, (size_t)(R.ntri + 1) * sizeof *R.tri);
        struct triage *t = &R.tri[R.ntri++];
        t->host = xstrdup(fl[0]); t->path = xstrdup(fl[1]); t->masked = xstrdup(fl[2]);
        t->reason = xstrdup(fl[3]); t->who = xstrdup(fl[4]); t->date = xstrdup(fl[5]);
        t->ticket = xstrdup(fl[6]);
        t->matched = 0;
    }
    free(line);
    fclose(f);
    return 0;
}

static int triage_match(const struct triage *t, const struct rhit *h)
{
    char a[32], b[32];
    if (strcmp(t->host, "*") && strcmp(t->host, R.runs[h->run].host)) return 0;
    if (strcmp(t->path, h->path) && fnmatch(t->path, h->path, 0) != 0) return 0;
    if (!strcmp(t->masked, "*")) return 1;
    norm_masked(t->masked, a);
    norm_masked(h->masked, b);
    return !strcmp(a, b);
}

/* Newest run per host, its predecessor, and the status of every hit. */
static void classify(void)
{
    for (int i = 0; i < R.nruns; i++) {
        struct run *r = &R.runs[i];
        r->latest = 1;
        for (int k = 0; k < R.nruns; k++) {
            if (k == i || strcmp(R.runs[k].host, r->host)) continue;
            int c = strcmp(R.runs[k].start, r->start);
            if (c > 0 || (c == 0 && k > i)) r->latest = 0;
            else if (r->prev < 0 || strcmp(R.runs[k].start, R.runs[r->prev].start) > 0) r->prev = k;
        }
    }
    for (size_t i = 0; i < R.nhits; i++) {
        struct rhit *h = &R.hits[i];
        struct run *r = &R.runs[h->run];
        h->status = h->marks[0] ? ST_LIKELY : ST_OPEN;
        for (int t = 0; t < R.ntri; t++)
            if (triage_match(&R.tri[t], h)) {
                h->status = ST_ACCEPTED;
                h->triage = t;
                if (r->latest) R.tri[t].matched++;
                break;
            }
        if (h->status == ST_OPEN) r->open++;
        else if (h->status == ST_LIKELY) r->likely++;
        else r->accepted++;
        h->bin = bin_lookup(&R.bin, h->masked);
    }
}

/* ---- grouping ---- */

static struct grp *grp_hit(struct grouping *G, const char *key, const struct rhit *h)
{
    static struct strbuf k;
    int isnew;
    int id = smap_id(&G->ids, key, &isnew);
    if (isnew) {
        if (id >= G->cap) { G->cap = G->cap ? G->cap * 2 : 64; G->g = xrealloc(G->g, (size_t)G->cap * sizeof *G->g); }
        memset(&G->g[id], 0, sizeof G->g[id]);
        G->g[id].key = xstrdup(key);
        G->n = id + 1;
    }
    struct grp *g = &G->g[id];
    const char *host = R.runs[h->run].host;
    g->hits++;
    g->brands |= 1u << h->brand;
    if (h->member) g->flag = 1;
    sb_reset(&k);
    sb_printf(&k, "F%d" SEP "%s" SEP "%s", id, host, h->path);
    smap_id(&G->seen, k.s, &isnew);
    if (isnew) g->files++;
    sb_reset(&k);
    sb_printf(&k, "H%d" SEP "%s", id, host);
    smap_id(&G->seen, k.s, &isnew);
    if (isnew) g->hosts++;
    return g;
}

static int cmp_grp(const void *a, const void *b)
{
    const struct grp *x = a, *y = b;
    if (x->hits != y->hits) return x->hits > y->hits ? -1 : 1;
    return strcmp(x->key, y->key);
}

static void grp_sort(struct grouping *G) { qsort(G->g, (size_t)G->n, sizeof *G->g, cmp_grp); }

static void grp_free(struct grouping *G)
{
    for (int i = 0; i < G->n; i++) { free(G->g[i].key); free(G->g[i].note); }
    free(G->g);
    smap_free(&G->ids);
    smap_free(&G->seen);
    memset(G, 0, sizeof *G);
}

/* Splits "a SEP b" in place; returns b. */
static char *split_key(char *key)
{
    char *p = strchr(key, SEP[0]);
    if (!p) return key + strlen(key);
    *p = 0;
    return p + 1;
}

/* Folder of a path, rolled up to R.depth components: /var/www/shop/a/b.txt -> /var/www/shop */
static const char *location(const char *path)
{
    static struct strbuf b;
    sb_reset(&b);
    if (path[0] != '/') return path;         /* not a file: the journal */
    const char *last = strrchr(path, '/');
    size_t dirlen = last ? (size_t)(last - path) : 0;
    int comps = 0;
    size_t cut = dirlen;
    for (size_t i = 1; i < dirlen; i++)
        if (path[i] == '/' && ++comps == R.depth) { cut = i; break; }
    sb_addn(&b, path, cut);
    if (!b.len) sb_add(&b, "/");
    return b.s;
}

static int ends_with(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && !strcasecmp(s + a - b, suffix);
}

static const char *file_type(const struct rhit *h)
{
    static char ext[40];
    const char *p = h->path;
    if (h->member)
        return ends_with(p, ".docx") || ends_with(p, ".xlsx") || ends_with(p, ".pptx") ? "office document"
                                                                                         : "archive member";
    const char *base = strrchr(p, '/');
    base = base ? base + 1 : p;
    if (strcasestr(base, ".log")) return "log";
    const char *dot = strrchr(base, '.');
    if (!dot || dot == base || !dot[1]) return "(no extension)";
    if (!strcasecmp(dot, ".csv")) return "csv";
    if (!strcasecmp(dot, ".txt")) return "text";
    if (!strcasecmp(dot, ".sqlite") || !strcasecmp(dot, ".sqlite3") || !strcasecmp(dot, ".db")) return "database";
    snprintf(ext, sizeof ext, "%.39s", dot);
    for (char *q = ext; *q; q++) if (*q >= 'A' && *q <= 'Z') *q = (char)(*q + 32);
    return ext;
}

static const char *issuer_name(const struct rhit *h)
{
    return h->bin && h->bin->issuer[0] ? h->bin->issuer : "unknown issuer";
}

static const char *joined(const char *s, const char *with)
{
    static struct strbuf b;
    sb_reset(&b);
    sb_addn(&b, "", 0);
    for (; *s; s++) {
        if (*s == SEP[0]) sb_add(&b, with);
        else sb_addn(&b, s, 1);
    }
    return b.s;
}

/* ---- the report ---- */

/* First thing a reader wants: where. */
static void section_locations(struct doc *d)
{
    struct grouping loc = { 0 };
    static struct strbuf k;
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        const struct run *r = &R.runs[h->run];
        if (!r->latest || h->status != ST_OPEN) continue;
        sb_reset(&k); sb_printf(&k, "%s" SEP "%s", r->host, location(h->path));
        grp_hit(&loc, k.s, h);
    }
    grp_sort(&loc);
    doc_h(d, 2, "Where the cards are");
    doc_h(d, 3, "Per location (folders rolled up to %d levels)", R.depth);
    int t = doc_table(d, 5, "Host", "Location", "Suspected PANs", "Files", "Brands");
    for (int i = 0; i < loc.n; i++) {
        struct grp *g = &loc.g[i];
        char *folder = split_key(g->key);
        doc_row(d, t, g->key, folder, N(g->hits), N(g->files), brand_list(g->brands));
    }
    grp_free(&loc);
}

static int cmp_grp_key(const void *a, const void *b)
{
    return strcmp(((const struct grp *)a)->key, ((const struct grp *)b)->key);
}

/* Then: every file with an open hit and the numbers in it, each distinct number once. */
static void section_files(struct doc *d)
{
    struct grouping f = { 0 };
    static struct strbuf k;
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        const struct run *r = &R.runs[h->run];
        if (!r->latest || h->status != ST_OPEN) continue;
        sb_reset(&k);
        sb_printf(&k, "%s" SEP "%s" SEP "%s" SEP "%s", r->host, h->path, h->member ? h->member : "", h->masked);
        struct grp *g = grp_hit(&f, k.s, h);
        if (!g->note) {
            struct strbuf b = { 0 };
            sb_printf(&b, "%s" SEP "%s", R.brands.v[h->brand], issuer_name(h));
            g->note = b.s;
        }
    }
    qsort(f.g, (size_t)f.n, sizeof *f.g, cmp_grp_key);
    doc_h(d, 3, "Suspected PANs per file");
    doc_p(d, "Every file with a suspected PAN, and each distinct number in it once, masked. \"Times\" is how "
             "often that number occurs in the file. For a hit inside an archive (zip, tar, gz) the file "
             "inside it is named too.");
    int t = doc_table(d, 6, "Host", "File", "Number", "Brand", "Issuer", "Times");
    struct strbuf where = { 0 };
    for (int i = 0; i < f.n; i++) {
        struct grp *g = &f.g[i];
        char *path = split_key(g->key), *member = split_key(path), *masked = split_key(member);
        char *issuer = split_key(g->note);
        sb_reset(&where);
        sb_add(&where, path);
        /* "(content)" is a single compressed file, not a file inside an archive */
        if (member[0] && strcmp(member, "(content)")) sb_printf(&where, " (inside it: %s)", member);
        doc_row(d, t, g->key, where.s, masked, g->note, issuer, N(g->hits));
    }
    sb_free(&where);
    grp_free(&f);
}

static void section_breakdowns(struct doc *d)
{
    struct grouping type = { 0 }, hb = { 0 }, host = { 0 };
    static struct strbuf k;
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        const struct run *r = &R.runs[h->run];
        if (!r->latest || h->status != ST_OPEN) continue;
        grp_hit(&type, file_type(h), h);
        sb_reset(&k); sb_printf(&k, "%s" SEP "%s", r->host, R.brands.v[h->brand]);
        grp_hit(&hb, k.s, h);
        grp_hit(&host, r->host, h);
    }
    grp_sort(&type); grp_sort(&host);

    doc_h(d, 3, "Suspected PANs per file type");
    int t = doc_table(d, 3, "File type", "Suspected PANs", "Files");
    for (int i = 0; i < type.n; i++) doc_row(d, t, type.g[i].key, N(type.g[i].hits), N(type.g[i].files));

    doc_h(d, 3, "Host by brand");
    if (!host.n) doc_p(d, "None.");
    else {
        /* one column per brand: a table built row by row */
        t = doc_table(d, 0);
        d->b[t].ncols = R.brands.n + 1;
        sl_add(&d->b[t].cells, "Host");
        for (int b = 0; b < R.brands.n; b++) sl_add(&d->b[t].cells, R.brands.v[b]);
        for (int i = 0; i < host.n; i++) {
            sl_add(&d->b[t].cells, host.g[i].key);
            for (int b = 0; b < R.brands.n; b++) {
                sb_reset(&k); sb_printf(&k, "%s" SEP "%s", host.g[i].key, R.brands.v[b]);
                int id = smap_find(&hb.ids, k.s);
                sl_add(&d->b[t].cells, N(id >= 0 ? hb.g[id].hits : 0));
            }
        }
    }
    grp_free(&type); grp_free(&hb); grp_free(&host);
}

static void section_issuers(struct doc *d)
{
    struct grouping brand = { 0 }, issuer = { 0 }, ctype = { 0 }, hi = { 0 };
    static struct strbuf k;
    long open = 0, known = 0;
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        const struct run *r = &R.runs[h->run];
        if (!r->latest || h->status != ST_OPEN) continue;
        open++;
        if (h->bin) known++;
        grp_hit(&brand, R.brands.v[h->brand], h);
        sb_reset(&k); sb_printf(&k, "%s" SEP "%s", issuer_name(h), h->bin ? h->bin->country : "");
        grp_hit(&issuer, k.s, h);
        grp_hit(&ctype, h->bin && h->bin->type[0] ? h->bin->type : "unknown", h);
        sb_reset(&k); sb_printf(&k, "%s" SEP "%s", r->host, issuer_name(h));
        grp_hit(&hi, k.s, h);
    }
    grp_sort(&brand); grp_sort(&issuer); grp_sort(&ctype); grp_sort(&hi);

    doc_h(d, 2, "Brands and issuers");
    doc_h(d, 3, "Per brand");
    int t = doc_table(d, 2, "Brand", "Suspected PANs");
    for (int i = 0; i < brand.n; i++)
        doc_row(d, t, brand.g[i].key, N(brand.g[i].hits));

    doc_h(d, 3, "Per issuer");
    t = doc_table(d, 3, "Issuer", "Country", "Suspected PANs");
    for (int i = 0; i < issuer.n && i < R.top; i++) {
        char *country = split_key(issuer.g[i].key);
        doc_row(d, t, issuer.g[i].key, country, N(issuer.g[i].hits));
    }
    if (issuer.n > R.top) doc_p(d, "%d more issuers are in the CSV.", issuer.n - R.top);

    doc_h(d, 3, "Per card type");
    t = doc_table(d, 2, "Card type", "Suspected PANs");
    for (int i = 0; i < ctype.n; i++)
        doc_row(d, t, ctype.g[i].key, N(ctype.g[i].hits));

    doc_h(d, 3, "Host by issuer");
    t = doc_table(d, 3, "Host", "Issuer", "Suspected PANs");
    for (int i = 0; i < hi.n && i < R.top; i++) {
        char *name = split_key(hi.g[i].key);
        doc_row(d, t, hi.g[i].key, name, N(hi.g[i].hits));
    }

    doc_p(d, "Issuer data: " BIN_ATTRIBUTION " Table: %s, upstream commit %s, pulled %s%s%s. "
             "The brand comes from the scanner; issuer, country and card type come from this table, looked up "
             "offline with the leading digits the masked number keeps. %ld of %ld suspected PANs (%ld%%) have a "
             "prefix in the table; the others show as unknown issuer.",
          R.bin.origin, R.bin.commit[0] ? R.bin.commit : "unknown", R.bin.pulled[0] ? R.bin.pulled : "unknown",
          R.bin.overrides[0] ? ", local overrides from " : "", R.bin.overrides,
          known, open, open ? known * 100 / open : 0);
    long age = days_since(R.bin.pulled, R.now);
    if (age > R.bin_age)
        doc_p(d, "Warning: the BIN table is %ld days old (limit %d). Issuer names may be out of date; "
                 "renew it with chdsweep bin-update.", age, R.bin_age);
    grp_free(&brand); grp_free(&issuer); grp_free(&ctype); grp_free(&hi);
}

static void section_likely(struct doc *d)
{
    struct grouping rule = { 0 };
    long total = 0;
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        if (!R.runs[h->run].latest || h->status != ST_LIKELY) continue;
        total++;
        char *marks = xstrdup(h->marks), *reasons = xstrdup(h->reasons);
        char *m = marks, *rs = reasons;
        while (*m) {
            char *mn = split_key(m), *rn = split_key(rs);
            struct grp *g = grp_hit(&rule, m, h);
            if (!g->note) g->note = xstrdup(rs);
            m = mn;
            rs = rn;
        }
        free(marks);
        free(reasons);
    }
    grp_sort(&rule);
    doc_h(d, 2, "Likely false positives");
    doc_p(d, "%ld hits are marked by a false-positive rule. They are set aside, not removed: every one is in "
             "the CSV with its marks, so a rule can be checked as a whole or by sample. A hit with several "
             "marks counts under each rule.", total);
    if (R.show_marked == 0) { grp_free(&rule); return; }
    int t = doc_table(d, 4, "Rule", "Hits", "Files", "Criterion");
    for (int i = 0; i < rule.n; i++) {
        const char *what = rule.g[i].note;   /* a rule this version does not know: its first reason */
        for (int r = 0; r < R_COUNT; r++)
            if (!strcmp(rule.g[i].key, rule_names[r])) what = rule_criteria[r];
        doc_row(d, t, rule.g[i].key, N(rule.g[i].hits), N(rule.g[i].files), what);
    }
    grp_free(&rule);
    if (R.show_marked < 2) return;

    struct grouping loc = { 0 };
    static struct strbuf k;
    doc_h(d, 3, "Every marked hit");
    t = doc_table(d, 6, "Host", "Path", "File inside archive", "Number", "Brand", "Marks");
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        const struct run *r = &R.runs[h->run];
        if (!r->latest || h->status != ST_LIKELY) continue;
        doc_row(d, t, r->host, h->path, h->member, h->masked, R.brands.v[h->brand], joined(h->reasons, "; "));
        sb_reset(&k); sb_printf(&k, "%s" SEP "%s", r->host, location(h->path));
        grp_hit(&loc, k.s, h);
    }
    grp_sort(&loc);
    doc_h(d, 3, "Marked hits per location");
    t = doc_table(d, 5, "Host", "Location", "Marked hits", "Files", "Brands");
    for (int i = 0; i < loc.n; i++) {
        char *folder = split_key(loc.g[i].key);
        doc_row(d, t, loc.g[i].key, folder, N(loc.g[i].hits), N(loc.g[i].files), brand_list(loc.g[i].brands));
    }
    grp_free(&loc);
}

/* Adds the host to the group's list of host names, once. */
static void add_host(struct grp *g, const char *host)
{
    if (g->flag == g->hosts) return;         /* grp_hit saw this host before */
    struct strbuf b = { 0 };
    if (g->note) { sb_add(&b, g->note); sb_add(&b, ", "); free(g->note); }
    sb_add(&b, host);
    g->note = b.s;
    g->flag = (int)g->hosts;
}

static const char *size_text(long long n)
{
    static char b[2][32];
    static int k;
    char *o = b[k ^= 1];
    if (n >= 1LL << 30 && n % (1LL << 30) == 0) snprintf(o, 32, "%lld GiB", n >> 30);
    else if (n >= 1 << 20) snprintf(o, 32, "%lld MiB", n >> 20);
    else snprintf(o, 32, "%lld bytes", n);
    return o;
}

/* What the reason of a skipped file means, with the limit that run was using. */
static const char *skip_criterion(const struct skip *s)
{
    static char o[320];
    const struct run *r = &R.runs[s->run];
    const char *why = s->reason;
    if (strstr(why, "max_file_size"))
        snprintf(o, sizeof o, "Files larger than %s are not read (setting max_file_size).", size_text(r->max_file_size));
    else if (strstr(why, "max_depth"))
        snprintf(o, sizeof o, "An archive inside archives is opened up to %lld levels deep (setting max_depth); "
                              "what lies deeper is not read.", r->max_depth);
    else if (strstr(why, "max_unpacked"))
        snprintf(o, sizeof o, "Reading an archive stops once %s has been unpacked from it (setting max_unpacked); "
                              "what comes before that is scanned.", size_text(r->max_unpacked));
    else if (strstr(why, "max_ratio"))
        snprintf(o, sizeof o, "Reading an archive stops when it unpacks to more than %lld times its own size "
                              "(setting max_ratio), a guard against archives built to fill a disk.", r->max_ratio);
    else if (strstr(why, "max_members"))
        snprintf(o, sizeof o, "Reading an archive stops after %lld files inside it (setting max_members).", r->max_members);
    else if (strstr(why, "max_file_seconds"))
        snprintf(o, sizeof o, "Reading one file stops after %lld seconds (setting max_file_seconds).", r->max_file_seconds);
    else if (strstr(why, "max_hits_per_file"))
        snprintf(o, sizeof o, "At most %lld numbers are listed per file (setting max_hits_per_file). The file was "
                              "read to the end; the numbers beyond that are counted in the run file, not listed.",
                 r->max_hits_per_file);
    else if (strstr(why, "libarchive"))
        snprintf(o, sizeof o, "Archives are not opened because the library for them (libarchive) is missing on the host.");
    else if (strstr(why, "journalctl"))
        snprintf(o, sizeof o, "The system journal could not be read with journalctl.");
    else if (strstr(why, "path not found"))
        snprintf(o, sizeof o, "A path given to the scan does not exist on the host.");
    else if (strstr(why, "unreadable") || strstr(why, "read error"))
        snprintf(o, sizeof o, "The file, folder or archive could not be opened or read; the system's error is in brackets.");
    else o[0] = 0;
    return o;
}

static int cmp_skip(const void *a, const void *b)   /* by reason, host, path */
{
    const struct skip *x = &R.skips[*(const size_t *)a], *y = &R.skips[*(const size_t *)b];
    int c = strcmp(x->reason, y->reason);
    if (!c) c = strcmp(R.runs[x->run].host, R.runs[y->run].host);
    return c ? c : strcmp(x->path, y->path);
}

static void section_accepted(struct doc *d)
{
    if (!R.triage_file) return;              /* no triage file: the report says nothing about it */
    doc_h(d, 2, "Accepted false positives (triage)");
    int ny, nm, nd, stale = 0, review = 0;
    char today[24];
    iso_time(R.now, today);
    parse_date(today, &ny, &nm, &nd);
    int t = doc_table(d, 9, "Host", "Path", "Number", "Reason", "Decided by", "Date", "Ticket", "Hits", "State");
    for (int i = 0; i < R.ntri; i++) {
        struct triage *e = &R.tri[i];
        int y, m, dd;
        parse_date(e->date, &y, &m, &dd);
        int months = (ny * 12 + nm) - (y * 12 + m) - (nd < dd ? 1 : 0);
        const char *state = "in use";
        if (!e->matched) { state = "stale: matches nothing"; stale++; }
        else if (months >= R.triage_age) { state = "review again: older than the set age"; review++; }
        doc_row(d, t, e->host, e->path, e->masked, e->reason, e->who, e->date, e->ticket, N(e->matched), state);
    }
    doc_p(d, "Triage file: %s. %d entries; %d stale (no longer match any hit), %d due for review (decided %d "
             "months ago or longer). The triage file is applied in this report only; the run files are unchanged.",
          R.triage_file, R.ntri, stale, review, R.triage_age);
}

struct dk { long now, before; const char *mnow, *mbefore; const struct rhit *h; };

static void section_diff(struct doc *d)
{
    doc_h(d, 2, "Differences against the previous run");
    int any = 0;
    static struct strbuf k;
    for (int ri = 0; ri < R.nruns; ri++) {
        const struct run *r = &R.runs[ri];
        if (!r->latest || r->prev < 0) continue;
        any = 1;
        struct smap ids = { 0 };
        struct dk *dk = NULL;
        int cap = 0;
        char nm[32];
        for (size_t i = 0; i < R.nhits; i++) {
            const struct rhit *h = &R.hits[i];
            if (h->run != ri && h->run != r->prev) continue;
            norm_masked(h->masked, nm);
            sb_reset(&k);
            sb_printf(&k, "%s" SEP "%s" SEP "%s", h->path, h->member ? h->member : "", nm);
            int isnew, id = smap_id(&ids, k.s, &isnew);
            if (id >= cap) { cap = cap ? cap * 2 : 256; dk = xrealloc(dk, (size_t)cap * sizeof *dk); }
            if (isnew) memset(&dk[id], 0, sizeof dk[id]);
            if (h->run == ri) { dk[id].now++; dk[id].mnow = h->marks; dk[id].h = h; }
            else { dk[id].before++; dk[id].mbefore = h->marks; if (!dk[id].h) dk[id].h = h; }
        }
        long added = 0, gone = 0, changed = 0;
        for (int i = 0; i < (int)ids.n; i++) {
            if (dk[i].now > dk[i].before) added += dk[i].now - dk[i].before;
            if (dk[i].before > dk[i].now) gone += dk[i].before - dk[i].now;
            if (dk[i].now && dk[i].before && strcmp(dk[i].mnow, dk[i].mbefore)) changed++;
        }
        doc_h(d, 3, "%s: %s against %s", r->host, r->start, R.runs[r->prev].start);
        doc_p(d, "%ld new hits, %ld hits gone, %ld hits with changed marks. Hits are compared by path, "
                 "archive member and masked number.", added, gone, changed);
        int t = doc_table(d, 5, "Change", "Path", "File inside archive", "Number", "Marks before -> now");
        int shown = 0;
        for (int i = 0; i < (int)ids.n && shown < R.top; i++) {
            const char *what = NULL;
            if (dk[i].now > dk[i].before) what = "new";
            else if (dk[i].before > dk[i].now) what = "gone";
            else if (strcmp(dk[i].mnow, dk[i].mbefore)) what = "marks changed";
            if (!what) continue;
            struct strbuf mk = { 0 };
            sb_add(&mk, dk[i].mbefore && dk[i].mbefore[0] ? joined(dk[i].mbefore, ", ") : (dk[i].before ? "suspected PAN" : "-"));
            sb_add(&mk, " -> ");
            sb_add(&mk, dk[i].mnow && dk[i].mnow[0] ? joined(dk[i].mnow, ", ") : (dk[i].now ? "suspected PAN" : "-"));
            doc_row(d, t, what, dk[i].h->path, dk[i].h->member, dk[i].h->masked, mk.s);
            sb_free(&mk);
            shown++;
        }
        if (added + gone + changed > shown && shown == R.top)
            doc_p(d, "Only the first %d changes are listed.", R.top);
        smap_free(&ids);
        free(dk);
    }
    if (!any) doc_p(d, "No host has an earlier run among the files given, so there is nothing to compare.");
}

static int cmp_run_idx(const void *a, const void *b)
{
    const struct run *x = &R.runs[*(const int *)a], *y = &R.runs[*(const int *)b];
    int c = strcmp(x->host, y->host);
    return c ? c : strcmp(x->start, y->start);
}

static void section_runs(struct doc *d, const int *order)
{
    doc_h(d, 2, "Trend");
    doc_p(d, "Every run given, per host in date order, so growth or a clean-up shows.");
    int t = doc_table(d, 6, "Host", "Run started", "Suspected PANs", "Likely false positives", "Accepted false positives", "Coverage");
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[order[i]];
        doc_row(d, t, r->host, r->start, N(r->open), N(r->likely), N(r->accepted), r->coverage);
    }

    doc_h(d, 2, "Coverage");
    doc_p(d, "A clean result only claims what was searched. Coverage is full when nothing was skipped, "
             "partial when files were not or not fully scanned, incomplete when the run did not finish.");
    t = doc_table(d, 9, "Host", "Run started", "Coverage", "Files", "MiB read", "Archives", "Skipped",
                  "Digits kept", "Version");
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[order[i]];
        if (!r->latest) continue;
        doc_row(d, t, r->host, r->start, r->coverage, N(r->files), N(r->bytes >> 20), N(r->archives),
                N(r->skipped), !strcmp(r->keep, "6") ? "6 + 4" : "8 + 4 (6 + 4 under 16 digits)",
                r->version);
    }
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[order[i]];
        if (!r->latest) continue;
        if (!r->complete)
            doc_p(d, "Warning: the run of %s started %s did not finish (file %s has no end record). "
                     "Its hits are counted, but its coverage is unknown.", r->host, r->start, r->file);
        if (r->messages) doc_p(d, "Message from the run on %s: %s", r->host, r->messages);
        if (r->not_entered)
            doc_p(d, "Not searched on %s, because a run stays on the file system of each path it is given: "
                     "%s. Add these as paths to search them.", r->host, r->not_entered);
    }

    struct grouping why = { 0 }, scanned = { 0 }, left = { 0 };
    static struct strbuf k;
    struct rhit fake;
    memset(&fake, 0, sizeof fake);
    long listed = 0, total = 0;

    doc_h(d, 3, "Scanned paths");
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[order[i]];
        if (!r->latest) continue;
        for (int p = 0; p < r->paths.n; p++) {
            fake.run = order[i];
            fake.path = r->paths.v[p];
            add_host(grp_hit(&scanned, r->paths.v[p], &fake), r->host);
        }
    }
    if (!scanned.n) doc_p(d, "The run files do not name the paths.");
    else {
        t = doc_table(d, 3, "Path", "Hosts", "Scanned on");
        for (int i = 0; i < scanned.n; i++)
            doc_row(d, t, scanned.g[i].key, N(scanned.g[i].hosts), scanned.g[i].note);
    }
    grp_free(&scanned);

    doc_h(d, 3, "Excluded from the scan");
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[order[i]];
        if (!r->latest) continue;
        for (int p = 0; p < r->excludes.n; p++) {
            /* an exclude that starts with a scanned path applies to that path only */
            const char *e = r->excludes.v[p], *in = e[0] == '/' ? "outside the scanned paths" : "every scanned path";
            size_t best = 0;
            for (int q = 0; q < r->paths.n; q++) {
                size_t n = strlen(r->paths.v[q]);
                if (n > best && !strncmp(e, r->paths.v[q], n) && (e[n] == '/' || e[n] == 0)) { best = n; in = r->paths.v[q]; }
            }
            sb_reset(&k); sb_printf(&k, "%s" SEP "%s", in, e);
            fake.run = order[i];
            fake.path = (char *)e;
            add_host(grp_hit(&left, k.s, &fake), r->host);
        }
    }
    if (!left.n) doc_p(d, "No excludes were set.");
    else {
        doc_p(d, "Patterns and folders ignored by the scan, per scanned path and relative to it. /proc, /sys, "
                 "/dev and /run are always ignored.");
        /* one row per scanned path: its excludes together, when they hold on the same hosts */
        qsort(left.g, (size_t)left.n, sizeof *left.g, cmp_grp_key);
        t = doc_table(d, 4, "Scanned path", "Ignored", "Hosts", "On");
        struct strbuf list = { 0 };
        for (int i = 0; i < left.n; i++) {
            struct grp *g = &left.g[i];
            if (!g->key) continue;               /* already in an earlier row */
            char *e = split_key(g->key);
            size_t pl = strlen(g->key);          /* shown without the scanned path in front */
            sb_reset(&list);
            sb_add(&list, !strncmp(e, g->key, pl) && e[pl] == '/' ? e + pl + 1 : e);
            for (int j = i + 1; j < left.n; j++) {
                struct grp *o = &left.g[j];
                if (!o->key) continue;
                size_t n = strlen(g->key);
                if (strncmp(o->key, g->key, n) || o->key[n] != SEP[0] || strcmp(o->note, g->note)) continue;
                const char *oe = o->key + n + 1;
                sb_printf(&list, ", %s", !strncmp(oe, g->key, pl) && oe[pl] == '/' ? oe + pl + 1 : oe);
                free(o->key);
                o->key = NULL;
            }
            doc_row(d, t, g->key, list.s, N(g->hosts), g->note);
        }
        sb_free(&list);
    }
    grp_free(&left);

    for (size_t i = 0; i < R.nskips; i++) {
        const struct skip *s = &R.skips[i];
        if (!R.runs[s->run].latest) continue;
        total++;
        /* group on the reason without its detail in brackets */
        sb_reset(&k);
        sb_printf(&k, "%.*s", (int)strcspn(s->reason, "("), s->reason);
        while (k.len && k.s[k.len - 1] == ' ') k.s[--k.len] = 0;
        fake.run = s->run;
        fake.path = s->path;
        add_host(grp_hit(&why, k.s, &fake), R.runs[s->run].host);
    }
    grp_sort(&why);
    doc_h(d, 3, "Not scanned, by reason");
    t = doc_table(d, 4, "Reason", "Criterion", "Files", "Hosts");
    for (int i = 0; i < why.n; i++) {
        const char *crit = "";
        size_t kl = strlen(why.g[i].key);
        for (size_t j = 0; j < R.nskips && !crit[0]; j++)
            if (R.runs[R.skips[j].run].latest && !strncmp(R.skips[j].reason, why.g[i].key, kl))
                crit = skip_criterion(&R.skips[j]);
        doc_row(d, t, why.g[i].key, crit, N(why.g[i].files), why.g[i].note);
    }
    grp_free(&why);
    doc_h(d, 3, "Not scanned, the files");
    /* one table per reason */
    size_t *idx = xmalloc((R.nskips + 1) * sizeof *idx), n = 0;
    for (size_t i = 0; i < R.nskips; i++)
        if (R.runs[R.skips[i].run].latest) idx[n++] = i;
    qsort(idx, n, sizeof *idx, cmp_skip);
    /* a file is listed once per reason, also when several files inside it were skipped */
    size_t m = 0;
    for (size_t i = 0; i < n; i++)
        if (!m || cmp_skip(&idx[m - 1], &idx[i])) idx[m++] = idx[i];
    const char *last = NULL;
    for (size_t i = 0; i < m && listed < R.top; i++) {
        const struct skip *s = &R.skips[idx[i]];
        if (!last || strcmp(last, s->reason)) {
            long same = 0;
            for (size_t j = i; j < m && !strcmp(R.skips[idx[j]].reason, s->reason); j++) same++;
            doc_p(d, "%s: %ld file%s. %s", s->reason, same, same == 1 ? "" : "s", skip_criterion(s));
            t = doc_table(d, 2, "Host", "Path");
            last = s->reason;
        }
        doc_row(d, t, R.runs[s->run].host, s->path);
        listed++;
    }
    free(idx);
    total = (long)m;
    if (total > listed) doc_p(d, "%ld more are in the run files (lines of type skip).", total - listed);
}

static void csv_cell(struct strbuf *b, const char *s, int last)
{
    if (!s) s = "";
    /* a cell that a spreadsheet would run as a formula gets a leading apostrophe */
    int formula = *s == '=' || *s == '+' || *s == '-' || *s == '@';
    if (formula || strpbrk(s, ",\"\n\r")) {
        sb_addn(b, "\"", 1);
        if (formula) sb_addn(b, "'", 1);
        for (; *s; s++) { if (*s == '"') sb_addn(b, "\"", 1); sb_addn(b, s, 1); }
        sb_addn(b, "\"", 1);
    } else sb_add(b, s);
    sb_addn(b, last ? "\n" : ",", 1);
}

static int write_csv(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    struct strbuf b = { 0 };
    sb_add(&b, "host,run_started,newest_run,status,path,member,brand,masked,digits,track,offset,file_modified,"
               "marks,reasons,triage_reason,issuer,country,card_type,category,issuer_data_credit\n");
    for (size_t i = 0; i < R.nhits; i++) {
        const struct rhit *h = &R.hits[i];
        const struct run *r = &R.runs[h->run];
        csv_cell(&b, r->host, 0);
        csv_cell(&b, r->start, 0);
        csv_cell(&b, r->latest ? "yes" : "no", 0);
        csv_cell(&b, status_names[h->status], 0);
        csv_cell(&b, h->path, 0);
        csv_cell(&b, h->member, 0);
        csv_cell(&b, R.brands.v[h->brand], 0);
        csv_cell(&b, h->masked, 0);
        csv_cell(&b, N(h->digits), 0);
        csv_cell(&b, N(h->track), 0);
        csv_cell(&b, N(h->offset), 0);
        csv_cell(&b, h->mtime, 0);
        csv_cell(&b, joined(h->marks, ";"), 0);
        csv_cell(&b, joined(h->reasons, "; "), 0);
        csv_cell(&b, h->triage >= 0 ? R.tri[h->triage].reason : "", 0);
        csv_cell(&b, h->bin ? h->bin->issuer : "", 0);
        csv_cell(&b, h->bin ? h->bin->country : "", 0);
        csv_cell(&b, h->bin ? h->bin->type : "", 0);
        csv_cell(&b, h->bin ? h->bin->category : "", 0);
        /* the CSV may be passed on without the report, so the credit is in the row */
        int own = h->bin && R.bin.nov && h->bin >= R.bin.ov && h->bin < R.bin.ov + R.bin.nov;
        csv_cell(&b, !h->bin ? "" : own ? "local overrides file"
                                        : "bin-list-data (Venelin Kochev / BinLookup.io), CC BY 4.0, trimmed", 1);
        if (b.len > (1 << 16)) { fwrite(b.s, 1, b.len, f); sb_reset(&b); }
    }
    int bad = fwrite(b.s, 1, b.len, f) != b.len;
    if (fclose(f) != 0) bad = 1;
    sb_free(&b);
    return bad ? -1 : 0;
}

static void usage(void)
{
    fputs(
        "usage: chdsweep report [options] run1.jsonl [run2.jsonl ...]\n"
        "  Merges run files from several hosts and dates. Writes PREFIX.md, PREFIX.html and PREFIX.csv.\n"
        "  -o PREFIX               output name without extension (default chdsweep-report)\n"
        "  --triage FILE           accepted false positives (default /etc/chdsweep/triage.csv, if present)\n"
        "  --show-marked=WHAT      none, summary (default) or all: how much of the marked hits is printed\n"
        "  --depth N               folder levels in the location table (default 3)\n"
        "  --top N                 rows in the top lists (default 25)\n"
        "  --triage-age MONTHS     triage entries this old are listed for review (default 12)\n"
        "  --bin-table FILE        BIN table to use instead of the newest available\n"
        "  --bin-dir DIR           where bin-update keeps its tables (default /var/lib/chdsweep/bin)\n"
        "  --bin-overrides FILE    local corrections (default /etc/chdsweep/bin-overrides.csv, if present)\n"
        "  --bin-age DAYS          warn when the BIN table is older (default 90)\n"
        "  --now YYYY-MM-DD        date of the report, to rebuild an earlier one\n",
        stderr);
}

int cmd_report(int argc, char **argv)
{
    static struct strlist files;   /* static: lives as long as the process */
    char err[600];
    R.prefix = "chdsweep-report";
    R.bin_dir = "/var/lib/chdsweep/bin";
    R.show_marked = 1;
    R.depth = 3;
    R.top = 25;
    R.triage_age = 12;
    R.bin_age = 90;
    R.now = time(NULL);
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        const char *eq = strchr(a, '=');
        if (!strncmp(a, "--show-marked", 13)) {
            const char *w = eq ? eq + 1 : v;
            if (!eq) i++;
            if (w && !strcmp(w, "none")) R.show_marked = 0;
            else if (w && !strcmp(w, "summary")) R.show_marked = 1;
            else if (w && !strcmp(w, "all")) R.show_marked = 2;
            else { usage(); return EXIT_FAILED; }
        } else if (a[0] == '-' && a[1]) {
            if (!v) { usage(); return EXIT_FAILED; }
            if (!strcmp(a, "-o")) R.prefix = v;
            else if (!strcmp(a, "--triage")) R.triage_file = v;
            else if (!strcmp(a, "--bin-table")) R.bin_file = v;
            else if (!strcmp(a, "--bin-dir")) R.bin_dir = v;
            else if (!strcmp(a, "--bin-overrides")) R.bin_overrides = v;
            else if (!strcmp(a, "--depth")) R.depth = atoi(v) > 0 ? atoi(v) : 3;
            else if (!strcmp(a, "--top")) R.top = atoi(v) > 0 ? atoi(v) : 25;
            else if (!strcmp(a, "--triage-age")) R.triage_age = atoi(v);
            else if (!strcmp(a, "--bin-age")) R.bin_age = atoi(v);
            else if (!strcmp(a, "--now")) {
                int y, m, dd;
                if (!parse_date(v, &y, &m, &dd)) { usage(); return EXIT_FAILED; }
                struct tm tm = { .tm_year = y - 1900, .tm_mon = m - 1, .tm_mday = dd, .tm_hour = 12 };
                R.now = timegm(&tm);
            } else { fprintf(stderr, "chdsweep: report: unknown option %s\n", a); usage(); return EXIT_FAILED; }
            i++;
        } else sl_add(&files, a);
    }
    if (!files.n) { usage(); return EXIT_FAILED; }
    if (!R.triage_file && access("/etc/chdsweep/triage.csv", R_OK) == 0) R.triage_file = "/etc/chdsweep/triage.csv";
    if (!R.bin_overrides && access("/etc/chdsweep/bin-overrides.csv", R_OK) == 0)
        R.bin_overrides = "/etc/chdsweep/bin-overrides.csv";

    if (bin_load(&R.bin, R.bin_file, R.bin_dir, R.bin_overrides, err, sizeof err)) {
        fprintf(stderr, "chdsweep: report: %s\n", err);
        return EXIT_FAILED;
    }
    for (int i = 0; i < files.n; i++)
        if (load_run(files.v[i])) return EXIT_FAILED;
    if (R.triage_file && load_triage(R.triage_file)) return EXIT_FAILED;
    classify();

    int *order = xmalloc((size_t)R.nruns * sizeof *order);
    for (int i = 0; i < R.nruns; i++) order[i] = i;
    qsort(order, (size_t)R.nruns, sizeof *order, cmp_run_idx);

    /* The order a reader needs: where, which files and numbers, what was set aside and why,
     * then the breakdowns and the record of the runs. */
    struct doc d = { 0 };
    char today[24];
    iso_time(R.now, today);
    today[10] = 0;
    long open = 0, likely = 0, accepted = 0, hosts = 0;
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[i];
        if (!r->latest) continue;
        open += r->open; likely += r->likely; accepted += r->accepted; hosts++;
    }
    doc_h(&d, 1, "Cardholder data discovery report");
    doc_p(&d, "Made by chdsweep %s on %s from %d run file%s. Card numbers are masked: at most the first six "
              "or eight and the last four digits are shown, never a full number.", CHD_VERSION, today, R.nruns, R.nruns == 1 ? "" : "s");
    struct strbuf acc = { 0 };
    if (R.triage_file) sb_printf(&acc, ", %ld accepted false positives", accepted);
    doc_p(&d, "%ld suspected PANs and %ld likely false positives%s on %ld host%s. "
              "A suspected PAN is a number that passes the brand and Luhn checks and that no false-positive "
              "rule marks; it needs a person to look at it. The counts are never added together and "
              "come from the newest run of each host.", open, likely, acc.s ? acc.s : "", hosts, hosts == 1 ? "" : "s");
    sb_free(&acc);

    section_locations(&d);
    section_files(&d);
    section_likely(&d);
    section_accepted(&d);

    doc_h(&d, 2, "Summary per host");
    int t = doc_table(&d, 5, "Host", "Suspected PANs", "Likely false positives", "Newest run", "Coverage");
    for (int i = 0; i < R.nruns; i++) {
        const struct run *r = &R.runs[order[i]];
        if (!r->latest) continue;
        doc_row(&d, t, r->host, N(r->open), N(r->likely), r->start, r->coverage);
    }
    section_breakdowns(&d);
    section_issuers(&d);
    section_diff(&d);
    section_runs(&d, order);
    if (!R.triage_file) doc_drop_column(&d, "Accepted false positives");

    /* Credits: in every report, so they travel with it. */
    doc_h(&d, 2, "Credits and licences");
    doc_p(&d, "Tool: chdsweep %s, copyright (c) 2026 D.J.S. van den Akker, MIT License. The licence asks "
              "for one thing: keep this credit with every copy.", CHD_VERSION);
    doc_p(&d, "Inspiration: ccsrch by Mike Beekey and Adam Caudill (https://github.com/adamcaudill/ccsrch) "
              "and PANhunt.");
    doc_p(&d, "Issuer data: " BIN_ATTRIBUTION " Source: https://github.com/venelinkochev/bin-list-data, "
              "licence: https://creativecommons.org/licenses/by/4.0/.");
    if (R.bin.overrides[0])
        doc_p(&d, "Issuer entries from the local overrides file %s are your own data and not part of that "
                  "data set.", R.bin.overrides);

    struct strbuf path = { 0 };
    int bad = 0;
    static const char *const ext[] = { ".md", ".html", ".csv" };
    for (int i = 0; i < 3; i++) {
        sb_reset(&path);
        sb_printf(&path, "%s%s", R.prefix, ext[i]);
        int rc = i == 0 ? doc_write_md(&d, path.s) : i == 1 ? doc_write_html(&d, path.s) : write_csv(path.s);
        if (rc) { fprintf(stderr, "chdsweep: report: cannot write %s: %s\n", path.s, strerror(errno)); bad = 1; }
        else printf("%s\n", path.s);
    }
    sb_free(&path);
    doc_free(&d);
    free(order);
    return bad ? EXIT_FAILED : 0;
}
