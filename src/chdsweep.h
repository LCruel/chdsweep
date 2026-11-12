/* chdsweep: shared declarations */
#ifndef CHDSWEEP_H
#define CHDSWEEP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

#define CHD_VERSION "0.1.0-dev"

/* Exit codes: health of the run, never whether cards were found. */
enum { EXIT_FULL = 0, EXIT_PARTIAL = 1, EXIT_FAILED = 2, EXIT_LOCKED = 3 };

/* ---- util.c ---- */
struct strbuf { char *s; size_t len, cap; };
void sb_reset(struct strbuf *b);
void sb_free(struct strbuf *b);
void sb_add(struct strbuf *b, const char *s);
void sb_addn(struct strbuf *b, const char *s, size_t n);
void sb_printf(struct strbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void sb_json_str(struct strbuf *b, const char *s);   /* quoted, escaped, valid UTF-8 */
void iso_time(time_t t, char out[24]);
void *xmalloc(size_t n);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
uint64_t fnv1a64(const void *data, size_t n, uint64_t h);
double now_seconds(void);

struct strlist { char **v; int n; };
void sl_add(struct strlist *l, const char *s);

/* ---- detect.c ---- */
int luhn_ok(const char *digits, int n);
const char *brand_lookup(const char *digits, int n);   /* NULL: no brand with this prefix and length */
int is_test_card(const char *digits, int n);
int is_repeat_digits(const char *digits, int n);
int is_sequence(const char *digits, int n);
/* keep_leading: 0 = auto, 6 or 8. out needs n + 1 bytes. */
void mask_number(const char *digits, int n, int keep_leading, char *out);

/* ---- rules.c ---- */
enum rule_id {
    R_TEST_CARD, R_REPEAT, R_SEQUENCE, R_LOW_LUHN, R_ID_KEYWORD,
    R_INSIDE_TOKEN, R_PACKAGE_FILE, R_TEST_PATH, R_BINARY, R_COUNT
};
extern const char *const rule_names[R_COUNT];
extern const char *const rule_criteria[R_COUNT];

struct rules {
    int on[R_COUNT];
    int luhn_percent;      /* low-luhn-ratio: mark below this pass rate */
    int luhn_min_runs;     /* ... when the file has at least this many candidates */
    int kw_window;         /* id-keyword: bytes looked at before the number */
    struct strlist keywords;
    char source[512];      /* "built-in" or the file's path */
    uint64_t checksum;
};
void rules_defaults(struct rules *r);
int rules_load(struct rules *r, const char *path, char *err, size_t errlen);

/* ---- scan.c ---- */
struct hit {
    uint64_t offset;
    int ndigits;
    int track;             /* 0, 1 or 2 */
    const char *brand;
    char masked[24];
    unsigned marks;        /* bit per rule_id */
    char keyword[32];      /* id-keyword: the key name that matched */
};

struct scan_result {
    struct hit *hits;
    size_t n, cap;
    uint64_t cand_total;   /* candidates with a brand prefix and length */
    uint64_t cand_luhn;    /* ... that pass Luhn */
    uint64_t bytes;
    uint64_t dropped;      /* hits over hit_room: counted, not kept */
    int binary_db;         /* SQLite or Berkeley DB file */
};

struct scan_opts {
    const struct rules *rules;
    int keep_leading;
    unsigned char *buf;              /* work buffer of SCAN_BUF_SIZE bytes */
    int hit_limit;                   /* 1: keep at most hit_room hits, count the rest */
    size_t hit_room;
};
#define SCAN_BUF_SIZE (64 * 1024 + 256)

typedef ssize_t (*scan_read_fn)(void *cookie, void *buf, size_t n);
/* Scans a stream. Returns 0, or -1 when the read function failed. */
int scan_stream(const struct scan_opts *o, scan_read_fn rd, void *cookie, struct scan_result *res);
void scan_result_reset(struct scan_result *res);
/* Applies the rules that need the whole file: low-luhn-ratio, package-file, test-path. */
void rules_finalize(const struct rules *r, const char *path, const char *member,
                    const char *package, struct scan_result *res);
void mark_reason(int rule, const struct hit *h, const struct scan_result *res,
                 const char *package, char *out, size_t outlen);

/* ---- libs.c: libarchive and libcrypto, loaded at run time ---- */
struct libs {
    int have_archive, have_crypto;
    char archive_name[32], crypto_name[32];
    char archive_version[96], crypto_version[96];

    /* libarchive */
    void *(*a_read_new)(void);
    int (*a_support_filter_gzip)(void *);
    int (*a_support_format_tar)(void *);
    int (*a_support_format_zip)(void *);
    int (*a_support_format_raw)(void *);
    int (*a_support_format_empty)(void *);
    int (*a_read_open)(void *, void *client,
                       int (*open_cb)(void *, void *),
                       ssize_t (*read_cb)(void *, void *, const void **),
                       int (*close_cb)(void *, void *));
    int (*a_next_header)(void *, void **entry);
    const char *(*a_entry_pathname)(void *entry);
    unsigned (*a_entry_filetype)(void *entry);
    ssize_t (*a_read_data)(void *, void *, size_t);
    int (*a_read_free)(void *);
    const char *(*a_error_string)(void *);
    int (*a_format)(void *);

    /* libcrypto */
    const void *(*c_md5)(void);
    void *(*c_ctx_new)(void);
    int (*c_init)(void *ctx, const void *md, void *engine);
    int (*c_update)(void *ctx, const void *d, size_t n);
    int (*c_final)(void *ctx, unsigned char *out, unsigned *outlen);
    void (*c_ctx_free)(void *ctx);
};
extern struct libs L;
void libs_load(void);
/* Message for a missing library ("archive" or "crypto"), with the fix for this distribution. */
void libs_missing_message(const char *which, struct strbuf *out);
int cmd_check(void);

/* ---- config.c ---- */
struct config {
    struct strlist paths, excludes;
    uint64_t max_file_size;      /* 0: no limit */
    uint64_t max_unpacked;
    int max_depth;
    int max_ratio;
    long max_members;
    int max_file_seconds;        /* 0: no limit */
    long max_hits_per_file;      /* hits listed per file, the rest are counted; 0: no limit */
    uint64_t max_read_rate;     /* bytes per second read from disk, all workers together; 0: no limit */
    int threads;
    char *output_dir, *output_file;
    char *lock_file;             /* "": no lock */
    int keep_leading;            /* 0 auto, 6, 8 */
    char *rules_file;
    int nice_level;
    int ionice_idle;
    int quiet;
    int progress;                /* off unless asked for: chdsweep is made for cron */
    int journal_days;            /* system journal of the last N days; 0 off, -1 not set */
    int require_all_libraries;
};
void config_defaults(struct config *c);
int config_load(struct config *c, const char *path, char *err, size_t errlen);
int config_set(struct config *c, const char *key, const char *val, char *err, size_t errlen);

/* ---- pkgdb.c ---- */
/* 1 when the file is an unchanged file of an installed dpkg package. */
int pkgdb_unchanged(int dirfd, const char *name, const char *path, char *pkg, size_t pkglen);

/* ---- run.c ---- */
int cmd_scan(struct config *cfg, const char *config_path);

/* ---- util.c: string keys to sequential ids (a set, or a map with parallel arrays) ---- */
struct smap { char **keys; int *vals; size_t cap, n; };
int smap_id(struct smap *m, const char *key, int *isnew);   /* id of key; added when new */
int smap_find(const struct smap *m, const char *key);       /* id, or -1 */
void smap_free(struct smap *m);
/* Splits a CSV line in place (quoted fields, "" for a quote). Returns the number of fields. */
int csv_split(char *line, char **fields, int max);

/* ---- json.c: reader for the run files ---- */
enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };
struct jv { int type; char *key; char *s; long long n; struct jv *child, *next; };
struct jv *json_parse(const char *text);                    /* NULL when not valid JSON */
void json_free(struct jv *v);
const struct jv *json_get(const struct jv *obj, const char *key);
const char *json_str(const struct jv *obj, const char *key, const char *def);
long long json_num(const struct jv *obj, const char *key, long long def);

/* ---- bintable.c: issuer lookup, offline ---- */
struct bin_entry { char prefix[9]; const char *brand, *type, *category, *issuer, *country; };
struct bin_table {
    struct bin_entry *e, *ov;       /* table and local overrides, each sorted by prefix */
    size_t n, nov;
    char source[128], commit[64], pulled[16];
    char origin[4200];              /* "built-in" or the file's path */
    char overrides[4200];           /* overrides file, or "" */
};
/* file: a table file, or NULL for the newest of the built-in set and the files in dir. */
int bin_load(struct bin_table *t, const char *file, const char *dir, const char *overrides,
             char *err, size_t errlen);
/* Longest matching prefix of the digits a masked number keeps; NULL: unknown issuer. */
const struct bin_entry *bin_lookup(const struct bin_table *t, const char *masked);
int cmd_bin_update(int argc, char **argv);
#define BIN_ATTRIBUTION \
    "bin-list-data by Venelin Kochev / BinLookup.io, licence CC BY 4.0, changed by chdsweep " \
    "(trimmed to six fields). Not an official BIN register."

/* ---- doc.c: a report as headings, paragraphs and tables; written as Markdown and HTML ---- */
struct block { int type; char *text; int ncols; struct strlist cells; };
struct doc { struct block *b; int n; char *title; };
void doc_h(struct doc *d, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
void doc_p(struct doc *d, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
int doc_table(struct doc *d, int ncols, ...);      /* ncols header strings; returns the table's index */
void doc_row(struct doc *d, int table, ...);       /* ncols cell strings */
int doc_rows(const struct doc *d, int table);
int doc_write_md(const struct doc *d, const char *path);
int doc_write_html(const struct doc *d, const char *path);
void doc_drop_column(struct doc *d, const char *header);   /* from every table that has it */
void doc_free(struct doc *d);

/* ---- report.c ---- */
int cmd_report(int argc, char **argv);

#endif
