/* chdsweep: config file (/etc/chdsweep.conf), "key = value" lines */
#include "chdsweep.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void config_defaults(struct config *c)
{
    memset(c, 0, sizeof *c);
    c->max_file_size = 2ULL << 30;
    c->max_unpacked = 1ULL << 30;
    c->max_depth = 3;
    c->max_ratio = 200;
    c->max_members = 100000;
    c->max_file_seconds = 300;
    c->max_hits_per_file = 10000;
    c->journal_days = -1;        /* not set: 35 with the default paths, else 0 */
    c->threads = 1;              /* one reader: a scan must not crowd out the server's own disk use */
    c->output_dir = xstrdup("/var/log/chdsweep");
    c->lock_file = xstrdup("/run/chdsweep.lock");
    c->nice_level = 10;
    c->ionice_idle = 1;
}

static int parse_size(const char *v, uint64_t *out)
{
    char *end;
    errno = 0;
    unsigned long long n = strtoull(v, &end, 10);
    if (errno || end == v) return -1;
    switch (toupper((unsigned char)*end)) {
    case 'K': n <<= 10; end++; break;
    case 'M': n <<= 20; end++; break;
    case 'G': n <<= 30; end++; break;
    case 'T': n <<= 40; end++; break;
    }
    if (*end) return -1;
    *out = n;
    return 0;
}

static int parse_int(const char *v, long lo, long hi, long *out)
{
    char *end;
    errno = 0;
    long n = strtol(v, &end, 10);
    if (errno || end == v || *end || n < lo || n > hi) return -1;
    *out = n;
    return 0;
}

static int parse_yes(const char *v, int *out)
{
    if (!strcasecmp(v, "yes") || !strcasecmp(v, "on") || !strcasecmp(v, "true") || !strcmp(v, "1")) { *out = 1; return 0; }
    if (!strcasecmp(v, "no") || !strcasecmp(v, "off") || !strcasecmp(v, "false") || !strcmp(v, "0")) { *out = 0; return 0; }
    return -1;
}

static void set_str(char **dst, const char *v) { free(*dst); *dst = xstrdup(v); }

int config_set(struct config *c, const char *key, const char *val, char *err, size_t errlen)
{
    long n = 0;
    int bad = 0;
    if (!strcmp(key, "path")) sl_add(&c->paths, val);
    else if (!strcmp(key, "exclude")) sl_add(&c->excludes, val);
    else if (!strcmp(key, "max_file_size")) bad = parse_size(val, &c->max_file_size);
    else if (!strcmp(key, "max_unpacked")) bad = parse_size(val, &c->max_unpacked);
    else if (!strcmp(key, "max_depth")) { bad = parse_int(val, 0, 32, &n); c->max_depth = (int)n; }
    else if (!strcmp(key, "max_ratio")) { bad = parse_int(val, 1, 1000000, &n); c->max_ratio = (int)n; }
    else if (!strcmp(key, "max_members")) { bad = parse_int(val, 1, 1000000000, &n); c->max_members = n; }
    else if (!strcmp(key, "max_file_seconds")) { bad = parse_int(val, 0, 86400, &n); c->max_file_seconds = (int)n; }
    else if (!strcmp(key, "max_hits_per_file")) { bad = parse_int(val, 0, 1000000000, &n); c->max_hits_per_file = n; }
    else if (!strcmp(key, "max_read_rate")) bad = parse_size(val, &c->max_read_rate);
    else if (!strcmp(key, "threads")) { bad = parse_int(val, 1, 256, &n); c->threads = (int)n; }
    else if (!strcmp(key, "output_dir")) set_str(&c->output_dir, val);
    else if (!strcmp(key, "output_file")) set_str(&c->output_file, val);
    else if (!strcmp(key, "lock_file")) set_str(&c->lock_file, val);
    else if (!strcmp(key, "rules_file")) set_str(&c->rules_file, val);
    else if (!strcmp(key, "nice")) { bad = parse_int(val, 0, 19, &n); c->nice_level = (int)n; }
    else if (!strcmp(key, "ionice_idle")) bad = parse_yes(val, &c->ionice_idle);
    else if (!strcmp(key, "quiet")) bad = parse_yes(val, &c->quiet);
    else if (!strcmp(key, "journal_days")) { bad = parse_int(val, 0, 3650, &n); c->journal_days = (int)n; }
    else if (!strcmp(key, "progress")) bad = parse_yes(val, &c->progress);
    else if (!strcmp(key, "require_all_libraries")) bad = parse_yes(val, &c->require_all_libraries);
    else if (!strcmp(key, "keep_leading")) {
        if (!strcmp(val, "auto") || !strcmp(val, "8")) c->keep_leading = 0;   /* 8 is the same as auto */
        else if (!strcmp(val, "6")) c->keep_leading = 6;
        else bad = -1;
    } else {
        snprintf(err, errlen, "unknown setting '%s'", key);
        return -1;
    }
    if (bad) { snprintf(err, errlen, "bad value '%s' for %s", val, key); return -1; }
    return 0;
}

int config_load(struct config *c, const char *path, char *err, size_t errlen)
{
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    char line[4096], msg[256];
    int lineno = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        char *s = line;
        while (isspace((unsigned char)*s)) s++;
        char *e = s + strlen(s);
        while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) { snprintf(err, errlen, "%s:%d: expected key = value", path, lineno); fclose(f); return -1; }
        char *k = s, *ke = eq, *v = eq + 1;
        while (ke > k && isspace((unsigned char)ke[-1])) ke--;
        *ke = 0;
        while (isspace((unsigned char)*v)) v++;
        if (config_set(c, k, v, msg, sizeof msg)) {
            snprintf(err, errlen, "%s:%d: %s", path, lineno, msg);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}
