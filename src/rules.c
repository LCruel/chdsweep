/* chdsweep: false-positive rules. A rule marks a hit with a reason; it never drops one. */
#include "chdsweep.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

const char *const rule_names[R_COUNT] = {
    "test-card", "repeat-digits", "sequence", "low-luhn-ratio", "id-keyword",
    "inside-token", "package-file", "test-path", "binary-context",
};

/* What each rule tests, for the report. The reason on a hit gives that hit's own values. */
const char *const rule_criteria[R_COUNT] = {
    "The number is a published test card number",
    "At most two different digits after the first six",
    "The digits run up or down in sequence",
    "Few of the card-like numbers in the file pass the Luhn check (under 30% of 20 or more, "
        "unless set otherwise): most likely random numbers",
    "A label just before the number names it as something else (order id, IMEI, session, ...)",
    "The number is part of a longer identifier, joined to more digits by . / : = or -",
    "The file belongs to an installed package and is unchanged since installation",
    "The file is in a test or library folder and another rule marks the number too",
    "The number sits between bytes that are not text",
};

static const char *const default_keywords[] = {
    "imei", "iccid", "imsi", "msisdn", "serial", "order_id", "orderid", "invoice",
    "tracking", "uuid", "guid", "timestamp", "phone", "iban", "user_id", "account_id",
    "session", "transaction_id", "txn_id", "barcode", "ean", "isbn",
};

void rules_defaults(struct rules *r)
{
    memset(r, 0, sizeof *r);
    for (int i = 0; i < R_COUNT; i++) r->on[i] = 1;
    r->luhn_percent = 30;
    r->luhn_min_runs = 20;
    r->kw_window = 32;
    for (size_t i = 0; i < sizeof default_keywords / sizeof default_keywords[0]; i++)
        sl_add(&r->keywords, default_keywords[i]);
    snprintf(r->source, sizeof r->source, "built-in");
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = 0;
    return s;
}

static int parse_bool(const char *v, int *out)
{
    if (!strcasecmp(v, "on") || !strcasecmp(v, "yes") || !strcasecmp(v, "true") || !strcmp(v, "1")) { *out = 1; return 0; }
    if (!strcasecmp(v, "off") || !strcasecmp(v, "no") || !strcasecmp(v, "false") || !strcmp(v, "0")) { *out = 0; return 0; }
    return -1;
}

/* File format: "rule-id = on|off", plus the settings
 *   low-luhn-ratio.percent, low-luhn-ratio.min-runs, id-keyword.window,
 *   id-keyword.keywords (comma list, replaces the defaults), id-keyword.add (comma list). */
int rules_load(struct rules *r, const char *path, char *err, size_t errlen)
{
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, errlen, "%s: %s", path, strerror(errno)); return -1; }
    char line[4096];
    int lineno = 0;
    uint64_t sum = 0;
    while (fgets(line, sizeof line, f)) {
        lineno++;
        sum = fnv1a64(line, strlen(line), sum);
        char *s = trim(line);
        if (!*s || *s == '#') continue;
        char *eq = strchr(s, '=');
        if (!eq) { snprintf(err, errlen, "%s:%d: expected key = value", path, lineno); fclose(f); return -1; }
        *eq = 0;
        char *key = trim(s), *val = trim(eq + 1);
        int ok = 0;
        for (int i = 0; i < R_COUNT && !ok; i++)
            if (!strcmp(key, rule_names[i])) ok = parse_bool(val, &r->on[i]) == 0;
        if (ok) continue;
        if (!strcmp(key, "low-luhn-ratio.percent")) r->luhn_percent = atoi(val);
        else if (!strcmp(key, "low-luhn-ratio.min-runs")) r->luhn_min_runs = atoi(val);
        else if (!strcmp(key, "id-keyword.window")) {
            r->kw_window = atoi(val);
            if (r->kw_window < 1 || r->kw_window > 64) {
                snprintf(err, errlen, "%s:%d: id-keyword.window must be 1 to 64", path, lineno);
                fclose(f);
                return -1;
            }
        } else if (!strcmp(key, "id-keyword.keywords") || !strcmp(key, "id-keyword.add")) {
            if (!strcmp(key, "id-keyword.keywords")) {
                for (int i = 0; i < r->keywords.n; i++) free(r->keywords.v[i]);
                r->keywords.n = 0;
            }
            for (char *tok = strtok(val, ","); tok; tok = strtok(NULL, ",")) {
                tok = trim(tok);
                for (char *p = tok; *p; p++) *p = (char)tolower((unsigned char)*p);
                if (*tok) sl_add(&r->keywords, tok);
            }
        } else {
            snprintf(err, errlen, "%s:%d: unknown rule or setting '%s'", path, lineno, key);
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    snprintf(r->source, sizeof r->source, "%s", path);
    r->checksum = sum;
    return 0;
}

static int has_test_folder(const char *p)
{
    static const char *const folders[] = {
        "/test/", "/tests/", "/fixtures/", "/examples/", "/node_modules/", "/site-packages/", "/vendor/",
    };
    if (!p) return 0;
    for (size_t i = 0; i < sizeof folders / sizeof folders[0]; i++)
        if (strstr(p, folders[i])) return 1;
    return 0;
}

void rules_finalize(const struct rules *r, const char *path, const char *member,
                    const char *package, struct scan_result *res)
{
    int low = r->on[R_LOW_LUHN] && res->cand_total >= (uint64_t)r->luhn_min_runs &&
              res->cand_luhn * 100 < (uint64_t)r->luhn_percent * res->cand_total;
    int testpath = r->on[R_TEST_PATH] && (has_test_folder(path) || has_test_folder(member));
    for (size_t i = 0; i < res->n; i++) {
        struct hit *h = &res->hits[i];
        if (low) h->marks |= 1u << R_LOW_LUHN;
        if (package && r->on[R_PACKAGE_FILE]) h->marks |= 1u << R_PACKAGE_FILE;
        /* test-path is weak evidence: it only marks together with another rule. */
        if (testpath && h->marks) h->marks |= 1u << R_TEST_PATH;
    }
}

void mark_reason(int rule, const struct hit *h, const struct scan_result *res,
                 const char *package, char *out, size_t outlen)
{
    switch (rule) {
    case R_TEST_CARD: snprintf(out, outlen, "Known test card number"); break;
    case R_REPEAT: snprintf(out, outlen, "Repeated digits, not an issued number"); break;
    case R_SEQUENCE: snprintf(out, outlen, "Digit sequence"); break;
    case R_LOW_LUHN:
        snprintf(out, outlen, "Luhn pass rate in this file (%llu of %llu) is what random numbers give",
                 (unsigned long long)res->cand_luhn, (unsigned long long)res->cand_total);
        break;
    case R_ID_KEYWORD: snprintf(out, outlen, "Labelled as %s in the file", h->keyword); break;
    case R_INSIDE_TOKEN: snprintf(out, outlen, "Part of a longer identifier"); break;
    case R_PACKAGE_FILE: snprintf(out, outlen, "Unchanged file from package %s", package ? package : "?"); break;
    case R_BINARY: snprintf(out, outlen, "Digits found inside binary data"); break;
    case R_TEST_PATH: {
        char other[160] = "";
        for (int i = 0; i < R_COUNT; i++)
            if (i != R_TEST_PATH && (h->marks & (1u << i))) {
                mark_reason(i, h, res, package, other, sizeof other);
                break;
            }
        if (other[0]) other[0] = (char)tolower((unsigned char)other[0]);
        snprintf(out, outlen, "Test or library file, and %s", other);
        break;
    }
    default: snprintf(out, outlen, "?");
    }
}
