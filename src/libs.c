/* chdsweep: libarchive and libcrypto are loaded at run time, so a missing one
 * gives a clear message and a partial scan instead of a loader error. */
#include "chdsweep.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

struct libs L;

#ifdef CHD_STATIC
/* Static build (make static): both libraries are linked in, nothing is loaded at run time.
 * The same names are looked up in a table instead of with dlsym. */
#define LIBSYMS(X) \
    X(archive_read_new) X(archive_read_support_filter_gzip) X(archive_read_support_format_tar) \
    X(archive_read_support_format_zip) X(archive_read_support_format_raw) \
    X(archive_read_support_format_empty) X(archive_read_open) X(archive_read_next_header) \
    X(archive_entry_pathname) X(archive_entry_filetype) X(archive_read_data) X(archive_read_free) \
    X(archive_error_string) X(archive_format) X(archive_version_string) \
    X(EVP_md5) X(EVP_MD_CTX_new) X(EVP_DigestInit_ex) X(EVP_DigestUpdate) \
    X(EVP_DigestFinal_ex) X(EVP_MD_CTX_free) X(OpenSSL_version)
#define X(n) extern void n(void);
LIBSYMS(X)
#undef X
static void *find_sym(void *handle, const char *name)
{
    (void)handle;
    static const struct { const char *name; void (*fn)(void); } table[] = {
#define X(n) { #n, n },
        LIBSYMS(X)
#undef X
    };
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (!strcmp(table[i].name, name)) return (void *)(uintptr_t)table[i].fn;
    return NULL;
}
static void *open_first(const char *const *names, char *found, size_t foundlen)
{
    (void)names;
    snprintf(found, foundlen, "built in");
    return &L;
}
#else
static void *find_sym(void *handle, const char *name) { return dlsym(handle, name); }
static void *open_first(const char *const *names, char *found, size_t foundlen)
{
    const char *dir = getenv("CHDSWEEP_NO_OPTIONAL_LIBS");   /* for tests: behave as if missing */
    if (dir && *dir) return NULL;
    for (int i = 0; names[i]; i++) {
        void *h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
        if (h) { snprintf(found, foundlen, "%s", names[i]); return h; }
    }
    return NULL;
}
#endif

static const char *const archive_names[] = { "libarchive.so.13", NULL };
static const char *const crypto_names[] = { "libcrypto.so.3", "libcrypto.so.1.1", NULL };

#define SYM(handle, field, name) \
    do { *(void **)&L.field = find_sym(handle, name); if (!L.field) ok = 0; } while (0)

void libs_load(void)
{
    memset(&L, 0, sizeof L);

    void *a = open_first(archive_names, L.archive_name, sizeof L.archive_name);
    if (a) {
        int ok = 1;
        SYM(a, a_read_new, "archive_read_new");
        SYM(a, a_support_filter_gzip, "archive_read_support_filter_gzip");
        SYM(a, a_support_format_tar, "archive_read_support_format_tar");
        SYM(a, a_support_format_zip, "archive_read_support_format_zip");
        SYM(a, a_support_format_raw, "archive_read_support_format_raw");
        SYM(a, a_support_format_empty, "archive_read_support_format_empty");
        SYM(a, a_read_open, "archive_read_open");
        SYM(a, a_next_header, "archive_read_next_header");
        SYM(a, a_entry_pathname, "archive_entry_pathname");
        SYM(a, a_entry_filetype, "archive_entry_filetype");
        SYM(a, a_read_data, "archive_read_data");
        SYM(a, a_read_free, "archive_read_free");
        SYM(a, a_error_string, "archive_error_string");
        SYM(a, a_format, "archive_format");
        const char *(*ver)(void) = NULL;
        *(void **)&ver = find_sym(a, "archive_version_string");
        if (ver) snprintf(L.archive_version, sizeof L.archive_version, "%s", ver());
        L.have_archive = ok;
    }

    void *c = open_first(crypto_names, L.crypto_name, sizeof L.crypto_name);
    if (c) {
        int ok = 1;
        SYM(c, c_md5, "EVP_md5");
        SYM(c, c_ctx_new, "EVP_MD_CTX_new");
        SYM(c, c_init, "EVP_DigestInit_ex");
        SYM(c, c_update, "EVP_DigestUpdate");
        SYM(c, c_final, "EVP_DigestFinal_ex");
        SYM(c, c_ctx_free, "EVP_MD_CTX_free");
        const char *(*ver)(int) = NULL;
        *(void **)&ver = find_sym(c, "OpenSSL_version");
        if (ver) snprintf(L.crypto_version, sizeof L.crypto_version, "%s", ver(0));
        L.have_crypto = ok;
    }
}

/* Distribution family from /etc/os-release: 'd'ebian, 'r'hel, 's'use, 'a'lpine, or 0. */
static int os_family(void)
{
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return 0;
    char line[512];
    int fam = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "ID=", 3) && strncmp(line, "ID_LIKE=", 8)) continue;
        if (strstr(line, "debian") || strstr(line, "ubuntu")) fam = 'd';
        else if (strstr(line, "rhel") || strstr(line, "fedora") || strstr(line, "centos") ||
                 strstr(line, "rocky") || strstr(line, "alma")) fam = 'r';
        else if (strstr(line, "suse")) fam = 's';
        else if (strstr(line, "alpine")) fam = 'a';
        if (fam) break;
    }
    fclose(f);
    return fam;
}

void libs_missing_message(const char *which, struct strbuf *out)
{
    int archive = !strcmp(which, "archive");
    static const struct { int fam; const char *a, *c, *who; } fix[] = {
        { 'd', "apt install libarchive13", "apt install libssl3", "Debian, Ubuntu" },
        { 'r', "dnf install libarchive", "dnf install openssl-libs", "RHEL, Rocky, Alma, Fedora" },
        { 's', "zypper install libarchive13", "zypper install libopenssl3", "SUSE" },
        { 'a', "apk add libarchive", "apk add libcrypto3", "Alpine" },
    };
    if (archive)
        sb_add(out, "chdsweep: libarchive not found (tried libarchive.so.13).\n"
                    "  Effect: archives (tar, zip, gz members) will be listed as not scanned.\n");
    else
        sb_add(out, "chdsweep: libcrypto not found (tried libcrypto.so.3, libcrypto.so.1.1).\n"
                    "  Effect: the package-file rule is off.\n");
    int fam = os_family(), first = 1;
    for (size_t i = 0; i < sizeof fix / sizeof fix[0]; i++) {
        if (fam && fix[i].fam != fam) continue;   /* known family: only its line */
        sb_printf(out, "  %s %-32s (%s)\n", first ? "Fix:   " : "       ",
                  archive ? fix[i].a : fix[i].c, fix[i].who);
        first = 0;
    }
    sb_add(out, "  Or:     use the static build of chdsweep, which needs no libraries.\n");
}

int cmd_check(void)
{
    libs_load();
    printf("chdsweep %s library check\n\n", CHD_VERSION);
    printf("  libarchive  %-8s %s\n              needed for: tar, zip and gz archives, office documents\n",
           L.have_archive ? "found" : "MISSING", L.have_archive ? L.archive_version : "");
    printf("  libcrypto   %-8s %s\n              needed for: package-file rule\n",
           L.have_crypto ? "found" : "MISSING", L.have_crypto ? L.crypto_version : "");
    struct strbuf b = { 0 };
    if (!L.have_archive) { sb_add(&b, "\n"); libs_missing_message("archive", &b); }
    if (!L.have_crypto) { sb_add(&b, "\n"); libs_missing_message("crypto", &b); }
    if (b.len) fputs(b.s, stdout);
    else puts("\nAll libraries present.");
    sb_free(&b);
    return (L.have_archive && L.have_crypto) ? 0 : 1;
}
