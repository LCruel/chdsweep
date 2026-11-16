/* chdsweep: libarchive and libcrypto are loaded at run time, so a missing one
 * gives a clear message and a partial scan instead of a loader error. */
#include "chdsweep.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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
        /* In FIPS mode libcrypto is there but refuses MD5, and with it the package-file rule. */
        void *ctx = ok ? L.c_ctx_new() : NULL;
        L.md5_ok = ctx && L.c_init(ctx, L.c_md5(), NULL) == 1;
        if (ctx) L.c_ctx_free(ctx);
        const char *no = getenv("CHDSWEEP_NO_MD5");   /* for tests: behave as if refused */
        if (no && *no) L.md5_ok = 0;
    }

    pdf_probe();
}

/* The distribution, from /etc/os-release: family 'd'ebian, 'r'hel, 's'use, 'a'lpine or 0,
 * its own ID and the major version (0: not given, as on a rolling release). */
struct os { int fam; char id[32]; int major; };

static struct os os_info(void)
{
    struct os o = { 0 };
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return o;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        const char *v = strchr(line, '=');
        if (!v) continue;
        v++;
        if (*v == '"' || *v == '\'') v++;
        if (!strncmp(line, "VERSION_ID=", 11)) o.major = atoi(v);
        if (!strncmp(line, "ID=", 3)) snprintf(o.id, sizeof o.id, "%.*s", (int)strcspn(v, "\"'\n"), v);
        if (o.fam || (strncmp(line, "ID=", 3) && strncmp(line, "ID_LIKE=", 8))) continue;
        if (strstr(line, "debian") || strstr(line, "ubuntu")) o.fam = 'd';
        else if (strstr(line, "rhel") || strstr(line, "fedora") || strstr(line, "centos") ||
                 strstr(line, "rocky") || strstr(line, "alma")) o.fam = 'r';
        else if (strstr(line, "suse")) o.fam = 's';
        else if (strstr(line, "alpine")) o.fam = 'a';
    }
    fclose(f);
    return o;
}

void libs_missing_message(const char *which, struct strbuf *out)
{
    int archive = !strcmp(which, "archive"), pdf = !strcmp(which, "pdftotext");
    struct os os = os_info();
    /* The package with libcrypto is libssl1.1 up to Debian 11 and Ubuntu 20.04, libssl3 after. */
    const char *dssl = "apt install libssl3", *dwho = "Debian, Ubuntu";
    if ((!strcmp(os.id, "debian") && os.major && os.major < 12) ||
        (!strcmp(os.id, "ubuntu") && os.major && os.major < 22))
        dssl = "apt install libssl1.1";
    else if (strcmp(os.id, "debian") && strcmp(os.id, "ubuntu"))
        dwho = "Debian, Ubuntu; libssl1.1 on Debian 11, Ubuntu 20.04 and older";
    const struct { int fam; const char *a, *c, *p, *who; } fix[] = {
        { 'd', "apt install libarchive13", dssl, "apt install poppler-utils", archive || pdf ? "Debian, Ubuntu" : dwho },
        { 'r', "dnf install libarchive", "dnf install openssl-libs", "dnf install poppler-utils", "RHEL, Rocky, Alma, Fedora" },
        { 's', "zypper install libarchive13", "zypper install libopenssl3", "zypper install poppler-tools", "SUSE" },
        { 'a', "apk add libarchive", "apk add libcrypto3", "apk add poppler-utils", "Alpine" },
    };
    if (archive)
        sb_add(out, "chdsweep: libarchive not found (tried libarchive.so.13).\n"
                    "  Effect: archives (tar, zip, gz members) will be listed as not scanned.\n");
    else if (pdf)
        sb_add(out, "chdsweep: pdftotext not found (looked in PATH, /usr/bin, /usr/local/bin, /bin).\n"
                    "  Effect: the text inside PDF files is not read; each PDF will be listed as not fully scanned.\n");
    else
        sb_add(out, "chdsweep: libcrypto not found (tried libcrypto.so.3, libcrypto.so.1.1).\n"
                    "  Effect: the package-file rule is off. Numbers in unchanged package files are listed\n"
                    "          as suspected PANs, not as likely false positives. Nothing is left unscanned.\n");
    int first = 1;
    for (size_t i = 0; i < sizeof fix / sizeof fix[0]; i++) {
        if (os.fam && fix[i].fam != os.fam) continue;   /* known family: only its line */
        sb_printf(out, "  %s %-32s (%s)\n", first ? "Fix:   " : "       ",
                  archive ? fix[i].a : pdf ? fix[i].p : fix[i].c, fix[i].who);
        first = 0;
    }
    /* pdftotext is a program of its own: no build of chdsweep has it built in. */
    if (pdf) sb_add(out, "  Or:     set pdf_text = no, to leave PDF text out on purpose.\n");
    else sb_add(out, "  Or:     use the static build of chdsweep, which needs no libraries.\n");
}

int find_program(const char *name, char *path, size_t pathlen)
{
    const char *env = getenv("PATH");
    struct strbuf dirs = { 0 };
    sb_add(&dirs, env && *env ? env : "");
    sb_add(&dirs, ":/usr/bin:/usr/local/bin:/bin");   /* cron starts with a short PATH */
    int found = 0;
    for (char *save = NULL, *d = strtok_r(dirs.s, ":", &save); d && !found; d = strtok_r(NULL, ":", &save)) {
        struct stat st;
        if (d[0] != '/') continue;                  /* never the current folder */
        snprintf(path, pathlen, "%s/%s", d, name);
        found = stat(path, &st) == 0 && S_ISREG(st.st_mode) && access(path, X_OK) == 0;
    }
    sb_free(&dirs);
    if (!found && pathlen) path[0] = 0;
    return found;
}

int find_journalctl(char *path, size_t pathlen)
{
    const char *no = getenv("CHDSWEEP_NO_JOURNALCTL");   /* for tests: a host without systemd */
    if (no && *no) { if (pathlen) path[0] = 0; return 0; }
    return find_program("journalctl", path, pathlen);
}

int pkgrule_state(void)
{
    char dir[4096];
    if (!pkgdb_present(dir, sizeof dir)) return PKG_NO_DB;
    if (!L.have_crypto) return PKG_NO_CRYPTO;
    return L.md5_ok ? PKG_OK : PKG_NO_MD5;
}

void pkgrule_message(int state, struct strbuf *out)
{
    static const char effect[] =
        "  Effect: numbers in unchanged package files are listed as suspected PANs, not as likely\n"
        "          false positives. Nothing is left unscanned.\n";
    char dir[4096];
    if (state == PKG_NO_CRYPTO) libs_missing_message("crypto", out);
    else if (state == PKG_NO_DB) {
        pkgdb_present(dir, sizeof dir);
        int rpm = access("/var/lib/rpm", F_OK) == 0 || access("/usr/lib/sysimage/rpm", F_OK) == 0;
        sb_printf(out, "chdsweep: the package-file rule is off: no dpkg package database on this host\n"
                       "  (looked in %s).\n", dir);
        sb_add(out, effect);
        sb_add(out, rpm ? "  Reason: this host uses rpm packages, which chdsweep does not read yet.\n"
                        : "  Reason: chdsweep reads the package database of dpkg (Debian, Ubuntu) only.\n");
        sb_add(out, "  Fix:    none needed.\n");
    } else if (state == PKG_NO_MD5) {
        sb_printf(out, "chdsweep: the package-file rule is off: OpenSSL on this host (%s)\n"
                       "  does not allow MD5, which the rule needs to compare a file with its package.\n",
                  L.crypto_version[0] ? L.crypto_version : L.crypto_name);
        sb_add(out, effect);
        sb_add(out, "  Reason: usually FIPS mode, which switches MD5 off for the whole host.\n"
                    "  Fix:    none needed.\n");
    }
}

void not_root_message(struct strbuf *out)
{
    sb_printf(out, "chdsweep: not running as root (user id %u).\n"
                   "  Effect: files and folders this user may not read will be listed as not scanned.\n"
                   "  Fix:    run chdsweep as root, for example with sudo.\n", (unsigned)geteuid());
}

void no_journal_message(int asked_for, struct strbuf *out)
{
    sb_add(out, "chdsweep: the system journal is not scanned: journalctl was not found, so this host\n"
                "  has no systemd journal.\n"
                "  Effect: none. There is no journal to scan; the logs under /var/log are scanned as files.\n");
    if (asked_for) sb_add(out, "  Fix:    set journal_days = 0 to stop this notice.\n");
}

int cmd_check(void)
{
    char prog[4096], dir[4096];
    libs_load();
    int journal = find_journalctl(prog, sizeof prog);
    int pkg = pkgrule_state();
    int root = geteuid() == 0;
    pkgdb_present(dir, sizeof dir);

    printf("chdsweep %s check of this host\n\n", CHD_VERSION);
    printf("  libarchive  %-9s %s\n              needed for: tar, zip and gz archives, office documents\n",
           L.have_archive ? "found" : "MISSING", L.have_archive ? L.archive_version : "");
    printf("  libcrypto   %-9s %s\n              needed for: package-file rule\n",
           L.have_crypto ? "found" : "MISSING", L.have_crypto ? L.crypto_version : "");
    if (L.have_crypto && !L.md5_ok)
        printf("  MD5         refused   by OpenSSL on this host\n              needed for: package-file rule\n");
    printf("  dpkg data   %-9s %s\n              needed for: package-file rule\n",
           pkg == PKG_NO_DB ? "not found" : "found", dir);
    printf("  pdftotext   %-9s %s\n              needed for: text inside PDF files (a program, from poppler-utils)\n",
           PDF.have ? "found" : "MISSING", PDF.have ? PDF.version : "");
    printf("  journalctl  %-9s %s\n              needed for: the system journal (journal_days)\n",
           journal ? "found" : "not found", prog);
    printf("  user        %s\n              needed for: reading every file\n", root ? "root" : "not root");

    struct strbuf b = { 0 };
    if (!L.have_archive) { sb_add(&b, "\n"); libs_missing_message("archive", &b); }
    if (pkg != PKG_OK) { sb_add(&b, "\n"); pkgrule_message(pkg, &b); }
    if (!PDF.have) { sb_add(&b, "\n"); libs_missing_message("pdftotext", &b); }
    if (!journal) { sb_add(&b, "\n"); no_journal_message(0, &b); }
    if (!root) { sb_add(&b, "\n"); not_root_message(&b); }
    if (b.len) fputs(b.s, stdout);
    else puts("\nEverything a full scan needs is there.");
    sb_free(&b);
    /* The exit code is about what can be installed: the two libraries and pdftotext. */
    return (L.have_archive && L.have_crypto && PDF.have) ? 0 : 1;
}
