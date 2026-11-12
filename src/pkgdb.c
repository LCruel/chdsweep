/* chdsweep: package-file rule. Is this file an unchanged file of an installed package?
 * dpkg only for now (/var/lib/dpkg/info/<package>.md5sums); rpm is still to do.
 * The index is loaded once, the first time a file with a hit asks for it. */
#include "chdsweep.h"

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entry { char *path; char md5[33]; const char *pkg; };

static struct entry *table;
static size_t table_cap, table_n;
static pthread_once_t once = PTHREAD_ONCE_INIT;

static struct entry *slot(const char *path)
{
    size_t i = (size_t)fnv1a64(path, strlen(path), 0) & (table_cap - 1);
    while (table[i].path && strcmp(table[i].path, path)) i = (i + 1) & (table_cap - 1);
    return &table[i];
}

static void grow(void)
{
    struct entry *old = table;
    size_t oldcap = table_cap;
    table_cap = table_cap ? table_cap * 2 : 1 << 16;
    table = xmalloc(table_cap * sizeof *table);
    memset(table, 0, table_cap * sizeof *table);
    for (size_t i = 0; i < oldcap; i++)
        if (old[i].path) *slot(old[i].path) = old[i];
    free(old);
}

static void load(void)
{
    const char *dir = getenv("CHDSWEEP_DPKG_INFO");   /* for tests */
    if (!dir || !*dir) dir = "/var/lib/dpkg/info";
    DIR *d = opendir(dir);
    if (!d) return;
    grow();
    struct dirent *de;
    char file[4096], line[8192];
    while ((de = readdir(d))) {
        size_t nl = strlen(de->d_name);
        if (nl < 9 || strcmp(de->d_name + nl - 8, ".md5sums")) continue;
        snprintf(file, sizeof file, "%s/%s", dir, de->d_name);
        FILE *f = fopen(file, "r");
        if (!f) continue;
        char *pkg = xstrdup(de->d_name);
        pkg[nl - 8] = 0;
        char *colon = strchr(pkg, ':');   /* "libfoo:amd64" */
        if (colon) *colon = 0;
        int used = 0;
        while (fgets(line, sizeof line, f)) {
            size_t ll = strlen(line);
            while (ll && (line[ll - 1] == '\n' || line[ll - 1] == '\r')) line[--ll] = 0;
            if (ll < 35 || line[32] != ' ') continue;
            char path[8192];
            snprintf(path, sizeof path, "/%s", line + 34);
            if ((table_n + 1) * 2 > table_cap) grow();
            struct entry *e = slot(path);
            if (e->path) continue;
            e->path = xstrdup(path);
            memcpy(e->md5, line, 32);
            e->md5[32] = 0;
            e->pkg = pkg;
            table_n++;
            used = 1;
        }
        if (!used) free(pkg);
        fclose(f);
    }
    closedir(d);
}

static int file_md5(int dirfd, const char *name, char hex[33])
{
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    void *ctx = L.c_ctx_new();
    unsigned char buf[65536], md[64];
    unsigned mdlen = 0;
    ssize_t r = -1;
    if (ctx && L.c_init(ctx, L.c_md5(), NULL) == 1) {
        while ((r = read(fd, buf, sizeof buf)) > 0) L.c_update(ctx, buf, (size_t)r);
        if (r == 0 && L.c_final(ctx, md, &mdlen) != 1) r = -1;
    }
    if (ctx) L.c_ctx_free(ctx);
    close(fd);
    if (r != 0 || mdlen != 16) return -1;
    for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", md[i]);
    return 0;
}

int pkgdb_unchanged(int dirfd, const char *name, const char *path, char *pkg, size_t pkglen)
{
    if (!L.have_crypto) return 0;
    pthread_once(&once, load);
    if (!table_n) return 0;
    const struct entry *e = slot(path);
    /* On a merged-/usr system dpkg lists /bin/x for what the walk sees as /usr/bin/x. */
    if (!e->path && !strncmp(path, "/usr/", 5)) e = slot(path + 4);
    if (!e->path) return 0;
    char hex[33];
    if (file_md5(dirfd, name, hex) || strcmp(hex, e->md5)) return 0;
    snprintf(pkg, pkglen, "%s", e->pkg);
    return 1;
}
