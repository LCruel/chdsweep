/* chdsweep: one scan run. Walker, worker pool, archives and limits, run file. */
#include "chdsweep.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define LA_BUF 65536
#define ARCHIVE_EOF 1
#define ARCHIVE_WARN (-20)
#define ARCHIVE_FORMAT_RAW 0x90000
#define AE_IFREG 0100000u

struct counters {
    uint64_t files, bytes, dirs, hits_open, hits_marked, skipped, symlinks, other_fs,
             excluded, special, archives, members, unlisted, pdfs;
    uint64_t by_rule[R_COUNT];
};

struct worker {
    int id;
    pthread_t th;
    struct counters c;
    unsigned char *buf;
    struct strbuf sb;
    struct scan_result res;
    pthread_mutex_t mu;      /* guards cur, read by the progress thread */
    char cur[160];
    struct strlist not_entered;   /* mount points of other file systems, the first few */
};

struct qnode { struct qnode *next; dev_t dev; int is_file; char path[]; };

/* One top-level file, with the limits that count over everything inside it. */
struct filectx {
    struct worker *w;
    const char *path, *name;
    int dirfd;
    struct stat st;
    uint64_t unpacked;
    uint64_t listed, unlisted;   /* hits written to the run file, and hits over max_hits_per_file */
    double deadline;
    const char *limit;       /* set when a limit stopped the scan of this file */
    int pkg_state;           /* 0 not asked, 1 unchanged package file, -1 not */
    char pkg[128];
    const struct pdf_run *pdf;   /* set while the text of a PDF is scanned: hits get their page */
};

struct source {
    struct filectx *fc;
    int fd;                  /* plain file, or -1 */
    void *ar;                /* archive this member is read from, or NULL */
    unsigned char peek[512];
    size_t peek_len, peek_pos;
    int tee, tee_fd;         /* tee: what is read is also copied to tee_fd (a PDF inside an archive) */
    int tee_over;            /* 1: larger than max_pdf_size, 2: the copy could not be written */
    uint64_t tee_len;
};

static const struct config *cfg;
static struct rules rules;

static FILE *out;
static pthread_mutex_t out_mu = PTHREAD_MUTEX_INITIALIZER;
static int out_failed;

static pthread_mutex_t q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_cv = PTHREAD_COND_INITIALIZER;
static struct qnode *q_head;
static int q_active, q_done;
static volatile sig_atomic_t g_stop;
static struct strlist roots;     /* the paths of this run, resolved; set before the workers start */

static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ---- run file ---- */

static void out_line(struct strbuf *b)
{
    pthread_mutex_lock(&out_mu);
    /* Flushed per file: a run that is killed keeps what it found, and a long run can be followed. */
    if (fwrite(b->s, 1, b->len, out) != b->len || fflush(out) != 0) out_failed = 1;
    pthread_mutex_unlock(&out_mu);
}

static void emit_skip(struct worker *w, const char *path, const char *member, const char *reason)
{
    struct strbuf *b = &w->sb;
    sb_reset(b);
    sb_add(b, "{\"type\":\"skip\",\"path\":");
    sb_json_str(b, path);
    if (member) { sb_add(b, ",\"member\":"); sb_json_str(b, member); }
    sb_add(b, ",\"reason\":");
    sb_json_str(b, reason);
    sb_add(b, "}\n");
    out_line(b);
    w->c.skipped++;
}

/* A PDF whose text was read in part: the page counts go with the reason. */
static void emit_skip_pages(struct worker *w, const char *path, const char *member, const char *reason,
                            long pages, long without_text)
{
    struct strbuf *b = &w->sb;
    sb_reset(b);
    sb_add(b, "{\"type\":\"skip\",\"path\":");
    sb_json_str(b, path);
    if (member) { sb_add(b, ",\"member\":"); sb_json_str(b, member); }
    sb_add(b, ",\"reason\":");
    sb_json_str(b, reason);
    sb_printf(b, ",\"pages_read\":%ld,\"pages_without_text\":%ld}\n", pages, without_text);
    out_line(b);
    w->c.skipped++;
}

/* A file with more hits than max_hits_per_file: read to the end, the rest counted only. */
static void emit_unlisted(struct filectx *fc)
{
    struct worker *w = fc->w;
    struct strbuf *b = &w->sb;
    if (!fc->unlisted) return;
    sb_reset(b);
    sb_add(b, "{\"type\":\"skip\",\"path\":");
    sb_json_str(b, fc->path);
    sb_printf(b, ",\"reason\":\"not fully listed: more hits than max_hits_per_file\",\"hits_not_listed\":%llu}\n",
              (unsigned long long)fc->unlisted);
    out_line(b);
    w->c.skipped++;
    w->c.unlisted += fc->unlisted;
}

static void emit_hits(struct filectx *fc, const char *member, struct scan_result *res)
{
    struct worker *w = fc->w;
    if (!res->n) return;
    if (rules.on[R_PACKAGE_FILE] && fc->pkg_state == 0)
        fc->pkg_state = pkgdb_unchanged(fc->dirfd, fc->name, fc->path, fc->pkg, sizeof fc->pkg) ? 1 : -1;
    const char *pkg = fc->pkg_state == 1 ? fc->pkg : NULL;
    rules_finalize(&rules, fc->path, member, pkg, res);

    char mtime[24], ctime_s[24], reason[256];
    iso_time(fc->st.st_mtime, mtime);
    iso_time(fc->st.st_ctime, ctime_s);
    struct strbuf *b = &w->sb;
    sb_reset(b);
    for (size_t i = 0; i < res->n; i++) {
        const struct hit *h = &res->hits[i];
        sb_add(b, "{\"type\":\"hit\",\"path\":");
        sb_json_str(b, fc->path);
        if (member) { sb_add(b, ",\"member\":"); sb_json_str(b, member); }
        sb_printf(b, ",\"brand\":\"%s\",\"masked\":\"%s\",\"digits\":%d,\"offset\":%llu,\"track\":%d",
                  h->brand, h->masked, h->ndigits, (unsigned long long)h->offset, h->track);
        if (fc->pdf) sb_printf(b, ",\"page\":%ld", pdf_page_of(fc->pdf, h->offset));
        sb_printf(b, ",\"mtime\":\"%s\",\"ctime\":\"%s\",\"marks\":[", mtime, ctime_s);
        int first = 1;
        for (int r = 0; r < R_COUNT; r++) {
            if (!(h->marks & (1u << r))) continue;
            mark_reason(r, h, res, pkg, reason, sizeof reason);
            sb_printf(b, "%s{\"rule\":\"%s\",\"reason\":", first ? "" : ",", rule_names[r]);
            sb_json_str(b, reason);
            sb_add(b, "}");
            first = 0;
            w->c.by_rule[r]++;
        }
        sb_add(b, "]");
        sb_add(b, "}\n");
        if (h->marks) w->c.hits_marked++; else w->c.hits_open++;
    }
    out_line(b);
}

/* ---- reading: plain files and archive members, with the limits ---- */

/* max_read_rate: all workers together read at most this many bytes per second from disk.
 * Returns the seconds slept, so the caller can leave them out of the time limit. */
static pthread_mutex_t rate_mu = PTHREAD_MUTEX_INITIALIZER;
static double rate_next;         /* when the bytes read so far are paid for */

static double throttle(size_t n)
{
    pthread_mutex_lock(&rate_mu);
    double now = now_seconds();
    if (rate_next < now) rate_next = now;
    rate_next += (double)n / (double)cfg->max_read_rate;
    double wait = rate_next - now;
    pthread_mutex_unlock(&rate_mu);
    if (wait < 0.01) return 0;
    double left = wait;
    while (left > 0 && !g_stop) {    /* in short steps, so Ctrl-C is not held up */
        double step = left > 0.2 ? 0.2 : left;
        usleep((useconds_t)(step * 1e6));
        left -= step;
    }
    return wait - (left > 0 ? left : 0);
}

static ssize_t src_raw(struct source *s, void *buf, size_t n)
{
    struct filectx *fc = s->fc;
    if (fc->limit || g_stop) return 0;
    ssize_t r;
    if (s->ar) r = L.a_read_data(s->ar, buf, n);
    else do r = read(s->fd, buf, n); while (r < 0 && errno == EINTR);
    if (r < 0) return -1;
    if (!s->ar && r > 0 && cfg->max_read_rate) fc->deadline += throttle((size_t)r);
    if (s->ar) {
        fc->unpacked += (uint64_t)r;
        if (fc->unpacked > cfg->max_unpacked)
            fc->limit = "not fully scanned: unpacked size over max_unpacked";
        else if (fc->unpacked > (16u << 20) &&
                 fc->unpacked / (uint64_t)(fc->st.st_size > 0 ? fc->st.st_size : 1) > (uint64_t)cfg->max_ratio)
            fc->limit = "not fully scanned: compression ratio over max_ratio";
    }
    if (cfg->max_file_seconds && now_seconds() > fc->deadline)
        fc->limit = "not fully scanned: time limit max_file_seconds reached";
    return r;
}

/* The copy of a PDF that cannot be read twice, for pdftotext. It stops at max_pdf_size. */
static void tee_write(struct source *s, const char *buf, size_t n)
{
    if (s->tee_over) return;
    if (cfg->max_pdf_size && s->tee_len + n > cfg->max_pdf_size) { s->tee_over = 1; return; }
    while (n) {
        ssize_t k = write(s->tee_fd, buf, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) { s->tee_over = 2; return; }
        buf += k;
        n -= (size_t)k;
        s->tee_len += (uint64_t)k;
    }
}

static ssize_t src_read(void *cookie, void *buf, size_t n)
{
    struct source *s = cookie;
    ssize_t r;
    if (s->peek_pos < s->peek_len) {
        size_t k = s->peek_len - s->peek_pos;
        if (k > n) k = n;
        memcpy(buf, s->peek + s->peek_pos, k);
        s->peek_pos += k;
        r = (ssize_t)k;
    } else r = src_raw(s, buf, n);
    if (r > 0 && s->tee) tee_write(s, buf, (size_t)r);
    return r;
}

static int src_sniff(struct source *s)
{
    while (s->peek_len < sizeof s->peek) {
        ssize_t r = src_raw(s, s->peek + s->peek_len, sizeof s->peek - s->peek_len);
        if (r < 0) return -1;
        if (r == 0) break;
        s->peek_len += (size_t)r;
    }
    return 0;
}

static int is_archive(const unsigned char *p, size_t n)
{
    if (n >= 2 && p[0] == 0x1f && p[1] == 0x8b) return 1;                                  /* gzip */
    if (n >= 4 && p[0] == 'P' && p[1] == 'K' && ((p[2] == 3 && p[3] == 4) || (p[2] == 5 && p[3] == 6)))
        return 1;                                                                          /* zip */
    if (n >= 262 && memcmp(p + 257, "ustar", 5) == 0) return 1;                            /* tar */
    return 0;
}

struct la_cookie { struct source *src; unsigned char *buf; };

static ssize_t la_read_cb(void *a, void *client, const void **outp)
{
    (void)a;
    struct la_cookie *c = client;
    *outp = c->buf;
    return src_read(c->src, c->buf, LA_BUF);
}

static void scan_source(struct filectx *fc, struct source *src, const char *member, int depth);

static void scan_archive(struct filectx *fc, struct source *src, const char *member, int depth)
{
    struct worker *w = fc->w;
    struct la_cookie ck = { src, xmalloc(LA_BUF) };
    struct strbuf name = { 0 };
    char reason[400];
    void *a = L.a_read_new();
    /* Only what is_archive() lets in: gzip, tar, zip. With every format switched on,
     * libarchive takes the text inside a .csv.gz for an mtree file and fails on it. */
    L.a_support_filter_gzip(a);
    L.a_support_format_tar(a);
    L.a_support_format_zip(a);
    L.a_support_format_raw(a);
    L.a_support_format_empty(a);
    w->c.archives++;

    int r = L.a_read_open(a, &ck, NULL, la_read_cb, NULL);
    long members = 0;
    while (r >= ARCHIVE_WARN && !fc->limit && !g_stop) {
        void *entry = NULL;
        r = L.a_next_header(a, &entry);
        if (r == ARCHIVE_EOF || r < ARCHIVE_WARN) break;
        if (++members > cfg->max_members) {
            fc->limit = "not fully scanned: more members than max_members";
            break;
        }
        int raw = L.a_format(a) == ARCHIVE_FORMAT_RAW;
        if (!raw && L.a_entry_filetype(entry) != AE_IFREG) continue;
        const char *en = raw ? "(content)" : L.a_entry_pathname(entry);
        sb_reset(&name);
        if (member) { sb_add(&name, member); sb_add(&name, "!"); }
        sb_add(&name, en ? en : "?");
        w->c.members++;
        struct source child = { .fc = fc, .fd = -1, .ar = a };
        scan_source(fc, &child, name.s, depth + 1);
    }
    if (r < ARCHIVE_WARN && r != ARCHIVE_EOF && !fc->limit && !g_stop) {
        const char *e = L.a_error_string(a);
        snprintf(reason, sizeof reason, "not fully scanned: archive unreadable (%s)", e ? e : "unknown error");
        emit_skip(w, fc->path, member, reason);
    }
    L.a_read_free(a);
    sb_free(&name);
    free(ck.buf);
}

/* One stream through the matcher: the bytes of a file or member, or the text of a PDF.
 * Returns what scan_stream returns: -1 when reading failed. */
static int scan_bytes(struct filectx *fc, scan_read_fn rd, void *cookie, const char *member)
{
    struct worker *w = fc->w;
    struct scan_opts o = {
        .rules = &rules, .keep_leading = cfg->keep_leading, .buf = w->buf, .pdf_text = fc->pdf != NULL,
    };
    if (cfg->max_hits_per_file) {   /* counted over the whole file, archive members included */
        uint64_t max = (uint64_t)cfg->max_hits_per_file;
        o.hit_limit = 1;
        o.hit_room = fc->listed < max ? (size_t)(max - fc->listed) : 0;
    }
    scan_result_reset(&w->res);
    int rc = scan_stream(&o, rd, cookie, &w->res);
    w->c.bytes += w->res.bytes;
    fc->listed += w->res.n;
    fc->unlisted += w->res.dropped;
    emit_hits(fc, member, &w->res);
    return rc;
}

/* ---- PDF: the bytes as for any file, then the text from pdftotext ---- */

static int is_pdf(const unsigned char *p, size_t n)
{
    if (n >= 3 && p[0] == 0xef && p[1] == 0xbb && p[2] == 0xbf) { p += 3; n -= 3; }   /* byte order mark */
    return n >= 5 && memcmp(p, "%PDF-", 5) == 0;
}

/* A file in memory, never on disk: a copy of a PDF may hold card numbers. */
static int mem_file(void)
{
#ifdef SYS_memfd_create
    return (int)syscall(SYS_memfd_create, "chdsweep-pdf", 1u /* MFD_CLOEXEC */);
#else
    errno = ENOSYS;
    return -1;
#endif
}

#define PDF_NOT_READ "not fully scanned: PDF text not read, "

static void scan_pdf_text(struct filectx *fc, int fd, const char *member)
{
    struct worker *w = fc->w;
    struct pdf_run p;
    char reason[160];
    if (pdf_start(&p, fd, cfg->max_pdf_pages, cfg->max_pdf_memory, cfg->max_file_seconds,
                  cfg->max_file_seconds ? fc->deadline : 0, &g_stop) < 0) {
        emit_skip(w, fc->path, member, PDF_NOT_READ "pdftotext could not be started");
        return;
    }
    struct strbuf name = { 0 };
    if (member) { sb_add(&name, member); sb_add(&name, "!"); }
    sb_add(&name, "(PDF text)");
    fc->pdf = &p;
    int rc = scan_bytes(fc, pdf_read, &p, name.s);
    fc->pdf = NULL;
    sb_free(&name);

    int res = pdf_finish(&p);
    if (rc < 0 && res == PDF_OK) res = PDF_BROKEN;
    switch (res) {
    case PDF_STOPPED:
        break;
    case PDF_TIMEOUT:       /* listed once for the whole file, like every limit */
        fc->limit = "not fully scanned: time limit max_file_seconds reached";
        break;
    case PDF_PASSWORD:
        emit_skip(w, fc->path, member, PDF_NOT_READ "password protected");
        break;
    case PDF_NO_COPY:
        emit_skip(w, fc->path, member, PDF_NOT_READ "the document does not allow its text to be copied");
        break;
    case PDF_NOT_STARTED:
        emit_skip(w, fc->path, member, PDF_NOT_READ "pdftotext could not be started");
        break;
    case PDF_SIGNAL:
        snprintf(reason, sizeof reason, PDF_NOT_READ "pdftotext was stopped by signal %d", p.code);
        emit_skip(w, fc->path, member, reason);
        break;
    case PDF_BROKEN:
        snprintf(reason, sizeof reason, PDF_NOT_READ "pdftotext could not read the file (exit %d)", p.code);
        emit_skip(w, fc->path, member, reason);
        break;
    default:
        w->c.pdfs++;
        if (p.more_pages)
            emit_skip_pages(w, fc->path, member, "not fully scanned: PDF text, more pages than max_pdf_pages",
                            p.pages, p.empty);
        if (p.empty == p.pages)
            emit_skip_pages(w, fc->path, member, "not fully scanned: PDF has no text (images only, or empty pages)",
                            p.pages, p.empty);
        else if (p.empty)
            emit_skip_pages(w, fc->path, member, "not fully scanned: PDF text, some pages have no text "
                                                 "(images only, or empty pages)", p.pages, p.empty);
    }
    pdf_free(&p);
}

static void scan_pdf(struct filectx *fc, struct source *src, const char *member, int depth)
{
    struct worker *w = fc->w;
    struct stat st;
    /* A plain file is opened by pdftotext itself. Anything else can be read only once,
     * so it is copied to a file in memory while its bytes are scanned. */
    int plain = !src->ar && src->fd >= 0 && fstat(src->fd, &st) == 0 && S_ISREG(st.st_mode);
    const char *why = NULL;      /* why the text will not be read */
    int fd = -1;
    if (!cfg->pdf_text) why = PDF_NOT_READ "pdf_text is off";
    else if (!PDF.have) why = PDF_NOT_READ "pdftotext not available";
    else if (plain) {
        if (cfg->max_pdf_size && (uint64_t)st.st_size > cfg->max_pdf_size) why = PDF_NOT_READ "larger than max_pdf_size";
        else fd = src->fd;
    } else if ((fd = mem_file()) < 0) why = PDF_NOT_READ "no memory file for the copy";
    else { src->tee = 1; src->tee_fd = fd; }

    int rc = scan_bytes(fc, src_read, src, member);
    src->tee = 0;
    if (rc < 0 && !fc->limit)
        emit_skip(w, fc->path, member, depth ? "not fully scanned: member unreadable" : "not fully scanned: read error");
    else if (!fc->limit && !g_stop) {
        if (!why && src->tee_over)
            why = src->tee_over == 1 ? PDF_NOT_READ "larger than max_pdf_size" : PDF_NOT_READ "no memory for the copy";
        if (why) emit_skip(w, fc->path, member, why);
        else scan_pdf_text(fc, fd, member);
    }
    if (!plain && fd >= 0) close(fd);
}

static void scan_source(struct filectx *fc, struct source *src, const char *member, int depth)
{
    struct worker *w = fc->w;
    if (src_sniff(src) < 0) {
        emit_skip(w, fc->path, member, depth ? "not scanned: member unreadable" : "not scanned: read error");
        return;
    }
    if (is_archive(src->peek, src->peek_len)) {
        if (!L.have_archive)
            emit_skip(w, fc->path, member, "not scanned: libarchive not available");
        else if (depth >= cfg->max_depth)
            emit_skip(w, fc->path, member, "not scanned: nested deeper than max_depth");
        else
            scan_archive(fc, src, member, depth);
        return;
    }
    if (is_pdf(src->peek, src->peek_len)) {
        scan_pdf(fc, src, member, depth);
        return;
    }
    if (scan_bytes(fc, src_read, src, member) < 0 && !fc->limit)
        emit_skip(w, fc->path, member, depth ? "not fully scanned: member unreadable" : "not fully scanned: read error");
}

static void process_file(struct worker *w, int dirfd, const char *name, const char *path, const struct stat *st)
{
    char reason[128];
    if (st->st_size == 0) { w->c.files++; return; }
    if (cfg->max_file_size && (uint64_t)st->st_size > cfg->max_file_size) {
        emit_skip(w, path, NULL, "not scanned: larger than max_file_size");
        return;
    }
    int fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NOATIME);
    if (fd < 0 && errno == EPERM) fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        snprintf(reason, sizeof reason, "not scanned: unreadable (%s)", strerror(errno));
        emit_skip(w, path, NULL, reason);
        return;
    }
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    struct filectx fc = { .w = w, .path = path, .name = name, .dirfd = dirfd, .st = *st,
                          .deadline = now_seconds() + cfg->max_file_seconds };
    struct source src = { .fc = &fc, .fd = fd, .ar = NULL };
    scan_source(&fc, &src, NULL, 0);
    if (fc.limit) emit_skip(w, path, NULL, fc.limit);
    emit_unlisted(&fc);
    close(fd);
    w->c.files++;
}

/* The system journal of the last N days, read as text from journalctl, which is started
 * directly (no shell). Nothing is written. A journalctl that fails is a gap in the coverage,
 * and its own first line of error text is the reason. */
static void scan_journal(struct worker *w, int days, const char *prog)
{
    char since[32], name[64], reason[400], errtext[200] = "";
    snprintf(since, sizeof since, "--since=-%dd", days);
    snprintf(name, sizeof name, "journal (last %d days)", days);
    int op[2] = { -1, -1 }, ep[2] = { -1, -1 };
    /* The error pipe never blocks: journalctl does not have to wait for us to read it. */
    if (pipe2(op, O_CLOEXEC) < 0 || pipe2(ep, O_CLOEXEC | O_NONBLOCK) < 0) {
        snprintf(reason, sizeof reason, "not scanned: journalctl could not be started (%s)", strerror(errno));
        emit_skip(w, name, NULL, reason);
        if (op[0] >= 0) { close(op[0]); close(op[1]); }
        return;
    }
    char *const argv[] = { "journalctl", since, "-o", "cat", "--no-pager", NULL };
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, op[1], 1);
    posix_spawn_file_actions_adddup2(&fa, ep[1], 2);
    pid_t pid;
    int rc = posix_spawn(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(op[1]);
    close(ep[1]);
    if (rc) {
        snprintf(reason, sizeof reason, "not scanned: journalctl could not be started (%s)", strerror(rc));
        emit_skip(w, name, NULL, reason);
        close(op[0]);
        close(ep[0]);
        return;
    }
    struct filectx fc = { .w = w, .path = name, .name = name, .dirfd = -1, .deadline = now_seconds() + 1e9 };
    fc.st.st_mtime = fc.st.st_ctime = time(NULL);
    struct source src = { .fc = &fc, .fd = op[0], .ar = NULL };
    scan_source(&fc, &src, NULL, 0);
    emit_unlisted(&fc);
    close(op[0]);   /* a journalctl that is still writing stops here */

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    ssize_t n;   /* it has ended, so what it wrote about an error is all there */
    do n = read(ep[0], errtext, sizeof errtext - 1); while (n < 0 && errno == EINTR);
    errtext[n > 0 ? n : 0] = 0;
    errtext[strcspn(errtext, "\r\n")] = 0;
    close(ep[0]);
    if (g_stop) return;
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) { w->c.files++; return; }
    if (errtext[0]) snprintf(reason, sizeof reason, "not scanned: journalctl failed (%s)", errtext);
    else if (WIFSIGNALED(status))
        snprintf(reason, sizeof reason, "not scanned: journalctl failed (stopped by signal %d)", WTERMSIG(status));
    else snprintf(reason, sizeof reason, "not scanned: journalctl failed (exit status %d)", WEXITSTATUS(status));
    emit_skip(w, name, NULL, reason);
}

/* ---- walker ---- */

/* open() for paths of any length: longer than PATH_MAX is opened in steps with openat. */
static int open_long(const char *path, int flags)
{
    if (strlen(path) < PATH_MAX) return open(path, flags);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    const char *p = path;
    while (fd >= 0) {
        while (*p == '/') p++;
        if (!*p) break;
        const char *end = p;   /* as many whole components as fit */
        for (const char *q = p;;) {
            const char *slash = strchr(q, '/');
            const char *stop = slash ? slash : q + strlen(q);
            if (stop - p >= PATH_MAX) break;
            end = stop;
            if (!slash) break;
            q = slash + 1;
        }
        if (end == p) { close(fd); errno = ENAMETOOLONG; return -1; }
        char chunk[PATH_MAX];
        memcpy(chunk, p, (size_t)(end - p));
        chunk[end - p] = 0;
        int nfd = openat(fd, chunk, *end ? (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : flags);
        int e = errno;
        close(fd);
        errno = e;
        fd = nfd;
        p = end;
    }
    return fd;
}

static int excluded(const char *path)
{
    static const char *const builtin[] = { "/proc", "/sys", "/dev", "/run" };
    for (size_t i = 0; i < sizeof builtin / sizeof builtin[0]; i++)
        if (!strcmp(path, builtin[i])) return 1;
    for (int i = 0; i < cfg->excludes.n; i++) {
        const char *e = cfg->excludes.v[i];
        if (strpbrk(e, "*?[")) {
            if (fnmatch(e, path, 0) == 0) return 1;
        } else {
            size_t n = strlen(e);
            while (n > 1 && e[n - 1] == '/') n--;
            if (!strncmp(path, e, n) && (path[n] == 0 || path[n] == '/')) return 1;
        }
    }
    return 0;
}

static void q_push(const char *path, dev_t dev, int is_file)
{
    size_t n = strlen(path) + 1;
    struct qnode *q = xmalloc(sizeof *q + n);
    memcpy(q->path, path, n);
    q->dev = dev;
    q->is_file = is_file;
    pthread_mutex_lock(&q_mu);
    q->next = q_head;
    q_head = q;
    pthread_cond_signal(&q_cv);
    pthread_mutex_unlock(&q_mu);
}

static void set_current(struct worker *w, const char *path)
{
    pthread_mutex_lock(&w->mu);
    size_t n = strlen(path);
    if (n < sizeof w->cur) memcpy(w->cur, path, n + 1);
    else snprintf(w->cur, sizeof w->cur, "...%s", path + n - (sizeof w->cur - 4));
    pthread_mutex_unlock(&w->mu);
}

static void process_dir(struct worker *w, const struct qnode *q)
{
    char reason[128];
    int fd = open_long(q->path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *d = fd >= 0 ? fdopendir(fd) : NULL;
    if (!d) {
        snprintf(reason, sizeof reason, "not scanned: unreadable folder (%s)", strerror(errno));
        emit_skip(w, q->path, NULL, reason);
        if (fd >= 0) close(fd);
        return;
    }
    set_current(w, q->path);
    w->c.dirs++;
    struct strbuf child = { 0 };
    struct dirent *de;
    while (!g_stop && (de = readdir(d))) {
        const char *n = de->d_name;
        if (n[0] == '.' && (!n[1] || (n[1] == '.' && !n[2]))) continue;
        sb_reset(&child);
        sb_add(&child, q->path);
        if (child.len && child.s[child.len - 1] != '/') sb_add(&child, "/");
        sb_add(&child, n);
        if (excluded(child.s)) { w->c.excluded++; continue; }
        struct stat st;
        if (fstatat(fd, n, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            snprintf(reason, sizeof reason, "not scanned: unreadable (%s)", strerror(errno));
            emit_skip(w, child.s, NULL, reason);
        } else if (S_ISLNK(st.st_mode)) w->c.symlinks++;          /* never followed */
        else if (S_ISDIR(st.st_mode)) {
            if (st.st_dev != q->dev) {                             /* stays on one file system */
                w->c.other_fs++;
                int given = 0;   /* a mount point that is itself a path of this run is searched */
                for (int i = 0; i < roots.n; i++) if (!strcmp(roots.v[i], child.s)) given = 1;
                if (!given && w->not_entered.n < 100) sl_add(&w->not_entered, child.s);
            }
            else q_push(child.s, q->dev, 0);
        } else if (S_ISREG(st.st_mode)) process_file(w, fd, n, child.s, &st);
        else w->c.special++;
    }
    sb_free(&child);
    closedir(d);
}

static void *worker_main(void *arg)
{
    struct worker *w = arg;
    for (;;) {
        pthread_mutex_lock(&q_mu);
        while (!q_head && q_active > 0 && !g_stop) pthread_cond_wait(&q_cv, &q_mu);
        struct qnode *q = g_stop ? NULL : q_head;
        if (!q) {
            q_done = 1;
            pthread_cond_broadcast(&q_cv);
            pthread_mutex_unlock(&q_mu);
            break;
        }
        q_head = q->next;
        q_active++;
        pthread_mutex_unlock(&q_mu);

        if (q->is_file) {
            struct stat st;
            if (lstat(q->path, &st) == 0 && S_ISREG(st.st_mode))
                process_file(w, AT_FDCWD, q->path, q->path, &st);
        } else {
            process_dir(w, q);
        }
        free(q);

        pthread_mutex_lock(&q_mu);
        q_active--;
        if (!q_head && q_active == 0) pthread_cond_broadcast(&q_cv);
        pthread_mutex_unlock(&q_mu);
    }
    set_current(w, "");
    return NULL;
}

/* ---- progress: on a terminal only ---- */

struct progress { struct worker *w; int n; };

static void *progress_main(void *arg)
{
    struct progress *p = arg;
    int drawn = 0;
    for (;;) {
        pthread_mutex_lock(&q_mu);
        int done = q_done;
        pthread_mutex_unlock(&q_mu);
        if (drawn) fprintf(stderr, "\033[%dA", p->n);
        for (int i = 0; i < p->n; i++) {
            char cur[sizeof p->w[i].cur];
            pthread_mutex_lock(&p->w[i].mu);
            memcpy(cur, p->w[i].cur, sizeof cur);
            pthread_mutex_unlock(&p->w[i].mu);
            fprintf(stderr, "\033[2K  worker %2d  %s\n", i + 1, done ? "done" : (cur[0] ? cur : "idle"));
        }
        drawn = 1;
        if (done) break;
        usleep(250000);
    }
    return NULL;
}

/* ---- the run ---- */

static void json_list(struct strbuf *b, const struct strlist *l)
{
    sb_add(b, "[");
    for (int i = 0; i < l->n; i++) { if (i) sb_add(b, ","); sb_json_str(b, l->v[i]); }
    sb_add(b, "]");
}

__attribute__((format(printf, 1, 2)))
static int fail(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fputs("chdsweep: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    return EXIT_FAILED;
}

int cmd_scan(struct config *c, const char *config_path)
{
    char err[600], host[256] = "unknown", start[24], end[24];
    cfg = c;

    rules_defaults(&rules);
    const char *default_rules = "/etc/chdsweep/fp-rules.conf";
    const char *rf = c->rules_file ? c->rules_file : (access(default_rules, R_OK) == 0 ? default_rules : NULL);
    if (rf && rules_load(&rules, rf, err, sizeof err)) return fail("rules file: %s", err);

    libs_load();
    static struct strbuf msgs;   /* static: still reachable on the early exits below */
    int partial = 0;
    if (!L.have_archive) { libs_missing_message("archive", &msgs); partial = 1; }
    if (msgs.len) fputs(msgs.s, stderr);          /* also in cron mode */
    /* A missing pdftotext is not announced on every run: most servers have no PDF in scope,
     * and each PDF that is met is listed. With require_all_libraries it is a failure. */
    if (c->require_all_libraries && c->pdf_text && !PDF.have) {
        struct strbuf m = { 0 };
        libs_missing_message("pdftotext", &m);
        fputs(m.s, stderr);
        sb_free(&m);
        partial = 1;
    }
    if (partial && c->require_all_libraries)
        return fail("a library is missing and require_all_libraries is set; not scanning");

    /* Notices: what this host cannot do, without a gap in the coverage. They go into the
     * run file for the report, and to the terminal unless the run is quiet (cron). */
    static struct strbuf notes, quiet_notes;
    int journal_asked = 1;
    if (geteuid() != 0) not_root_message(&notes);
    int pkg = rules.on[R_PACKAGE_FILE] ? pkgrule_state() : PKG_OK;
    if (pkg != PKG_OK) pkgrule_message(pkg, &notes);

    /* No path given: root's folder, the home folders, the current logs and the journal of
     * the last 35 days. Rotated and compressed logs and the binary journal are left out. */
    if (!c->paths.n) {
        static const char *const dpaths[] = { "/root", "/home", "/var/log" };
        static const char *const dexcl[] = {
            "/var/log/*.gz", "/var/log/*.xz", "/var/log/*.bz2", "/var/log/*.zst", "/var/log/*.zip",
            "/var/log/*.[0-9]", "/var/log/*-20[0-9][0-9][0-9][0-9][0-9][0-9]", "/var/log/journal",
        };
        for (size_t i = 0; i < sizeof dpaths / sizeof dpaths[0]; i++) sl_add(&c->paths, dpaths[i]);
        for (size_t i = 0; i < sizeof dexcl / sizeof dexcl[0]; i++) sl_add(&c->excludes, dexcl[i]);
        if (c->journal_days < 0) { c->journal_days = 35; journal_asked = 0; }
    }
    if (c->journal_days < 0) c->journal_days = 0;
    /* A host without journalctl has no systemd journal: nothing to scan, and no gap. In
     * the default scope that is not worth a line on the terminal. */
    char journalctl[4096] = "";
    if (c->journal_days > 0 && !find_journalctl(journalctl, sizeof journalctl)) {
        struct strbuf *to = journal_asked ? &notes : &quiet_notes;
        no_journal_message(journal_asked, to);
        c->journal_days = 0;
    }
    if (notes.len && !c->quiet) fputs(notes.s, stderr);

    int lock_fd = -1;
    if (c->lock_file && *c->lock_file) {
        lock_fd = open(c->lock_file, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        if (lock_fd < 0) return fail("lock file %s: %s", c->lock_file, strerror(errno));
        if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
            if (!c->quiet) fprintf(stderr, "chdsweep: another run holds the lock %s; not started\n", c->lock_file);
            return EXIT_LOCKED;
        }
    }

    if (c->nice_level) setpriority(PRIO_PROCESS, 0, c->nice_level);
#ifdef SYS_ioprio_set
    if (c->ionice_idle) syscall(SYS_ioprio_set, 1, 0, 3 << 13);   /* this process, idle class */
#endif

    time_t t0 = time(NULL);
    iso_time(t0, start);
    gethostname(host, sizeof host - 1);

    char outpath[PATH_MAX];
    if (c->output_file) snprintf(outpath, sizeof outpath, "%s", c->output_file);
    else {
        struct tm tm;
        char stamp[32];
        gmtime_r(&t0, &tm);
        strftime(stamp, sizeof stamp, "%Y%m%dT%H%M%SZ", &tm);
        mkdir(c->output_dir, 0700);
        snprintf(outpath, sizeof outpath, "%s/chdsweep-%s-%s.jsonl", c->output_dir, host, stamp);
    }
    int ofd = open(outpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (ofd < 0 || !(out = fdopen(ofd, "w"))) return fail("run file %s: %s", outpath, strerror(errno));

    /* header */
    struct strbuf b = { 0 };
    sb_add(&b, "{\"type\":\"header\",\"tool\":\"chdsweep\",\"version\":\"" CHD_VERSION "\",\"host\":");
    sb_json_str(&b, host);
    sb_printf(&b, ",\"start\":\"%s\",\"config_file\":", start);
    if (config_path) sb_json_str(&b, config_path); else sb_add(&b, "null");
    sb_add(&b, ",\"paths\":");
    json_list(&b, &c->paths);
    sb_add(&b, ",\"excludes\":");
    json_list(&b, &c->excludes);
    sb_printf(&b, ",\"limits\":{\"max_file_size\":%llu,\"max_unpacked\":%llu,\"max_depth\":%d,"
                  "\"max_ratio\":%d,\"max_members\":%ld,\"max_file_seconds\":%d,\"max_read_rate\":%llu,"
                  "\"max_hits_per_file\":%ld,\"max_pdf_pages\":%ld,\"max_pdf_size\":%llu,"
                  "\"max_pdf_memory\":%llu}",
              (unsigned long long)c->max_file_size, (unsigned long long)c->max_unpacked, c->max_depth,
              c->max_ratio, c->max_members, c->max_file_seconds, (unsigned long long)c->max_read_rate,
              c->max_hits_per_file, c->max_pdf_pages, (unsigned long long)c->max_pdf_size,
              (unsigned long long)c->max_pdf_memory);
    sb_printf(&b, ",\"pdf_text\":%s", c->pdf_text ? "true" : "false");
    sb_printf(&b, ",\"threads\":%d,\"keep_leading\":\"%s\",\"journal_days\":%d", c->threads,
              c->keep_leading == 6 ? "6" : "auto", c->journal_days);
    sb_add(&b, ",\"rules\":{\"source\":");
    sb_json_str(&b, rules.source);
    sb_printf(&b, ",\"checksum\":\"fnv1a64:%016llx\",\"enabled\":[", (unsigned long long)rules.checksum);
    for (int i = 0, first = 1; i < R_COUNT; i++)
        if (rules.on[i]) { sb_printf(&b, "%s\"%s\"", first ? "" : ",", rule_names[i]); first = 0; }
    sb_add(&b, "]},\"libraries\":{\"libarchive\":");
    if (L.have_archive) sb_json_str(&b, L.archive_version); else sb_add(&b, "null");
    sb_add(&b, ",\"libcrypto\":");
    if (L.have_crypto) sb_json_str(&b, L.crypto_version); else sb_add(&b, "null");
    sb_add(&b, ",\"pdftotext\":");
    if (PDF.have) sb_json_str(&b, PDF.version); else sb_add(&b, "null");
    sb_add(&b, "},\"messages\":");
    sb_add(&msgs, notes.s ? notes.s : "");
    sb_add(&msgs, quiet_notes.s ? quiet_notes.s : "");
    if (msgs.len) sb_json_str(&b, msgs.s); else sb_add(&b, "null");
    sb_add(&b, "}\n");
    out_line(&b);
    fflush(out);

    struct sigaction sa = { .sa_handler = on_signal };
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct worker *ws = xmalloc((size_t)c->threads * sizeof *ws);
    memset(ws, 0, (size_t)c->threads * sizeof *ws);
    for (int i = 0; i < c->threads; i++) {
        ws[i].id = i;
        ws[i].buf = xmalloc(SCAN_BUF_SIZE);
        pthread_mutex_init(&ws[i].mu, NULL);
    }

    /* roots */
    for (int i = 0; i < c->paths.n; i++) {
        char real[PATH_MAX];
        struct stat st;
        if (!realpath(c->paths.v[i], real) || stat(real, &st) < 0) {
            snprintf(err, sizeof err, "not scanned: path not found (%s)", strerror(errno));
            emit_skip(&ws[0], c->paths.v[i], NULL, err);
        } else if (S_ISDIR(st.st_mode)) { sl_add(&roots, real); q_push(real, st.st_dev, 0); }
        else if (S_ISREG(st.st_mode)) q_push(real, st.st_dev, 1);
    }

    for (int i = 0; i < c->threads; i++) pthread_create(&ws[i].th, NULL, worker_main, &ws[i]);
    pthread_t pth;
    struct progress prog = { ws, c->threads };
    int show = c->progress && !c->quiet && isatty(STDERR_FILENO);
    if (show) pthread_create(&pth, NULL, progress_main, &prog);
    for (int i = 0; i < c->threads; i++) pthread_join(ws[i].th, NULL);
    if (show) pthread_join(pth, NULL);
    if (c->journal_days > 0 && !g_stop) scan_journal(&ws[0], c->journal_days, journalctl);

    struct counters t = { 0 };
    for (int i = 0; i < c->threads; i++) {
        uint64_t *dst = (uint64_t *)&t, *src = (uint64_t *)&ws[i].c;
        for (size_t k = 0; k < sizeof t / sizeof(uint64_t); k++) dst[k] += src[k];
    }

    int complete = !g_stop;
    if (t.skipped) partial = 1;
    int code = !complete ? EXIT_FAILED : (partial ? EXIT_PARTIAL : EXIT_FULL);

    iso_time(time(NULL), end);
    sb_reset(&b);
    sb_printf(&b, "{\"type\":\"end\",\"end\":\"%s\",\"complete\":%s,\"coverage\":\"%s\",\"exit_code\":%d",
              end, complete ? "true" : "false", !complete ? "incomplete" : (partial ? "partial" : "full"), code);
    sb_printf(&b, ",\"counters\":{\"files\":%llu,\"bytes\":%llu,\"folders\":%llu,\"archives\":%llu,"
                  "\"archive_members\":%llu,\"skipped\":%llu,\"symlinks_not_followed\":%llu,"
                  "\"other_file_systems\":%llu,\"excluded\":%llu,\"special_files\":%llu,"
                  "\"open_hits\":%llu,\"marked_hits\":%llu,\"hits_not_listed\":%llu,"
                  "\"pdf_text_read\":%llu}",
              (unsigned long long)t.files, (unsigned long long)t.bytes, (unsigned long long)t.dirs,
              (unsigned long long)t.archives, (unsigned long long)t.members, (unsigned long long)t.skipped,
              (unsigned long long)t.symlinks, (unsigned long long)t.other_fs, (unsigned long long)t.excluded,
              (unsigned long long)t.special, (unsigned long long)t.hits_open, (unsigned long long)t.hits_marked,
              (unsigned long long)t.unlisted, (unsigned long long)t.pdfs);
    sb_add(&b, ",\"marked_by_rule\":{");
    for (int i = 0; i < R_COUNT; i++)
        sb_printf(&b, "%s\"%s\":%llu", i ? "," : "", rule_names[i], (unsigned long long)t.by_rule[i]);
    /* Folders on another file system are scope, not a failure, but a reader must be able
     * to see them: /var or /home on its own file system is not searched unless it is a path. */
    sb_add(&b, "},\"not_entered\":[");
    for (int i = 0, first = 1; i < c->threads; i++)
        for (int k = 0; k < ws[i].not_entered.n; k++) {
            if (!first) sb_add(&b, ",");
            sb_json_str(&b, ws[i].not_entered.v[k]);
            first = 0;
            if (!c->quiet)
                fprintf(stderr, "chdsweep: not entered (another file system): %s\n", ws[i].not_entered.v[k]);
            free(ws[i].not_entered.v[k]);
        }
    sb_add(&b, "]}\n");
    out_line(&b);
    if (fclose(out) != 0) out_failed = 1;
    if (out_failed) {
        fail("run file %s: write failed", outpath);
        code = EXIT_FAILED;
    }

    if (!c->quiet) {
        fprintf(stderr, "chdsweep: %s, %llu files, %llu open hits, %llu marked hits, %llu skipped\n",
                !complete ? "interrupted" : (partial ? "completed with partial coverage" : "completed with full coverage"),
                (unsigned long long)t.files, (unsigned long long)t.hits_open,
                (unsigned long long)t.hits_marked, (unsigned long long)t.skipped);
        fprintf(stderr, "chdsweep: run file %s\n", outpath);
    }
    for (int i = 0; i < c->threads; i++) {
        free(ws[i].buf); sb_free(&ws[i].sb); free(ws[i].res.hits); free(ws[i].not_entered.v);
    }
    free(ws);
    sb_free(&b);
    sb_free(&msgs);
    sb_free(&notes);
    sb_free(&quiet_notes);
    if (lock_fd >= 0) close(lock_fd);
    return code;
}
