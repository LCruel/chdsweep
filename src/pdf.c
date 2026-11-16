/* chdsweep: text inside PDF files, read by an installed pdftotext (poppler-utils).
 *
 * pdftotext runs as a child process, one per PDF, with a memory and a CPU limit, and its
 * text comes back through a pipe. Nothing is linked in: a PDF parser reads untrusted
 * files, and as a child a crash or a file that never ends costs that one file. */
#include "chdsweep.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

struct pdf_tool PDF;

/* The program in PATH, then in the usual places: cron starts with a short PATH. */
static int find_tool(char *out, size_t outlen)
{
    const char *path = getenv("PATH");
    struct strbuf dirs = { 0 };
    sb_add(&dirs, path && *path ? path : "");
    sb_add(&dirs, ":/usr/bin:/usr/local/bin:/bin");
    int found = 0;
    for (char *save = NULL, *d = strtok_r(dirs.s, ":", &save); d && !found; d = strtok_r(NULL, ":", &save)) {
        struct stat st;
        if (d[0] != '/') continue;                  /* never the current folder */
        snprintf(out, outlen, "%s/pdftotext", d);
        found = stat(out, &st) == 0 && S_ISREG(st.st_mode) && access(out, X_OK) == 0;
    }
    sb_free(&dirs);
    return found;
}

static void close_fd(int *fd) { if (*fd >= 0) close(*fd); *fd = -1; }

/* Child side, between fork and exec: only calls that are safe there. */
static void child_fd(int from, int to)
{
    if (from == to) fcntl(to, F_SETFD, 0);          /* keep it across the exec */
    else dup2(from, to);
}

static pid_t spawn(char *const argv[], int in, int outfd, int errfd, uint64_t max_memory, int cpu_seconds)
{
    pid_t pid = fork();
    if (pid != 0) return pid;
    child_fd(in, 0);
    child_fd(outfd, 1);
    child_fd(errfd, 2);
    struct rlimit rl = { 0, 0 };
    setrlimit(RLIMIT_CORE, &rl);
    if (max_memory) {
        rl.rlim_cur = rl.rlim_max = (rlim_t)max_memory;
        setrlimit(RLIMIT_AS, &rl);
    }
    if (cpu_seconds > 0) {                           /* behind the wall-clock limit of the reader */
        rl.rlim_cur = rl.rlim_max = (rlim_t)cpu_seconds;
        setrlimit(RLIMIT_CPU, &rl);
    }
    execv(argv[0], argv);
    _exit(127);
}

void pdf_probe(void)
{
    memset(&PDF, 0, sizeof PDF);
    const char *off = getenv("CHDSWEEP_NO_OPTIONAL_LIBS");   /* for tests: behave as if missing */
    if (off && *off) return;
    if (!find_tool(PDF.path, sizeof PDF.path)) return;

    /* "pdftotext -v" prints its version on stderr. A program that does not answer is not used. */
    int pe[2], null = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (null < 0 || pipe2(pe, O_CLOEXEC) < 0) { if (null >= 0) close(null); return; }
    char *argv[] = { PDF.path, "-v", NULL };
    pid_t pid = spawn(argv, null, pe[1], pe[1], 0, 10);
    close(pe[1]);
    close(null);
    char buf[512];
    size_t len = 0;
    if (pid > 0) {
        struct pollfd pf = { pe[0], POLLIN, 0 };
        double end = now_seconds() + 10;
        while (len < sizeof buf - 1 && now_seconds() < end) {
            if (poll(&pf, 1, 500) <= 0) continue;
            ssize_t r = read(pe[0], buf + len, sizeof buf - 1 - len);
            if (r > 0) len += (size_t)r;
            else if (r == 0 || errno != EINTR) break;
        }
        kill(pid, SIGKILL);
        int st;
        while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    }
    close(pe[0]);
    buf[len] = 0;
    const char *v = strstr(buf, "version ");
    if (pid <= 0 || !v) return;
    v += 8;
    size_t n = strcspn(v, " \r\n");
    snprintf(PDF.version, sizeof PDF.version, "%.*s%s", (int)(n < 40 ? n : 40), v,
             strstr(buf, "Poppler") || strstr(buf, "poppler") ? " (poppler)" : "");
    /* Through /proc the child opens the file itself and reads only what it needs;
     * from standard input it would first copy the whole file into its memory. */
    PDF.by_proc = access("/proc/self/fd/0", F_OK) == 0;
    PDF.have = 1;
}

int pdf_start(struct pdf_run *p, int fd, long max_pages, uint64_t max_memory, int cpu_seconds,
              double deadline, const volatile sig_atomic_t *stop)
{
    memset(p, 0, sizeof *p);
    p->out_fd = p->err_fd = -1;
    p->max_pages = max_pages;
    p->deadline = deadline;
    p->stop = stop;
    int po[2], pe[2];
    if (pipe2(po, O_CLOEXEC) < 0) return -1;
    if (pipe2(pe, O_CLOEXEC) < 0) { close(po[0]); close(po[1]); return -1; }
    lseek(fd, 0, SEEK_SET);

    /* One page more than the limit is asked for, to see whether the PDF has more. */
    char last[24];
    snprintf(last, sizeof last, "%ld", max_pages + 1);
    char *argv[10];
    int n = 0;
    argv[n++] = PDF.path;
    argv[n++] = "-enc";
    argv[n++] = "UTF-8";
    /* The text as it is laid out on the page: a number spread over table cells or tab stops
     * stays on one line. Without it every cell is a line of its own. */
    argv[n++] = "-layout";
    if (max_pages > 0) { argv[n++] = "-l"; argv[n++] = last; }
    argv[n++] = PDF.by_proc ? "/proc/self/fd/0" : "-";
    argv[n++] = "-";
    argv[n] = NULL;

    p->pid = spawn(argv, fd, po[1], pe[1], max_memory, cpu_seconds);
    close(po[1]);
    close(pe[1]);
    if (p->pid < 0) { close(po[0]); close(pe[0]); return -1; }
    p->out_fd = po[0];
    p->err_fd = pe[0];
    return 0;
}

static void page_end(struct pdf_run *p, uint64_t next_start)
{
    p->pages++;
    if (!p->page_has_text) p->empty++;
    p->page_has_text = 0;
    if (p->npages == p->cap) {
        p->cap = p->cap ? p->cap * 2 : 64;
        p->page_start = xrealloc(p->page_start, p->cap * sizeof *p->page_start);
    }
    p->page_start[p->npages++] = next_start;
}

/* scan_read_fn: the text, page after page; a form feed ends a page. */
ssize_t pdf_read(void *cookie, void *buf, size_t n)
{
    struct pdf_run *p = cookie;
    char junk[256];
    while (!p->done) {
        if (p->stop && *p->stop) { p->stopped = 1; break; }
        double left = p->deadline > 0 ? p->deadline - now_seconds() : 1;
        if (left <= 0) { p->timed_out = 1; break; }
        struct pollfd pf[2] = { { p->out_fd, POLLIN, 0 }, { p->err_fd, POLLIN, 0 } };
        int ready = poll(pf, 2, left > 0.2 ? 200 : (int)(left * 1000) + 1);
        if (ready < 0 && errno != EINTR) return -1;
        if (ready <= 0) continue;

        if (p->err_fd >= 0 && pf[1].revents) {       /* the first lines are kept, the rest dropped */
            ssize_t r = read(p->err_fd, junk, sizeof junk);
            if (r > 0) {
                size_t room = sizeof p->err - 1 - p->errlen, k = (size_t)r < room ? (size_t)r : room;
                memcpy(p->err + p->errlen, junk, k);
                p->errlen += k;
            } else if (r == 0 || errno != EINTR) close_fd(&p->err_fd);
        }
        if (!pf[0].revents) continue;

        ssize_t r = read(p->out_fd, buf, p->at_limit ? 1 : n);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        if (r == 0) {
            if (p->page_has_text) page_end(p, p->pos);   /* text without a closing form feed */
            p->done = 1;
            break;
        }
        if (p->at_limit) { p->more_pages = 1; break; }    /* anything after the last page allowed */
        const unsigned char *b = buf;
        for (ssize_t i = 0; i < r; i++) {
            if (b[i] == '\f') {
                page_end(p, p->pos + (uint64_t)i + 1);
                if (p->max_pages > 0 && p->pages == p->max_pages) {
                    if (i + 1 < r) p->more_pages = 1; else p->at_limit = 1;
                    r = i + 1;
                    break;
                }
            } else if (b[i] != ' ' && b[i] != '\n' && b[i] != '\r' && b[i] != '\t') p->page_has_text = 1;
        }
        p->pos += (uint64_t)r;
        if (p->more_pages) p->done = 1;
        return r;
    }
    p->done = 1;
    return 0;
}

int pdf_finish(struct pdf_run *p)
{
    int early = p->more_pages || p->timed_out || p->stopped;
    /* What is left of the messages, without waiting for a child that is being stopped. */
    while (!early && p->err_fd >= 0 && p->errlen < sizeof p->err - 1) {
        ssize_t r = read(p->err_fd, p->err + p->errlen, sizeof p->err - 1 - p->errlen);
        if (r > 0) p->errlen += (size_t)r;
        else if (r == 0 || errno != EINTR) break;
    }
    p->err[p->errlen] = 0;
    close_fd(&p->out_fd);
    close_fd(&p->err_fd);
    int st = 0;
    if (p->pid > 0) {
        if (early) kill(p->pid, SIGKILL);
        while (waitpid(p->pid, &st, 0) < 0 && errno == EINTR) {}
    }
    if (p->stopped) return PDF_STOPPED;
    if (p->timed_out) return PDF_TIMEOUT;
    if (p->more_pages) return PDF_OK;
    if (WIFSIGNALED(st)) { p->code = WTERMSIG(st); return PDF_SIGNAL; }
    p->code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    if (p->code == 0) return PDF_OK;
    if (p->code == 127) return PDF_NOT_STARTED;
    if (p->code == 3) return PDF_NO_COPY;
    if (strcasestr(p->err, "password")) return PDF_PASSWORD;
    return PDF_BROKEN;
}

long pdf_page_of(const struct pdf_run *p, uint64_t offset)
{
    size_t lo = 0, hi = p->npages;                   /* pages that end at or before the offset */
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (p->page_start[mid] <= offset) lo = mid + 1; else hi = mid;
    }
    return (long)lo + 1;
}

void pdf_free(struct pdf_run *p)
{
    free(p->page_start);
    p->page_start = NULL;
    p->npages = p->cap = 0;
}
