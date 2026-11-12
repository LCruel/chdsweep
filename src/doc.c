/* chdsweep: a report as a list of headings, paragraphs and tables,
 * written once as Markdown and once as a self-contained HTML page. */
#include "chdsweep.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

enum { B_H1 = 1, B_H2, B_H3, B_P, B_TABLE };

static struct block *add_block(struct doc *d, int type)
{
    d->b = xrealloc(d->b, (size_t)(d->n + 1) * sizeof *d->b);
    struct block *b = &d->b[d->n++];
    memset(b, 0, sizeof *b);
    b->type = type;
    return b;
}

static char *vformat(const char *fmt, va_list ap)
{
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    char *s = xmalloc((size_t)n + 1);
    vsnprintf(s, (size_t)n + 1, fmt, ap);
    return s;
}

void doc_h(struct doc *d, int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *s = vformat(fmt, ap);
    va_end(ap);
    add_block(d, level <= 1 ? B_H1 : level == 2 ? B_H2 : B_H3)->text = s;
    if (level <= 1 && !d->title) d->title = xstrdup(s);
}

void doc_p(struct doc *d, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    add_block(d, B_P)->text = vformat(fmt, ap);
    va_end(ap);
}

int doc_table(struct doc *d, int ncols, ...)
{
    struct block *b = add_block(d, B_TABLE);
    b->ncols = ncols;
    va_list ap;
    va_start(ap, ncols);
    for (int i = 0; i < ncols; i++) sl_add(&b->cells, va_arg(ap, const char *));
    va_end(ap);
    return d->n - 1;
}

void doc_row(struct doc *d, int table, ...)
{
    struct block *b = &d->b[table];
    va_list ap;
    va_start(ap, table);
    for (int i = 0; i < b->ncols; i++) {
        const char *s = va_arg(ap, const char *);
        sl_add(&b->cells, s ? s : "");
    }
    va_end(ap);
}

int doc_rows(const struct doc *d, int table)
{
    return d->b[table].cells.n / d->b[table].ncols - 1;
}

void doc_drop_column(struct doc *d, const char *header)
{
    for (int i = 0; i < d->n; i++) {
        struct block *b = &d->b[i];
        if (b->type != B_TABLE || b->ncols < 2) continue;
        int col = -1;
        for (int c = 0; c < b->ncols; c++)
            if (!strcmp(b->cells.v[c], header)) col = c;
        if (col < 0) continue;
        int kept = 0;
        for (int k = 0; k < b->cells.n; k++) {
            if (k % b->ncols == col) free(b->cells.v[k]);
            else b->cells.v[kept++] = b->cells.v[k];
        }
        b->cells.n = kept;
        b->ncols--;
    }
}

void doc_free(struct doc *d)
{
    for (int i = 0; i < d->n; i++) {
        free(d->b[i].text);
        for (int k = 0; k < d->b[i].cells.n; k++) free(d->b[i].cells.v[k]);
        free(d->b[i].cells.v);
    }
    free(d->b);
    free(d->title);
    memset(d, 0, sizeof *d);
}

/* A cell that is a number, a percentage or a dash is right-aligned. */
static int is_numeric(const char *s)
{
    if (!*s) return 0;
    if (!strcmp(s, "-") || !strcmp(s, "n/a")) return 1;
    for (; *s; s++)
        if (!((*s >= '0' && *s <= '9') || *s == '.' || *s == ',' || *s == '%' || *s == '+' || *s == '-')) return 0;
    return 1;
}

static int column_numeric(const struct block *b, int col)
{
    int rows = b->cells.n / b->ncols;
    if (rows < 2) return 0;
    for (int r = 1; r < rows; r++)
        if (!is_numeric(b->cells.v[r * b->ncols + col])) return 0;
    return 1;
}

static void md_text(struct strbuf *o, const char *s, int cell)
{
    for (; *s; s++) {
        if (*s == '\n' || *s == '\r') sb_addn(o, " ", 1);
        else if (cell && *s == '|') sb_add(o, "\\|");
        else if (*s == '<') sb_add(o, "&lt;");
        else if (*s == '*' || *s == '_' || *s == '`' || *s == '\\' || *s == '[') {
            sb_addn(o, "\\", 1);
            sb_addn(o, s, 1);
        } else sb_addn(o, s, 1);
    }
}

static void html_text(struct strbuf *o, const char *s)
{
    for (; *s; s++) {
        if (*s == '&') sb_add(o, "&amp;");
        else if (*s == '<') sb_add(o, "&lt;");
        else if (*s == '>') sb_add(o, "&gt;");
        else if (*s == '"') sb_add(o, "&quot;");
        else sb_addn(o, s, 1);
    }
}

static int write_out(const char *path, const struct strbuf *o)
{
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    int bad = fwrite(o->s, 1, o->len, f) != o->len;
    if (fclose(f) != 0) bad = 1;
    return bad ? -1 : 0;
}

int doc_write_md(const struct doc *d, const char *path)
{
    struct strbuf o = { 0 };
    for (int i = 0; i < d->n; i++) {
        const struct block *b = &d->b[i];
        if (b->type == B_TABLE) {
            int rows = b->cells.n / b->ncols;
            if (rows < 2) { sb_add(&o, "None.\n\n"); continue; }
            for (int r = 0; r < rows; r++) {
                sb_add(&o, "|");
                for (int c = 0; c < b->ncols; c++) {
                    sb_add(&o, " ");
                    md_text(&o, b->cells.v[r * b->ncols + c], 1);
                    sb_add(&o, " |");
                }
                sb_add(&o, "\n");
                if (r == 0) {
                    sb_add(&o, "|");
                    for (int c = 0; c < b->ncols; c++) sb_add(&o, column_numeric(b, c) ? " ---: |" : " --- |");
                    sb_add(&o, "\n");
                }
            }
            sb_add(&o, "\n");
        } else {
            if (b->type == B_H1) sb_add(&o, "# ");
            else if (b->type == B_H2) sb_add(&o, "## ");
            else if (b->type == B_H3) sb_add(&o, "### ");
            md_text(&o, b->text, 0);
            sb_add(&o, "\n\n");
        }
    }
    int rc = write_out(path, &o);
    sb_free(&o);
    return rc;
}

int doc_write_html(const struct doc *d, const char *path)
{
    struct strbuf o = { 0 };
    sb_add(&o, "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
               "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>");
    html_text(&o, d->title ? d->title : "chdsweep report");
    sb_add(&o, "</title>\n<style>\n"
               "body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:72rem;padding:0 1rem;color:#1c1c1c}\n"
               "h1{font-size:1.7rem}h2{font-size:1.3rem;margin-top:2.2rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}\n"
               "h3{font-size:1.05rem;margin-top:1.5rem}\n"
               "table{border-collapse:collapse;margin:.6rem 0 1.2rem;font-size:.9rem}\n"
               "th,td{border:1px solid #ccc;padding:.25rem .6rem;text-align:left;vertical-align:top}\n"
               "td{max-width:44rem;overflow-wrap:break-word}\n"
               "th{background:#f0f0f0;white-space:nowrap}td.n,th.n{text-align:right;white-space:nowrap}\n"
               ".wrap{overflow-x:auto}\n"
               "@media (prefers-color-scheme:dark){body{background:#181818;color:#e4e4e4}"
               "th{background:#2a2a2a}th,td{border-color:#444}h2{border-color:#444}}\n"
               "@media print{body{max-width:none;margin:0}}\n"
               "</style></head><body>\n");
    for (int i = 0; i < d->n; i++) {
        const struct block *b = &d->b[i];
        if (b->type == B_TABLE) {
            int rows = b->cells.n / b->ncols;
            if (rows < 2) { sb_add(&o, "<p>None.</p>\n"); continue; }
            sb_add(&o, "<div class=\"wrap\"><table>\n");
            for (int r = 0; r < rows; r++) {
                sb_add(&o, r == 0 ? "<thead><tr>" : "<tr>");
                for (int c = 0; c < b->ncols; c++) {
                    const char *tag = r == 0 ? "th" : "td";
                    sb_printf(&o, "<%s%s>", tag, column_numeric(b, c) ? " class=\"n\"" : "");
                    html_text(&o, b->cells.v[r * b->ncols + c]);
                    sb_printf(&o, "</%s>", tag);
                }
                sb_add(&o, r == 0 ? "</tr></thead>\n<tbody>\n" : "</tr>\n");
            }
            sb_add(&o, "</tbody></table></div>\n");
        } else {
            const char *tag = b->type == B_H1 ? "h1" : b->type == B_H2 ? "h2" : b->type == B_H3 ? "h3" : "p";
            sb_printf(&o, "<%s>", tag);
            html_text(&o, b->text);
            sb_printf(&o, "</%s>\n", tag);
        }
    }
    sb_add(&o, "</body></html>\n");
    int rc = write_out(path, &o);
    sb_free(&o);
    return rc;
}
