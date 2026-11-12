/* chdsweep: a small JSON reader, enough for the run files chdsweep writes */
#include "chdsweep.h"

#include <stdlib.h>
#include <string.h>

struct parser { const char *p; int depth; };

static void skip_ws(struct parser *ps)
{
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\n' || *ps->p == '\r') ps->p++;
}

static int hex4(const char *p)
{
    int v = 0;
    for (int i = 0; i < 4; i++) {
        int c = p[i];
        if (c >= '0' && c <= '9') v = v * 16 + c - '0';
        else if (c >= 'a' && c <= 'f') v = v * 16 + c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = v * 16 + c - 'A' + 10;
        else return -1;
    }
    return v;
}

static char *parse_string(struct parser *ps)
{
    if (*ps->p != '"') return NULL;
    const char *p = ps->p + 1;
    struct strbuf b = { 0 };
    sb_addn(&b, "", 0);
    for (;;) {
        unsigned char c = (unsigned char)*p;
        if (c == 0 || c < 0x20) { sb_free(&b); return NULL; }
        if (c == '"') { p++; break; }
        if (c != '\\') { sb_addn(&b, p++, 1); continue; }
        p++;
        switch (*p) {
        case '"': case '\\': case '/': sb_addn(&b, p, 1); break;
        case 'b': sb_addn(&b, "\b", 1); break;
        case 'f': sb_addn(&b, "\f", 1); break;
        case 'n': sb_addn(&b, "\n", 1); break;
        case 'r': sb_addn(&b, "\r", 1); break;
        case 't': sb_addn(&b, "\t", 1); break;
        case 'u': {
            int v = hex4(p + 1);
            if (v < 0) { sb_free(&b); return NULL; }
            p += 4;
            char u[3];
            if (v == 0) v = 0xfffd;              /* no NUL inside a C string */
            if (v < 0x80) { u[0] = (char)v; sb_addn(&b, u, 1); }
            else if (v < 0x800) { u[0] = (char)(0xC0 | (v >> 6)); u[1] = (char)(0x80 | (v & 0x3F)); sb_addn(&b, u, 2); }
            else {
                u[0] = (char)(0xE0 | (v >> 12));
                u[1] = (char)(0x80 | ((v >> 6) & 0x3F));
                u[2] = (char)(0x80 | (v & 0x3F));
                sb_addn(&b, u, 3);
            }
            break;
        }
        default: sb_free(&b); return NULL;
        }
        p++;
    }
    ps->p = p;
    return b.s;
}

static struct jv *parse_value(struct parser *ps)
{
    skip_ws(ps);
    if (++ps->depth > 32) return NULL;
    struct jv *v = xmalloc(sizeof *v);
    memset(v, 0, sizeof *v);
    char c = *ps->p;
    int ok = 0;
    if (c == '"') {
        v->type = J_STR;
        ok = (v->s = parse_string(ps)) != NULL;
    } else if (c == '{' || c == '[') {
        char close = c == '{' ? '}' : ']';
        v->type = c == '{' ? J_OBJ : J_ARR;
        ps->p++;
        skip_ws(ps);
        struct jv **tail = &v->child;
        ok = 1;
        if (*ps->p == close) ps->p++;
        else for (;;) {
            char *key = NULL;
            skip_ws(ps);
            if (v->type == J_OBJ) {
                key = parse_string(ps);
                skip_ws(ps);
                if (!key || *ps->p != ':') { free(key); ok = 0; break; }
                ps->p++;
            }
            struct jv *item = parse_value(ps);
            if (!item) { free(key); ok = 0; break; }
            item->key = key;
            *tail = item;
            tail = &item->next;
            skip_ws(ps);
            if (*ps->p == ',') { ps->p++; continue; }
            if (*ps->p == close) { ps->p++; break; }
            ok = 0;
            break;
        }
    } else if (!strncmp(ps->p, "true", 4)) { v->type = J_BOOL; v->n = 1; ps->p += 4; ok = 1; }
    else if (!strncmp(ps->p, "false", 5)) { v->type = J_BOOL; ps->p += 5; ok = 1; }
    else if (!strncmp(ps->p, "null", 4)) { v->type = J_NULL; ps->p += 4; ok = 1; }
    else if (c == '-' || (c >= '0' && c <= '9')) {
        char *end;
        v->type = J_NUM;
        v->n = strtoll(ps->p, &end, 10);
        while (*end == '.' || *end == 'e' || *end == 'E' || *end == '+' || *end == '-' ||
               (*end >= '0' && *end <= '9')) end++;   /* fractions are not used; skip them */
        ok = end != ps->p;
        ps->p = end;
    }
    ps->depth--;
    if (!ok) { json_free(v); return NULL; }
    return v;
}

struct jv *json_parse(const char *text)
{
    struct parser ps = { text, 0 };
    struct jv *v = parse_value(&ps);
    if (!v) return NULL;
    skip_ws(&ps);
    if (*ps.p) { json_free(v); return NULL; }
    return v;
}

void json_free(struct jv *v)
{
    while (v) {
        struct jv *next = v->next;
        json_free(v->child);
        free(v->key);
        free(v->s);
        free(v);
        v = next;
    }
}

const struct jv *json_get(const struct jv *obj, const char *key)
{
    if (!obj || obj->type != J_OBJ) return NULL;
    for (const struct jv *c = obj->child; c; c = c->next)
        if (c->key && !strcmp(c->key, key)) return c;
    return NULL;
}

const char *json_str(const struct jv *obj, const char *key, const char *def)
{
    const struct jv *v = json_get(obj, key);
    return v && v->type == J_STR ? v->s : def;
}

long long json_num(const struct jv *obj, const char *key, long long def)
{
    const struct jv *v = json_get(obj, key);
    return v && (v->type == J_NUM || v->type == J_BOOL) ? v->n : def;
}
