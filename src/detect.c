/* chdsweep: Luhn, brand table, masking and the rules that look at the number alone */
#include "chdsweep.h"

#include <string.h>

int luhn_ok(const char *d, int n)
{
    int sum = 0, alt = 0;
    for (int i = n - 1; i >= 0; i--) {
        int v = d[i] - '0';
        if (alt) { v *= 2; if (v > 9) v -= 9; }
        sum += v;
        alt = !alt;
    }
    return n > 0 && sum % 10 == 0;
}

/* Brand table: prefix range and the lengths the brand issues.
 * Maintained by hand from the schemes' published ranges. */
#define LEN(n) (1u << (n))
#define L16_19 (LEN(16) | LEN(17) | LEN(18) | LEN(19))
#define L12_19 (LEN(12) | LEN(13) | LEN(14) | LEN(15) | L16_19)
#define DINERS (LEN(14) | LEN(16) | LEN(19))

static const struct brand {
    const char *name;
    int plen;
    unsigned lo, hi;
    unsigned lens;
} brands[] = {
    { "mir",        4, 2200, 2204, L16_19 },
    { "mastercard", 4, 2221, 2720, LEN(16) },
    { "mastercard", 2, 51,   55,   LEN(16) },
    { "amex",       2, 34,   34,   LEN(15) },
    { "amex",       2, 37,   37,   LEN(15) },
    { "diners",     3, 300,  305,  DINERS },
    { "diners",     4, 3095, 3095, DINERS },
    { "diners",     2, 36,   36,   DINERS },
    { "diners",     2, 38,   39,   DINERS },
    { "jcb",        4, 3528, 3589, L16_19 },
    { "discover",   4, 6011, 6011, L16_19 },
    { "discover",   3, 644,  649,  L16_19 },
    { "discover",   2, 65,   65,   L16_19 },
    { "maestro",    4, 5018, 5018, L12_19 },
    { "maestro",    4, 5020, 5020, L12_19 },
    { "maestro",    4, 5038, 5038, L12_19 },
    { "maestro",    4, 5893, 5893, L12_19 },
    { "maestro",    4, 6304, 6304, L12_19 },
    { "maestro",    4, 6759, 6759, L12_19 },
    { "maestro",    4, 6761, 6763, L12_19 },
    { "unionpay",   2, 62,   62,   L16_19 },
    { "visa",       1, 4,    4,    LEN(13) | LEN(16) | LEN(19) },
};

const char *brand_lookup(const char *d, int n)
{
    if (n < 12 || n > 19) return NULL;
    unsigned prefix[5] = { 0 };
    for (int i = 1; i <= 4; i++) prefix[i] = prefix[i - 1] * 10 + (unsigned)(d[i - 1] - '0');
    for (size_t i = 0; i < sizeof brands / sizeof brands[0]; i++) {
        const struct brand *b = &brands[i];
        unsigned p = prefix[b->plen];
        if (p >= b->lo && p <= b->hi && (b->lens & LEN(n))) return b->name;
    }
    return NULL;
}

/* Test numbers published by the schemes and payment providers. */
static const char *const test_cards[] = {
    "4111111111111111", "4012888888881881", "4222222222222", "4242424242424242",
    "4000056655665556", "4000000000000002", "4917610000000000", "4484070000000000",
    "4263982640269299", "5555555555554444", "5105105105105100", "5200828282828210",
    "5425233430109903", "2223003122003222", "2222420000001113", "378282246310005",
    "371449635398431", "378734493671000", "374245455400126", "6011111111111117",
    "6011000990139424", "3056930009020004", "36227206271667", "30569309025904",
    "38520000023237", "3530111333300000", "3566002020360505", "6200000000000005",
    "5019717010103742", "6331101999990016",
};

int is_test_card(const char *d, int n)
{
    for (size_t i = 0; i < sizeof test_cards / sizeof test_cards[0]; i++)
        if ((int)strlen(test_cards[i]) == n && memcmp(test_cards[i], d, (size_t)n) == 0) return 1;
    return 0;
}

/* At most two distinct digits after the six-digit prefix. */
int is_repeat_digits(const char *d, int n)
{
    int seen[10] = { 0 }, distinct = 0;
    for (int i = 6; i < n; i++)
        if (!seen[d[i] - '0']++) distinct++;
    return distinct <= 2;
}

/* Ascending or descending run, wrapping at 9/0. The check digit is left out. */
int is_sequence(const char *d, int n)
{
    int up = 1, down = 1;
    for (int i = 1; i < n - 1; i++) {
        int diff = (d[i] - d[i - 1] + 10) % 10;
        if (diff != 1) up = 0;
        if (diff != 9) down = 0;
    }
    return up || down;
}

void mask_number(const char *d, int n, int keep_leading, char *out)
{
    /* PCI DSS: first eight only for 16 digits or more, otherwise first six. */
    int lead = (keep_leading != 6 && n >= 16) ? 8 : 6;
    for (int i = 0; i < n; i++) out[i] = (i < lead || i >= n - 4) ? d[i] : '*';
    out[n] = 0;
}
