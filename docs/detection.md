# What chdsweep detects

chdsweep reports a string of digits as a card number when all of this holds:

1. **A brand issues it.** The first digits and the length match a card brand (table below).
2. **The check digit is right.** The number passes the Luhn check that every card number passes.
3. **It stands on its own.** The character before and after it is not a letter, a digit or `_`. So `ref4539148803436467abc` and a card number inside a longer number are not reported.
4. **It is written in a way cards are written** (below).

Every hit is reported masked. Whether a hit is a real card number is for a person to decide; the [false-positive rules](#likely-false-positives) mark the ones that most likely are not.

## Brands and lengths

| Brand | Starts with | Digits |
|---|---|---|
| Visa | 4 | 13, 16, 19 |
| Mastercard | 51 to 55, 2221 to 2720 | 16 |
| American Express | 34, 37 | 15 |
| Diners Club | 300 to 305, 3095, 36, 38, 39 | 14, 16, 19 |
| Discover | 6011, 644 to 649, 65 | 16 to 19 |
| JCB | 3528 to 3589 | 16 to 19 |
| UnionPay | 62 | 16 to 19 |
| Maestro | 5018, 5020, 5038, 5893, 6304, 6759, 6761 to 6763 | 12 to 19 |
| Mir | 2200 to 2204 | 16 to 19 |

## How the number may be written

**Without separators,** at any of the lengths above:

```
4556737586899855
```

**In groups of four,** with a shorter last group where the length asks for it:

```
4556 7375 8689 9855          16 digits
4716 1234 5678 9012 344      19 digits
4539 1234 5678 5            13 digits
```

**As printed on the card,** for American Express (4-6-5) and Diners Club (4-6-4):

```
3714 496353 98431
3605 123456 7890
```

**Between the groups** one of these, and the same one all the way through:

| Separator | Example |
|---|---|
| a space | `4556 7375 8689 9855` |
| a dash | `4556-7375-8689-9855` |
| a dot | `4556.7375.8689.9855` |
| a tab, as in a column export | `4556	7375	8689	9855` |
| two spaces, as in a fixed-width report | `4556  7375  8689  9855` |
| `+`, a space as a web form sends it | `card=4556+7375+8689+9855&cvc=...` |
| `%20`, a space as a URL writes it | `card=4556%207375%208689%209855` |

The last two are how a number typed with spaces ends up in a web server's access log.

When a grouped number can be read at two lengths, the longest one that is a valid card number is reported: `4556 7375 8689 9855 123` is a 16-digit card followed by `123`, unless all 19 digits happen to make a valid card number.

## In the text of a PDF

A PDF places every piece of text by itself, so a number that looks whole on the page can be spread out in the text. chdsweep asks `pdftotext` for the text as it is laid out on the page, and in that text, and only there, the groups of a number may be:

- **several spaces apart, not always the same number:** a number with one group per table cell, at tab stops, or in a fixed-width report;
- **over the end of a line:** the first groups at the end of one line and the rest at the start of the next, as in a letter. One line break per number, not an empty line and not the next page.

```
Jansen        4556      7375    8689     9855     10,00
... so that the card number 4556 7375
8689 9855 is broken over two lines ...
```

Not found in a PDF: a number set with wide letter spacing by the program that made the PDF, which comes out with every digit apart; and a column of four-digit numbers, each on its own line.

## Text encodings

- **ASCII and UTF-8:** read as they are.
- **UTF-16**, as Windows tools write it (PowerShell output, "Unicode text" exports, SQL Server): found, with or without a byte-order mark, little or big endian. This also works for a text column inside a binary file, such as a database file.

## Track data

The magnetic stripe formats are recognised and reported as track 1 or track 2:

```
%B4556737586899855^JANSEN/P^2712...        track 1
;4556737586899855=27121010000000000?       track 2
```

## Where it looks

- Every file in the scope, whatever its name or type: the bytes are searched, not only text files.
- Inside tar, zip and gz archives and office documents (which are zip files), also nested.
- The text inside PDF files, through `pdftotext`; a hit names the page.
- The system journal.

See [scanning.md](scanning.md) for the scope and the limits.

## Not detected

| Written as | Example | Why not |
|---|---|---|
| Other groupings | `455673-7586-899855`, `455673 7586899855` | no card is written that way, and loose groupings match many other numbers |
| Other separators | `4556/7375/8689/9855`, `4556 - 7375 - 8689 - 9855` | the same |
| Mixed separators | `4556-7375 8689-9855` | the same |
| Every digit apart | `4 5 5 6 7 3 7 5 ...` | the same |
| Groups on separate lines | | the same; in the text of a PDF one line break is allowed, see above |
| Glued to letters, digits or `_` | `ref4556737586899855abc`, `card_4556737586899855` | rule 3 above |
| Masked or cut short | `455673******9855` | not a full card number |
| In pictures | a scanned page, a photo, a screenshot | pictures are not read |
| Encrypted, or encoded as base64 or hex | | the digits are not there to find |
| In bz2, xz or zstd files | | not unpacked yet |

## Likely false positives

A hit that one of these rules matches is kept and shown in the report as a likely false positive, with the rule and its reason. The rules can be switched off one by one in `/etc/chdsweep/fp-rules.conf` ([example](../etc/fp-rules.conf.example)).

| Rule | Marks a number when |
|---|---|
| `test-card` | it is a published test card number |
| `repeat-digits` | it has at most two different digits after the first six |
| `sequence` | its digits run up or down in sequence |
| `low-luhn-ratio` | few of the card-like numbers in the file pass the Luhn check (under 30% of 20 or more): most likely random numbers |
| `id-keyword` | a label just before it names it as something else (order id, IMEI, session, ...) |
| `inside-token` | it is part of a longer identifier, joined to more digits by `.` `/` `:` `=` or `-` |
| `package-file` | the file belongs to an installed package and is unchanged since installation |
| `test-path` | the file is in a test or library folder and another rule marks the number too |
| `binary-context` | it sits between bytes that are not text |

Tables of four-digit numbers in columns can look like a grouped card number; one in ten of those passes the Luhn check by chance. In a file with many of them the `low-luhn-ratio` rule marks them.
