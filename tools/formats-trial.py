#!/usr/bin/env python3
"""Formats trial: which written forms of a card number does this chdsweep find?

  python3 tools/formats-trial.py /path/to/chdsweep

Makes 15 made-up, Luhn-valid numbers (12 to 19 digits, eight brands), writes each of them
in every form below, one case per file in a temporary folder, scans that folder and
prints a table: one row per written form, one column per number. Every row says what is
expected (found, or not found on purpose); the trial fails when a row is different.
docs/detection.md describes the forms. Reads nothing else and needs no root.

The PDF rows need pdftotext (poppler-utils); without it they are skipped and said so.
"""
import json, os, random, shutil, subprocess, sys, tempfile, zlib

BIN = sys.argv[1] if len(sys.argv) > 1 else "chdsweep"
rnd = random.Random(20261116)


def luhn_digit(body):
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def card(prefix, length):
    while True:
        body = prefix + "".join(rnd.choice("0123456789") for _ in range(length - len(prefix) - 1))
        n = body + luhn_digit(body)
        if len(set(n[6:])) > 3:          # not a run of the same digits
            return n


# brand, first digits, length
CARDS = [("visa", "4539", 13), ("visa", "4556", 16), ("visa", "4716", 19),
         ("mastercard", "5412", 16), ("mastercard", "2221", 16),
         ("amex", "3714", 15), ("amex", "3400", 15),
         ("diners", "3605", 14), ("discover", "6011", 16), ("discover", "6500", 19),
         ("jcb", "3528", 16), ("unionpay", "6221", 16), ("unionpay", "6221", 19),
         ("maestro", "5018", 12), ("maestro", "6759", 18)]


def groups(n, sizes):
    out, pos = [], 0
    for s in sizes:
        if pos >= len(n):
            break
        out.append(n[pos:pos + s])
        pos += s
    if pos < len(n):
        out.append(n[pos:])
    return out


def by4(n):
    return groups(n, [4] * 5)


def native(n):   # how the card itself prints it
    return groups(n, {15: [4, 6, 5], 14: [4, 6, 4]}.get(len(n), [4] * 5))


def pdf(text):
    """A one-page PDF with this line of text, compressed as in nearly every PDF."""
    esc = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    s = zlib.compress(("BT /F1 12 Tf 72 720 Td (%s) Tj ET" % esc).encode())
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
            b"/Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(s) + s + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, off = b"%PDF-1.4\n", []
    for i, o in enumerate(objs):
        off.append(len(out))
        out += b"%d 0 obj\n" % (i + 1) + o + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 6\n0000000000 65535 f \n" + b"".join(b"%010d 00000 n \n" % n for n in off)
    return out + b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % x


def line(text):
    return ("customer paid with " + text + " on monday\n").encode()


# (label, how the number is written, expected: True found, False not found on purpose)
FORMATS = [
    ("xxxxxxxxxxxxxxxx  (no separator)",        lambda n: n, True),
    ("xxxx xxxx xxxx xxxx  (spaces)",           lambda n: " ".join(by4(n)), True),
    ("xxxx-xxxx-xxxx-xxxx  (dashes)",           lambda n: "-".join(by4(n)), True),
    ("as printed on the card (amex 4-6-5)",     lambda n: " ".join(native(n)), True),
    ("as printed, with dashes",                 lambda n: "-".join(native(n)), True),
    ("xxxx.xxxx.xxxx.xxxx  (dots)",             lambda n: ".".join(by4(n)), True),
    ("xxxx  xxxx  xxxx  xxxx  (two spaces)",    lambda n: "  ".join(by4(n)), True),
    ("xxxx<tab>xxxx<tab>xxxx  (tabs)",          lambda n: "\t".join(by4(n)), True),
    ("xxxx+xxxx+xxxx+xxxx  (web form)",         lambda n: "+".join(by4(n)), True),
    ("xxxx%20xxxx%20xxxx  (URL)",               lambda n: "%20".join(by4(n)), True),
    ("xxxxxx-xxxx-xxxxxx  (6, 4, rest)",        lambda n: "-".join(groups(n, [6, 4])), False),
    ("xxxxxx xxxxxxxxxx  (first six apart)",    lambda n: " ".join(groups(n, [6])), False),
    ("xxxxxxxxxxxx-xxxx  (last four apart)",    lambda n: n[:-4] + "-" + n[-4:], False),
    ("xxxx/xxxx/xxxx/xxxx  (slashes)",          lambda n: "/".join(by4(n)), False),
    ("xxxx-xxxx xxxx-xxxx  (mixed)",            lambda n: "".join(g + ("-" if i % 2 == 0 else " ") for i, g in enumerate(by4(n))).rstrip("- "), False),
    ("xxxx - xxxx - xxxx  (dash with spaces)",  lambda n: " - ".join(by4(n)), False),
    ("x x x x x x x x  (every digit apart)",    lambda n: " ".join(n), False),
    ("groups on separate lines",                lambda n: "\n".join(by4(n)), False),
]
# The number inside other text or another kind of file. These give the whole file.
CONTEXTS = [
    ('"pan":"x"  (JSON)',                   lambda n: line('{"pan":"%s","exp":"12/27"}' % n), True),
    ("card=x&amount=  (URL)",               lambda n: line("card=%s&amount=10" % n), True),
    ("x,2027  (CSV field)",                 lambda n: line("jansen,%s,2027" % n), True),
    ("'x'  (SQL insert)",                   lambda n: line("INSERT INTO pay VALUES ('%s', 10);" % n), True),
    ("<pan>x</pan>  (XML)",                 lambda n: line("<pan>%s</pan>" % n), True),
    ("UTF-16 text file",                    lambda n: ("card %s paid" % n).encode("utf-16"), True),
    ("UTF-16, in groups of four",           lambda n: ("card %s paid" % " ".join(by4(n))).encode("utf-16"), True),
    ("PDF text",                            lambda n: pdf("paid with %s on monday" % n), "pdf"),
    ("PDF text, in groups of four",         lambda n: pdf("paid with %s on monday" % " ".join(by4(n))), "pdf"),
    ("textxtext  (letters on both sides)",  lambda n: line("ref%sabc" % n), False),
    ("check digit wrong",                   lambda n: line(n[:-1] + str((int(n[-1]) + 1) % 10)), False),
    ("inside a longer number",              lambda n: line("9" + n + "7"), False),
]

tmp = tempfile.mkdtemp(prefix="chdsweep-formats-")
root = os.path.join(tmp, "data")
os.makedirs(root)
numbers = [(b, card(p, l)) for b, p, l in CARDS]
check = subprocess.run([BIN, "check"], capture_output=True, text=True).stdout
have_pdf = "pdftotext   found" in check

for ci, (brand, n) in enumerate(numbers):
    for fi, (label, fn, want) in enumerate(FORMATS):
        with open(os.path.join(root, "f%02d_%02d.txt" % (fi, ci)), "wb") as f:
            f.write(line(fn(n)))
    for fi, (label, fn, want) in enumerate(CONTEXTS):
        ext = "pdf" if want == "pdf" else "txt"
        with open(os.path.join(root, "c%02d_%02d.%s" % (fi, ci, ext)), "wb") as f:
            f.write(fn(n))

out = os.path.join(tmp, "run.jsonl")
p = subprocess.run([BIN, "scan", "-q", "--no-lock", "-s", "journal_days=0", "-o", out, root],
                   capture_output=True, text=True)
found, full, files = {}, 0, len(os.listdir(root))
raw = open(out, "rb").read()
for _, n in numbers:
    full += raw.count(n.encode())
for l in raw.decode().splitlines():
    r = json.loads(l)
    if r["type"] == "hit":
        found.setdefault(os.path.basename(r["path"]), []).append(r)

version = subprocess.run([BIN, "version"], capture_output=True, text=True).stdout.split("\n")[0]
print("%s, %d files with %d numbers, scan exit code %d" % (version, files, len(numbers), p.returncode))
print("pdftotext: %s" % ("found" if have_pdf else "not found, the PDF rows are skipped"))
print()
print("numbers: " + "  ".join("%d=%s %d" % (i + 1, b, len(n)) for i, (b, n) in enumerate(numbers)))
print()
bad = 0


def table(kind, rows):
    global bad
    print("%-40s %s   found  expected" % ("", " ".join("%2d" % (i + 1) for i in range(len(numbers)))))
    for fi, (label, _, want) in enumerate(rows):
        cells, n_ok = [], 0
        for ci, (brand, n) in enumerate(numbers):
            ext = "pdf" if want == "pdf" else "txt"
            hits = found.get("%s%02d_%02d.%s" % (kind, fi, ci, ext), [])
            # found: one hit, masked, with the first six and the last four of this number
            good = len(hits) == 1 and hits[0]["masked"].startswith(n[:6]) and hits[0]["masked"].endswith(n[-4:]) \
                and hits[0]["digits"] == len(n) and hits[0]["brand"] == brand
            n_ok += good
            cells.append(" Y" if good else (" ." if not hits else " ?"))
        if want == "pdf" and not have_pdf:
            verdict, exp = "skipped", "all (needs pdftotext)"
        else:
            exp_n = len(numbers) if want else 0
            exp = "all" if want else "none"
            wrong_hits = sum(1 for c in cells if c == " ?")
            verdict = "ok" if n_ok == exp_n and not wrong_hits else "WRONG"
            bad += verdict == "WRONG"
        print("%-40s %s   %2d/%d  %-5s %s" % (label, " ".join(cells), n_ok, len(numbers), exp, verdict))


print("WRITTEN FORMS  (Y found, . not found, ? found as something else)")
table("f", FORMATS)
print()
print("INSIDE OTHER TEXT AND OTHER KINDS OF FILE")
table("c", CONTEXTS)
print()
if full:
    bad += 1
print("full numbers in the run file: %d (must be 0)" % full)
print("result: %s" % ("all rows as expected" if not bad else "%d rows or checks are WRONG" % bad))
shutil.rmtree(tmp)
sys.exit(1 if bad else 0)
