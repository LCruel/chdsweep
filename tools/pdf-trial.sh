#!/bin/sh
# PDF trial: PDF files made by real programs, each with made-up card numbers, scanned with
# chdsweep. The tests build their PDFs by hand; this checks what office programs and
# print-to-PDF tools write. Needs Docker and fetches about 400 MB of packages, so it is
# not part of "make test" or of the release build.
#
#   tools/pdf-trial.sh               from the repository root
#
# In a Debian 12 container it builds chdsweep from this source, makes the PDFs with
# LibreOffice (Writer, Calc, an HTML table), Ghostscript and ReportLab, scans them and
# checks the number of hits per file. Ends with "all files as expected" when all is well.
set -u
if [ "${1:-}" != --inside ]; then
    src=$(pwd)
    [ -f "$src/Makefile" ] || { echo "run from the repository root" >&2; exit 2; }
    exec docker run --rm -v "$src:/src:ro" debian:12 sh /src/tools/pdf-trial.sh --inside
fi

export DEBIAN_FRONTEND=noninteractive
(apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev zlib1g-dev libarchive13 libssl3 \
    poppler-utils ghostscript enscript python3 python3-reportlab libreoffice-writer-nogui libreoffice-calc-nogui \
    fonts-dejavu-core) >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
cp -r /src /build && cd /build && make BUILD=/b >/tmp/make.log 2>&1 || { tail -5 /tmp/make.log; exit 1; }
B=/b/chdsweep
mkdir -p /w/out && cd /w

# made-up, Luhn-valid
A=4556737586899855; A4="4556 7375 8689 9855"; AD="4556-7375-8689-9855"
X4="3714 496353 98431"
cat > text.txt <<EOF
Invoice 2026-118
Paid by card $A on monday.
Second card $A4 on tuesday.
Third card $AD on wednesday.
American Express $X4 on thursday.
EOF
cat > table.html <<EOF
<html><body><h1>Payments</h1>
<table border="1"><tr><th>Customer</th><th>Card</th><th>Amount</th></tr>
<tr><td>Jansen</td><td>$A</td><td>10,00</td></tr>
<tr><td>De Vries</td><td>$A4</td><td>12,50</td></tr>
<tr><td>Bakker</td><td>$X4</td><td>99,00</td></tr></table>
<p>Split over cells:</p>
<table border="1"><tr><td>4556</td><td>7375</td><td>8689</td><td>9855</td></tr></table>
</body></html>
EOF
printf 'customer,card,amount\nJansen,%s,10\nDe Vries,%s,12\n' "$A" "$A4" > sheet.csv

soffice --headless --convert-to pdf:writer_pdf_Export --outdir out text.txt >/dev/null 2>&1 && mv out/text.pdf out/libreoffice-writer-text.pdf
soffice --headless --convert-to pdf:writer_web_pdf_Export --outdir out table.html >/dev/null 2>&1 && mv out/table.pdf out/libreoffice-html-table.pdf
soffice --headless --convert-to pdf:calc_pdf_Export --outdir out sheet.csv >/dev/null 2>&1 && mv out/sheet.pdf out/libreoffice-calc-sheet.pdf
enscript -q -B -p text.ps text.txt && ps2pdf text.ps out/ghostscript-enscript.pdf
ps2pdf -dPDFSETTINGS=/prepress -dCompatibilityLevel=1.7 text.ps out/ghostscript-pdf17.pdf
A="$A" A4="$A4" X4="$X4" python3 - <<'PY'
import os
from reportlab.lib.pagesizes import A4 as PAGE
from reportlab.pdfgen import canvas
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
A, A4, X4 = os.environ["A"], os.environ["A4"], os.environ["X4"]
c = canvas.Canvas("out/reportlab-canvas.pdf", pagesize=PAGE)
y = 800
for line in open("text.txt").read().splitlines():
    c.drawString(60, y, line)
    y -= 18
c.showPage()
c.drawString(60, 800, "Page two: card %s again." % A)
c.save()
doc = SimpleDocTemplate("out/reportlab-table.pdf", pagesize=PAGE)
doc.build([Paragraph("Payments", getSampleStyleSheet()["Heading1"]),
           Table([["Customer", "Card", "Amount"], ["Jansen", A, "10,00"], ["De Vries", A4, "12,50"],
                  ["Bakker", X4, "99,00"]]),
           Table([["4556", "7375", "8689", "9855"]])])
PY
# a scanned page: the same text, only as a picture
gs -q -dNOPAUSE -dBATCH -sDEVICE=png16m -r100 -sOutputFile=page.png out/ghostscript-enscript.pdf 2>/dev/null
python3 - <<'PY'
from reportlab.pdfgen import canvas
c = canvas.Canvas("out/picture-only.pdf")
c.drawImage("page.png", 0, 0, width=595, height=842)
c.save()
PY

$B version | head -1
$B check | grep -E "pdftotext"
$B scan -q --no-lock -s journal_days=0 -o run.jsonl out
echo "scan exit code $? (1 is expected: the picture-only PDF cannot be read)"
echo
python3 - <<'PY'
import collections, json, os, sys
# file: (numbers in it, what must be said about it)
EXPECT = {
    "libreoffice-writer-text.pdf": (4, None), "libreoffice-html-table.pdf": (4, None),
    "libreoffice-calc-sheet.pdf": (2, None), "ghostscript-enscript.pdf": (4, None),
    "ghostscript-pdf17.pdf": (4, None), "reportlab-canvas.pdf": (5, None),
    "reportlab-table.pdf": (4, None), "picture-only.pdf": (0, "PDF has no text"),
}
hits, skips, raw = collections.defaultdict(list), {}, open("run.jsonl").read()
for l in raw.splitlines():
    r = json.loads(l)
    if r["type"] == "hit":
        hits[os.path.basename(r["path"])].append(r)
    if r["type"] == "skip":
        skips[os.path.basename(r["path"])] = r["reason"]
bad = 0
print("%-30s %-26s %4s %4s  %s" % ("file", "made by", "hits", "want", "pages, and what is said about the file"))
for f, (want, said) in sorted(EXPECT.items()):
    if not os.path.exists("out/" + f):
        print("%-30s NOT MADE" % f)
        bad += 1
        continue
    prod = os.popen("pdfinfo out/%s 2>/dev/null | grep '^Producer' | cut -c17-" % f).read().strip()[:25]
    hs = hits.get(f, [])
    ok = len(hs) == want and all(h.get("page") for h in hs) and (said is None or said in skips.get(f, ""))
    bad += not ok
    pages = ",".join(sorted({"p%s" % h.get("page") for h in hs})) or "-"
    print("%-30s %-26s %4d %4d  %s%s%s" % (f, prod, len(hs), want, pages,
                                          ("  [" + skips[f] + "]") if f in skips else "", "" if ok else "   WRONG"))
full = sum(raw.count(n) for n in ("4556737586899855", "371449635398431"))
bad += full > 0
print()
print("full numbers in the run file: %d (must be 0)" % full)
print("result: %s" % ("all files as expected" if not bad else "%d files or checks are WRONG" % bad))
sys.exit(1 if bad else 0)
PY
