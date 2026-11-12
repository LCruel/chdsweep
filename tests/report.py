#!/usr/bin/env python3
"""Report test for chdsweep: scans small trees as two hosts and two dates, then
checks the merged report (Markdown, HTML, CSV), the triage file, the issuer lookup
and bin-update.

    python3 tests/report.py build/chdsweep

Every number here is made up. Needs only the Python standard library.
"""
import csv
import gzip
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/chdsweep")
HERE = os.path.dirname(os.path.abspath(__file__))
rnd = random.Random(11)
failures = []
checks = 0
all_numbers = set()


def check(cond, what):
    global checks
    checks += 1
    if not cond:
        failures.append(what)
        print("FAIL:", what)


def card(prefix, length=16):
    while True:
        body = prefix + "".join(rnd.choice("0123456789") for _ in range(length - len(prefix) - 1))
        total = 0
        for i, ch in enumerate(reversed(body)):
            v = int(ch) * (2 if i % 2 == 0 else 1)
            total += v - 9 if v > 9 else v
        number = body + str((10 - total % 10) % 10)
        if len(set(number[6:])) > 4:
            all_numbers.add(number)
            return number


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(text if isinstance(text, bytes) else text.encode())
    return path


def scan(root, out, host, start):
    """One run, then the header is rewritten as if it came from this host and date."""
    p = subprocess.run([BIN, "scan", "-q", "--no-lock", "-o", out, root],
                       capture_output=True, text=True)
    check(p.returncode in (0, 1), "scan exit code %d %s" % (p.returncode, p.stderr))
    lines = open(out, encoding="utf-8").read().splitlines()
    head = json.loads(lines[0])
    head["host"], head["start"] = host, start
    lines[0] = json.dumps(head)
    # paths as they would be on the host: without the temporary folder
    real = os.path.realpath(root)
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(l.replace(json.dumps(real)[1:-1], "") for l in lines) + "\n")


def report(tmp, name, *args, expect=0):
    prefix = os.path.join(tmp, name)
    p = subprocess.run([BIN, "report", "-o", prefix, *args], capture_output=True, text=True)
    check(p.returncode == expect, "report exit code %d, expected %d: %s" % (p.returncode, expect, p.stderr))
    if p.returncode:
        return None, None, None, p.stderr
    md = open(prefix + ".md", encoding="utf-8").read()
    html = open(prefix + ".html", encoding="utf-8").read()
    rows = list(csv.DictReader(open(prefix + ".csv", encoding="utf-8", newline="")))
    for n in all_numbers:
        check(n not in md and n not in html and n not in open(prefix + ".csv").read(), "full number in a report")
    return md, html, rows, p.stderr


def table_rows(md, heading):
    """Rows (lists of cells) of the first table after a heading."""
    part = md.split(heading, 1)[1]
    rows = []
    for line in part.splitlines()[1:]:
        if line.startswith("|"):
            rows.append([c.strip().replace("\\_", "_").replace("\\*", "*") for c in line.strip("|").split(" | ")])
        elif rows:
            break
    return rows[2:] if len(rows) > 1 else []


def unknown_prefix():
    with gzip.open(os.path.join(HERE, "..", "data", "bin-table.csv.gz"), "rt", encoding="utf-8") as f:
        have = {line.split(",")[0] for line in f if not line.startswith("#")}
    return next(str(n) for n in range(400000, 500000) if str(n) not in have)


def have_libarchive():
    return "libarchive  found" in subprocess.run([BIN, "check"], capture_output=True, text=True).stdout


def main():
    tmp = tempfile.mkdtemp(prefix="chdsweep-report-")
    try:
        run_tests(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("report tests: %d checks, %d failed" % (checks, len(failures)))
    sys.exit(1 if failures else 0)


def run_tests(tmp):
    unknown = unknown_prefix()
    shared = card("453201")            # in two files on web01 and also on db01
    visa2, mc, amex, odd = card("453201"), card("541275"), card("378282", 15), card(unknown)
    accepted, later = card("601100"), card("541275")
    archives = have_libarchive()

    web = os.path.join(tmp, "web")
    write(web, "srv/shop/logs/pay.log", "paid %s\npaid %s\npaid %s\n" % (shared, mc, amex))
    export = write(web, "srv/shop/export/cards.csv", "%s\n%s\n%s\n" % (shared, visa2, odd))
    write(web, "srv/shop/tests/fixture.txt", "4111111111111111\n")
    write(web, "home/app/notes.txt", "sample for the supplier: %s\n" % accepted)
    if archives:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = (mc + "\n").encode()
            info = tarfile.TarInfo("dump/orders.sql")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        write(web, "backup/old.tar.gz", buf.getvalue())
    write(web, "big/skipme.bin", b"x" * 4096)
    os.chmod(os.path.join(web, "big/skipme.bin"), 0)

    run1, run2, run3 = (os.path.join(tmp, n) for n in ("web-1.jsonl", "web-2.jsonl", "db-1.jsonl"))
    scan(web, run1, "web01", "2026-10-01T02:00:00Z")
    os.remove(export)                                        # cleaned up
    write(web, "srv/shop/logs/new.log", "paid %s\n" % later)  # and a new one appeared
    scan(web, run2, "web01", "2026-11-01T02:00:00Z")
    db = os.path.join(tmp, "db")
    write(db, "var/lib/dump/customers.txt", "%s\n" % shared)
    scan(db, run3, "db01", "2026-11-02T02:00:00Z")

    left_run = os.path.join(tmp, "left.jsonl")
    subprocess.run([BIN, "scan", "-q", "--no-lock", "-x", "*.bak", "-x", db + "/var/*.old", "-o", left_run, db], capture_output=True)
    triage = write(tmp, "triage.csv",
                   "# reviewed hits\nhost,path,masked,reason,who,date,ticket\n"
                   "web01,*/notes.txt,*,\"Sample number from the supplier, not issued\",D. Example,2025-06-01,T-12\n"
                   "web01,/srv/old/*,*,Gone long ago,D. Example,2026-09-01,\n"
                   "db01,/var/lib/dump/customers.txt,%s******%s,Checked with the bank,D. Example,2026-10-20,T-15\n"
                   % (visa2[:6], visa2[-4:]))
    overrides = write(tmp, "bin-overrides.csv", "%s,VISA,DEBIT,,Our Own Test Bank,NL\n" % odd[:8])

    md, html, rows, _ = report(tmp, "all", "--now", "2026-11-12", "--triage", triage,
                               "--bin-overrides", overrides, "--show-marked=all", run1, run2, run3)
    if md is None:
        return
    check(html.startswith("<!doctype html>") and "<table>" in html and "</html>" in html, "HTML page")
    check("Cardholder data discovery report" in md and "from 3 run files" in md, "title")

    # summary: newest run per host. web01 now: pay.log 3 (+1 in the archive) + new.log 1 open,
    # fixture 1 likely, notes 1 accepted. db01: 1 open (its triage entry is for another number).
    n_open_web = 5 if archives else 4
    s = {r[0]: r for r in table_rows(md, "## Summary")}
    check(s["web01"][1] == str(n_open_web) and s["web01"][2] == "1" and len(s["web01"]) == 5,
          "summary web01: %s" % s.get("web01"))
    # root can read the file made unreadable above, so as root nothing is skipped
    coverage = "full" if os.geteuid() == 0 else "partial"
    check(s["web01"][3] == "2026-11-01T02:00:00Z" and s["web01"][4] == coverage, "newest run and coverage")
    check(s["db01"][1] == "1" and s["db01"][2] == "0" and s["db01"][4] == "full",
          "summary db01: %s" % s.get("db01"))
    check("%d suspected PANs and 1 likely false positives, 1 accepted false positives on 2 hosts" % (n_open_web + 1) in md,
          "totals")

    loc = {(r[0], r[1]): r for r in table_rows(md, "### Per location")}
    check(loc[("web01", "/srv/shop/logs")][2] == "4" and loc[("web01", "/srv/shop/logs")][3] == "2", "location roll-up")
    check(("web01", "/srv/shop/export") not in loc, "the removed file is not counted any more")
    check(loc[("db01", "/var/lib/dump")][2] == "1", "location db01")
    # the report starts with where, then every file and number, then what was set aside
    order = [md.index(h) for h in ("## Where the cards are", "### Suspected PANs per file", "## Likely false positives",
                                   "## Accepted false positives", "## Summary per host", "## Brands and issuers",
                                   "## Coverage", "## Credits and licences")]
    check(order == sorted(order), "section order")
    files = table_rows(md, "### Suspected PANs per file")
    pay = [r for r in files if r[0] == "web01" and r[1] == "/srv/shop/logs/pay.log"]
    check(len(pay) == 3 and all("*" in r[2] and r[5] == "1" for r in pay), "per file: each distinct number once, masked: %s" % pay)
    check(len(files) == n_open_web + 1 and "Top " not in md, "per file: every open hit, no top list (%d rows)" % len(files))
    check(not any("fixture.txt" in r[1] or "notes.txt" in r[1] for r in files), "per file: open hits only")
    types = {r[0]: r[1] for r in table_rows(md, "### Suspected PANs per file type")}
    check(types.get("log") == "4" and types.get("text") == "1", "file types: %s" % types)
    if archives:
        check(types.get("archive member") == "1", "archive member type")
        check(any(r[1] == "/backup/old.tar.gz (inside it: dump/orders.sql)" for r in table_rows(md, "### Suspected PANs per file")),
              "per file: a hit inside an archive names the file inside it")
    hb = {r[0]: r[1:] for r in table_rows(md, "### Host by brand")}
    check(sum(int(x) for x in hb["web01"]) == n_open_web and sum(int(x) for x in hb["db01"]) == 1, "host by brand")

    brands = {r[0]: r[1] for r in table_rows(md, "### Per brand")}
    check(brands.get("visa") == "2" and brands.get("amex") == "1", "brands: %s" % brands)
    issuers = {r[0]: r for r in table_rows(md, "### Per issuer")}
    check(issuers["BANCO CAMINOS, S.A."][1] == "ES" and issuers["BANCO CAMINOS, S.A."][2] == "2", "issuer with country")
    check("AMERICAN EXPRESS US CARS" in issuers, "amex issuer")
    check("CC BY 4.0" in md and "Venelin Kochev" in md and "built-in" in md and "pulled 2026-11-12" in md,
          "BIN attribution, source and date")
    check("(100%)" in md, "share of hits with a known prefix")

    check("hash" not in md.split("## Credits")[0].lower() and "Distinct cards" not in md
          and "Cards in more than one file" not in md, "no hash and no distinct-card count in the report")

    rules = {r[0]: r for r in table_rows(md, "## Likely false positives")}
    check(rules["test-card"][1] == "1" and rules["test-path"][1] == "1", "likely false positives per rule")
    check("published test card number" in rules["test-card"][3] and " of " not in rules["test-card"][3],
          "the rule's criterion, not the values of one hit")
    marked = table_rows(md, "### Every marked hit")
    check(len(marked) == 1 and marked[0][1] == "/srv/shop/tests/fixture.txt", "--show-marked=all lists the hit")

    tri = table_rows(md, "## Accepted false positives")
    states = [r[8] for r in tri]
    check(len(tri) == 3 and tri[0][7] == "1" and states[0].startswith("review again"), "old triage entry: %s" % states)
    check(states[1].startswith("stale") and states[2].startswith("stale"), "stale triage entries")
    check("3 entries; 2 stale" in md and "1 due for review" in md, "triage summary")

    check("### web01: 2026-11-01T02:00:00Z against 2026-10-01T02:00:00Z" in md, "difference heading")
    check("1 new hits, 3 hits gone, 0 hits with changed marks" in md, "difference counts")
    diff = table_rows(md, "### web01: 2026-11-01")
    check(sorted(r[0] for r in diff) == ["gone", "gone", "gone", "new"], "difference rows")
    check(any(r[0] == "new" and r[1] == "/srv/shop/logs/new.log" for r in diff), "the new hit")

    trend = table_rows(md, "## Trend")
    check([r[1] for r in trend] == ["2026-11-02T02:00:00Z", "2026-10-01T02:00:00Z", "2026-11-01T02:00:00Z"],
          "trend: every run, per host in date order")
    check(trend[1][2] == str(n_open_web + 2), "open hits in the older run: %s" % trend[1][2])
    cov = table_rows(md, "## Coverage")
    check(len(cov) == 2 and all(len(r) == 9 for r in cov), "coverage table")
    paths = table_rows(md, "### Scanned paths")
    check(any(r[1] == "2" and "web01" in r[2] and "db01" in r[2] for r in paths), "scanned paths with their hosts: %s" % paths)
    md5, _, _, _ = report(tmp, "left", left_run)
    left = table_rows(md5, "### Excluded from the scan")
    check(any(r[0] == "every scanned path" and r[1] == "*.bak" and r[2] == "1" for r in left)
          and any(r[0] == db and r[1] == "var/*.old" for r in left) and "No excludes were set" in md,
          "excludes are listed in the coverage: %s" % left)
    check("(content)" not in md, "a compressed single file is not shown as a file inside an archive")
    if os.geteuid() != 0:
        why = table_rows(md, "### Not scanned, by reason")
        check(any(r[0] == "not scanned: unreadable" and "could not be opened" in r[1] and r[2] == "1" and r[3] == "web01" for r in why),
              "skipped by reason: %s" % why)
        skipped = table_rows(md, "### Not scanned, the files")
        check(any(r[1] == "/big/skipme.bin" and len(r) == 2 for r in skipped) and "not scanned: unreadable (Permission denied): 1 file. The file" in md,
              "skipped files listed per reason: host, path")

    # CSV: every hit of every run
    check(len(rows) == sum(1 for f in (run1, run2, run3) for l in open(f) if '"type":"hit"' in l.replace(" ", "")),
          "CSV has every hit (%d)" % len(rows))
    by_status = {}
    for r in rows:
        if r["newest_run"] == "yes":
            by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    check(by_status == {"suspected PAN": n_open_web + 1, "likely false positive": 1, "accepted false positive": 1},
          "CSV statuses: %s" % by_status)
    acc = [r for r in rows if r["status"] == "accepted false positive"]
    check(all(r["triage_reason"] == "Sample number from the supplier, not issued" for r in acc), "CSV triage reason")
    check(any(r["issuer"] == "BANCO CAMINOS, S.A." and r["country"] == "ES" for r in rows), "CSV issuer")
    odd_rows = [r for r in rows if r["masked"].startswith(odd[:6])]
    check(odd_rows and all(r["issuer"] == "Our Own Test Bank" and r["country"] == "NL" for r in odd_rows),
          "overrides file: eight-digit prefix")
    check(all("keyed_hash" not in r for r in rows), "CSV has no hash column")

    # credits travel with every report
    for name, text in (("Markdown", md), ("HTML", html)):
        check("Credits and licences" in text and "D.J.S. van den Akker" in text and "MIT License" in text,
              name + ": tool credit")
        check("ccsrch" in text and "Adam Caudill" in text and "PANhunt" in text,
              name + ": inspiration credit")
        check("Venelin Kochev" in text and "CC BY 4.0" in text and "creativecommons.org/licenses/by/4.0" in text
              and "github.com/venelinkochev/bin-list-data" in text and "trimmed" in text,
              name + ": issuer data credit, licence, source and change note")
    check(all(("CC BY 4.0" in r["issuer_data_credit"]) == (r["issuer"] not in ("", "Our Own Test Bank"))
              for r in rows), "CSV: every row with issuer data carries the credit")
    check(all(r["issuer_data_credit"] == "local overrides file" for r in odd_rows), "CSV: overrides are not credited upstream")
    check(any(r["marks"] == "test-card;repeat-digits;test-path" for r in rows), "CSV marks column")

    # without triage, overrides and marked detail
    md2, _, rows2, _ = report(tmp, "plain", "--now", "2026-11-12", "--show-marked=none", run1, run2, run3)
    check("ccepted false positive" not in md2 and "Every marked hit" not in md2, "no triage, --show-marked=none")
    check(not any(r["status"].startswith("accepted") for r in rows2), "no accepted hits without a triage file")
    odd2 = [r for r in rows2 if r["masked"].startswith(odd[:6])]
    check(odd2 and all(r["issuer"] == "" for r in odd2) and "unknown issuer" in md2, "unknown issuer without overrides")
    check("Warning: the BIN table" not in md2, "no age warning for a fresh table")
    md3, _, _, _ = report(tmp, "old", "--now", "2027-06-01", run3)
    check("Warning: the BIN table is" in md3 and "No host has an earlier run" in md3, "BIN table age warning")


    # an unfinished run file is used, with a warning
    cut = os.path.join(tmp, "cut.jsonl")
    with open(cut, "w") as f:
        f.writelines(open(run3).readlines()[:-1])
    md5, _, _, _ = report(tmp, "cut", cut)
    check("did not finish" in md5 and "incomplete" in md5, "incomplete run is flagged")

    notrun = write(tmp, "notes.txt", "hello\n")
    report(tmp, "bad", notrun, expect=2)
    report(tmp, "bad", os.path.join(tmp, "missing.jsonl"), expect=2)

    # bin-update: a downloaded data set becomes a dated table that replaces the built-in one
    upstream = write(tmp, "upstream.csv",
                     "BIN,Brand,Type,Category,Issuer,IssuerPhone,IssuerUrl,isoCode2,isoCode3,CountryName\n"
                     "453201,VISA,CREDIT,GOLD,\"NEW NAME,  BANK\",1,http://x,ES,ESP,SPAIN\n"
                     "453201,VISA,DEBIT,,SECOND LINE IGNORED,1,http://x,ES,ESP,SPAIN\n"
                     "12,BAD,,,TOO SHORT,,,,,\n"
                     "541275,MASTERCARD,CREDIT,,Other Bank,,,US,USA,UNITED STATES\n")
    bindir = os.path.join(tmp, "bin")
    p = subprocess.run([BIN, "bin-update", "--dir", bindir, "--commit", "abc123", "--date", "2027-01-15", upstream],
                       capture_output=True, text=True)
    check(p.returncode == 0 and "2 entries" in p.stdout, "bin-update: %s %s" % (p.stdout, p.stderr))
    table = gzip.open(os.path.join(bindir, "bin-table-2027-01-15.csv.gz"), "rt").read().splitlines()
    check(table[0].startswith("# chdsweep BIN table") and "upstream_commit=abc123" in table[0]
          and "pulled=2027-01-15" in table[0] and "entries=2" in table[0], "table header")
    check(table[1:] == ['453201,VISA,CREDIT,GOLD,"NEW NAME, BANK",ES', "541275,MASTERCARD,CREDIT,,Other Bank,US"],
          "table lines: %s" % table[1:])
    md6, _, rows6, _ = report(tmp, "newbin", "--now", "2027-02-01", "--bin-dir", bindir, run3)
    check("NEW NAME, BANK" in md6 and "upstream commit abc123" in md6 and "bin-table-2027-01-15" in md6,
          "a newer table file replaces the built-in set")
    md7, _, _, _ = report(tmp, "oldbin", "--bin-table", os.path.join(bindir, "bin-table-2027-01-15.csv.gz"), run2)
    check("Other Bank" in md7, "--bin-table picks a table")
    p = subprocess.run([BIN, "bin-update", "--dir", bindir, notrun], capture_output=True, text=True)
    check(p.returncode == 2 and "no column" in p.stderr, "bin-update refuses another file")


if __name__ == "__main__":
    main()
