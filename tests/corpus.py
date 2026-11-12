#!/usr/bin/env python3
"""Corpus test for chdsweep: builds a folder tree of fake, Luhn-valid numbers and
checks the run file of the real binary against what each file must give.

    python3 tests/corpus.py build/chdsweep

Every number here is made up. Needs only the Python standard library. The archive
tests run when `chdsweep check` finds libarchive, and are reported as skipped when not.
"""
import fcntl
import gzip
import hashlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "build/chdsweep")
rnd = random.Random(2026)
failures = []
BASE = 0              # exit code of a run with nothing skipped; set in main()
checks = 0
all_numbers = set()   # every full number written to the corpus; none may be in a run file


def check(cond, what):
    global checks
    checks += 1
    if not cond:
        failures.append(what)
        print("FAIL:", what)


def luhn_digit(body):
    total = 0
    for i, ch in enumerate(reversed(body)):
        v = int(ch)
        if i % 2 == 0:
            v *= 2
            if v > 9:
                v -= 9
        total += v
    return str((10 - total % 10) % 10)


def card(prefix="4539", length=16):
    """A real-looking number: Luhn-valid, not a test card, no repeats or sequences."""
    while True:
        body = prefix + "".join(rnd.choice("0123456789") for _ in range(length - len(prefix) - 1))
        number = body + luhn_digit(body)
        if len(set(number[6:])) > 4:
            all_numbers.add(number)
            return number


def grouped(number, sep=" "):
    sizes = {16: (4, 4, 4, 4), 15: (4, 6, 5), 19: (4, 4, 4, 4, 3)}[len(number)]
    parts, pos = [], 0
    for s in sizes:
        parts.append(number[pos:pos + s])
        pos += s
    return sep.join(parts)


def write(root, rel, data):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    return path


def run(root, *args, env=None, expect=None):
    out = os.path.join(root, "..", "run-%d.jsonl" % rnd.randrange(10**9))
    e = dict(os.environ)
    e.update(env or {})
    p = subprocess.run([BIN, "scan", "-q", "--no-lock", "-o", out, *args, root],
                       env=e, capture_output=True, text=True)
    if expect == 0:
        expect = BASE   # without libarchive a run is partial by design, also with no archive in the tree
    if expect is not None:
        check(p.returncode == expect, "exit code %d, expected %d (%s) %s" % (p.returncode, expect, args, p.stderr))
    with open(out, "rb") as f:
        raw = f.read()
    for n in all_numbers:
        check(n.encode() not in raw, "full number in the run file")
    lines = [json.loads(line) for line in raw.decode().splitlines()]
    check(lines[0]["type"] == "header" and lines[-1]["type"] == "end", "run file has header and end")
    return {
        "header": lines[0],
        "end": lines[-1],
        "hits": [l for l in lines if l["type"] == "hit"],
        "skips": [l for l in lines if l["type"] == "skip"],
        "stderr": p.stderr,
        "code": p.returncode,
    }


def hits_in(result, root, rel):
    path = os.path.realpath(os.path.join(root, rel))
    return [h for h in result["hits"] if h["path"] == path]


def marks(hit):
    return sorted(m["rule"] for m in hit["marks"])


def test_plain(tmp):
    """Real-looking cards in every format are open hits; look-alikes are not hits."""
    root = os.path.join(tmp, "plain")
    visa, mc, amex, v19 = card("4539"), card("5412"), card("3714", 15), card("4024", 19)
    disc, jcb, maestro, v13 = card("6011"), card("3566"), card("5018", 12), card("4716", 13)
    write(root, "app/cards.txt", "\n".join([
        "plain " + visa, "spaces " + grouped(mc), "dashes " + grouped(disc, "-"),
        "amex " + grouped(amex), "amex plain " + amex, "long " + grouped(v19),
        "csv," + jcb + ",2027-01", "<pan>" + maestro + "</pan>", "short " + v13, ""]))
    write(root, "app/track.log", "%%B%s^DOE/JANE^2712101?\n;%s=27121010000?\n" % (visa, mc))
    bad = visa[:-1] + str((int(visa[-1]) + 1) % 10)
    write(root, "app/not-cards.txt", "\n".join([
        "luhn fails " + bad,
        "too long 12" + visa + "34",
        "hash d41d8cd98f00b204e9800998ecf8427e" + visa + "abc",
        "mixed " + visa[:4] + "-" + visa[4:8] + " " + visa[8:12] + "-" + visa[12:],
        "pairs " + " ".join(visa[i:i + 2] for i in range(0, 16, 2)),
        "sha256 " + hashlib.sha256(b"x").hexdigest(), ""]))
    write(root, "empty.txt", b"")
    # a symbolic link to a file with a card outside the tree must not be followed
    outside = write(tmp, "outside/secret.txt", card("4539") + "\n")
    os.symlink(outside, os.path.join(root, "app", "link.txt"))
    os.symlink(os.path.dirname(outside), os.path.join(root, "linkdir"))

    r = run(root, "-j", "4", expect=0)
    cards = hits_in(r, root, "app/cards.txt")
    check(len(cards) == 9, "9 formats found, got %d" % len(cards))
    check(all(h["marks"] == [] for h in cards), "real-looking cards are open hits")
    check(sorted(h["brand"] for h in cards) == sorted(
        ["visa", "mastercard", "discover", "amex", "amex", "visa", "jcb", "maestro", "visa"]), "brands")
    by_len = {h["digits"]: h["masked"] for h in cards}
    check(by_len[16].count("*") == 4 and by_len[15].count("*") == 5, "masking keeps 8+4 for 16, 6+4 for 15")
    check(by_len[19].count("*") == 7 and by_len[13].count("*") == 3, "masking for 19 and 13 digits")
    tracks = hits_in(r, root, "app/track.log")
    check(sorted(h["track"] for h in tracks) == [1, 2], "track 1 and track 2")
    check(hits_in(r, root, "app/not-cards.txt") == [], "look-alikes are not hits")
    check(len(r["hits"]) == 11, "no hit through a symbolic link (%d hits)" % len(r["hits"]))
    c = r["end"]["counters"]
    check(c["symlinks_not_followed"] == 2 and c["open_hits"] == 11 and c["marked_hits"] == 0, "counters")
    check(r["end"]["complete"] is True and r["end"]["coverage"] == ("partial" if BASE else "full"),
          "end record: coverage")

    r6 = run(root, "-s", "keep_leading=6", expect=0)
    check(all(h["masked"].count("*") == h["digits"] - 10 for h in r6["hits"]), "keep_leading=6 keeps six")
    check(r6["header"]["keep_leading"] == "6", "header records keep_leading")

    rx = run(root, "-x", os.path.join(os.path.realpath(root), "app"), expect=0)
    check(rx["hits"] == [] and rx["end"]["counters"]["excluded"] == 1, "exclude a folder")
    rg = run(root, "-x", "*.log", expect=0)
    check(len(rg["hits"]) == 9, "exclude a glob")


def test_marks(tmp):
    """Each false-positive rule marks its case with a reason and marks nothing else."""
    root = os.path.join(tmp, "marks")
    real = card("4539")
    write(root, "shop/testcards.txt", "4111111111111111\n5555 5555 5555 4444\n378282246310005\n")
    write(root, "shop/ids.json", json.dumps({"imei": card("3714", 15), "tracking": card("4539"),
                                             "pan": real}, indent=1))
    write(root, "shop/versions.txt", "build 3.%s.12\noid 1.2.840.%s\n" % (card("4539"), card("5412")))
    table = "\n".join("4" + "".join(rnd.choice("0123456789") for _ in range(15)) for _ in range(500))
    write(root, "data/numbers.csv", table + "\n")
    write(root, "data/blob.bin", b"\x00\x01\x02" + card("4539").encode() + b"\x00\x03\x04" * 3)
    write(root, "src/tests/fixture.txt", "4242424242424242\n" + real + "\n")
    write(root, "data/cards.csv", "\n".join(card("5412") for _ in range(40)) + "\n")

    r = run(root, expect=0)
    t = hits_in(r, root, "shop/testcards.txt")
    check(len(t) == 3 and all("test-card" in marks(h) for h in t), "test-card")
    check(any(m["reason"] == "Known test card number" for m in t[0]["marks"]), "test-card reason")
    ids = {h["offset"]: h for h in hits_in(r, root, "shop/ids.json")}
    idm = sorted(marks(h) for h in ids.values())
    check(idm == [[], ["id-keyword"], ["id-keyword"]], "id-keyword marks the labelled IDs only: %s" % idm)
    reasons = sorted(m["reason"] for h in ids.values() for m in h["marks"])
    check(reasons == ["Labelled as imei in the file", "Labelled as tracking in the file"], "id-keyword reasons")
    v = hits_in(r, root, "shop/versions.txt")
    check(len(v) == 2 and all(marks(h) == ["inside-token"] for h in v), "inside-token")
    n = hits_in(r, root, "data/numbers.csv")
    check(20 < len(n) < 90 and all("low-luhn-ratio" in marks(h) for h in n), "low-luhn-ratio (%d hits)" % len(n))
    check("of 500)" in [m for m in n[0]["marks"] if m["rule"] == "low-luhn-ratio"][0]["reason"], "ratio reason")
    b = hits_in(r, root, "data/blob.bin")
    check(len(b) == 1 and marks(b[0]) == ["binary-context"], "binary-context")
    f = sorted(marks(h) for h in hits_in(r, root, "src/tests/fixture.txt"))
    check(f == [[], ["repeat-digits", "test-card", "test-path"]], "test-path only with another rule: %s" % f)
    good = hits_in(r, root, "data/cards.csv")
    check(len(good) == 40 and all(h["marks"] == [] for h in good), "a real card list is not marked")
    by_rule = r["end"]["marked_by_rule"]
    check(by_rule["test-card"] == 4 and by_rule["inside-token"] == 2 and by_rule["id-keyword"] == 2, "per-rule counts")
    check(r["end"]["counters"]["open_hits"] == 42, "open hits: %d" % r["end"]["counters"]["open_hits"])

    # rules file: a switched-off rule makes its hits open again; its checksum is in the header
    rules = write(tmp, "fp-rules.conf", "# strict\ntest-card = off\nrepeat-digits = off\nid-keyword.add = pan\n")
    rs = run(root, "-s", "rules_file=" + rules, expect=0)
    t = hits_in(rs, root, "shop/testcards.txt")
    check(sum(1 for h in t if h["marks"] == []) >= 2, "rule switched off: hits are open")
    check(all(h["marks"] for h in hits_in(rs, root, "shop/ids.json")), "added keyword marks")
    check(rs["header"]["rules"]["source"] == rules and "test-card" not in rs["header"]["rules"]["enabled"],
          "header names the rules file")
    check(rs["header"]["rules"]["checksum"] != r["header"]["rules"]["checksum"], "rules checksum")


def test_package_file(tmp):
    root = os.path.join(tmp, "pkg")
    doc = write(root, "usr/share/doc/libfoo/example.txt", "sample 4111111111111111 and " + card("4539") + "\n")
    changed = write(root, "usr/share/doc/libfoo/changed.txt", card("5412") + "\n")
    info = os.path.join(tmp, "dpkg-info")
    os.makedirs(info)
    real = os.path.realpath(doc)
    with open(os.path.join(info, "libfoo:amd64.md5sums"), "w") as f:
        f.write("%s  %s\n" % (hashlib.md5(open(doc, "rb").read()).hexdigest(), real.lstrip("/")))
        f.write("%s  %s\n" % ("0" * 32, os.path.realpath(changed).lstrip("/")))
    r = run(root, env={"CHDSWEEP_DPKG_INFO": info}, expect=0)
    d = hits_in(r, root, "usr/share/doc/libfoo/example.txt")
    check(len(d) == 2 and all("package-file" in marks(h) for h in d), "package-file marks an unchanged file")
    check(any(m["reason"] == "Unchanged file from package libfoo" for m in d[0]["marks"]), "package reason")
    c = hits_in(r, root, "usr/share/doc/libfoo/changed.txt")
    check(len(c) == 1 and c[0]["marks"] == [], "a changed package file stays open")


def test_boundary(tmp):
    """A number across the 64 KiB block boundary."""
    root = os.path.join(tmp, "big")
    same, other = card("4539"), card("5412")
    line = "x" * 99 + "\n"
    for i, shift in enumerate(range(-20, 21, 4)):
        pad = (line * 700)[:65536 + shift]
        write(root, "logs/app.%d.log" % i, pad + " " + same + " " + line * 700 + grouped(other) + "\n")
    r = run(root, "-j", "3", expect=0)
    check(len(r["hits"]) == 22, "every boundary position found (%d of 22)" % len(r["hits"]))
    check(all("hash" not in h for h in r["hits"]) and "keyed_hash" not in r["header"], "no hash in the run file")


def test_journal(tmp):
    """journal_days reads the system journal from journalctl; a stand-in script plays journalctl."""
    root = os.path.join(tmp, "journal")
    write(root, "empty.txt", "nothing here\n")
    number = card("4539")
    fake = write(tmp, "fakebin/journalctl", "#!/bin/sh\necho \"$@\" > %s/args\necho 'paid with %s today'\n" % (tmp, number))
    os.chmod(fake, 0o755)
    env = {"PATH": os.path.join(tmp, "fakebin") + ":" + os.environ["PATH"]}
    r = run(root, "-s", "journal_days=35", env=env, expect=0)
    check(len(r["hits"]) == 1 and r["hits"][0]["path"] == "journal (last 35 days)", "hit in the journal: %s" % r["hits"])
    check("--since=-35d" in open(os.path.join(tmp, "args")).read() and r["header"]["journal_days"] == 35,
          "journalctl is asked for the last 35 days")
    r = run(root, expect=0)
    check(r["hits"] == [] and r["header"]["journal_days"] == 0, "with a path given the journal is not read unless asked")
    write(tmp, "fakebin/journalctl", "#!/bin/sh\nexit 1\n")
    r = run(root, "-s", "journal_days=7", env=env, expect=1)
    check(any(s["path"] == "journal (last 7 days)" for s in r["skips"]), "a failing journalctl is listed as not scanned")


def test_health(tmp):
    """Exit codes report the health of the run."""
    root = os.path.join(tmp, "health")
    write(root, "ok.txt", card("4539") + "\n")
    secret = write(root, "locked.txt", card("4539") + "\n")
    big = write(root, "big.txt", "x" * 5000)
    if os.geteuid() != 0:
        os.chmod(secret, 0)
        r = run(root, expect=1)
        check(any("unreadable" in s["reason"] for s in r["skips"]), "unreadable file is listed")
        check(r["end"]["coverage"] == "partial" and r["end"]["counters"]["skipped"] == 1, "partial coverage")
        os.chmod(secret, 0o600)
    r = run(root, "-s", "max_file_size=1K", expect=1)
    check([s["path"] for s in r["skips"]] == [os.path.realpath(big)], "file over max_file_size is listed")

    def scan(*args):
        return subprocess.run([BIN, "scan", "-q", *args], capture_output=True, text=True)

    out = os.path.join(tmp, "x.jsonl")
    conf = write(tmp, "bad.conf", "path = /tmp\nnonsense = 1\n")
    p = scan("-c", conf, "--no-lock", "-o", out)
    check(p.returncode == 2 and "nonsense" in p.stderr, "bad config: exit 2 with the setting named")
    p = scan("--no-lock", "-o", os.path.join(tmp, "no-such-dir", "x.jsonl"), root)
    check(p.returncode == 2, "output not writable: exit 2")
    p = scan("--no-lock", "-o", out, os.path.join(tmp, "no-such-path"))
    check(p.returncode == 1, "path not found: partial")

    good = write(tmp, "good.conf", "# test\npath = %s\nthreads = 2\nmax_depth = 1\nkeep_leading = 6\n"
                                   "lock_file = %s\noutput_file = %s\nquiet = yes\n"
                 % (root, os.path.join(tmp, "lock"), out))
    p = subprocess.run([BIN, "scan", "-c", good], capture_output=True, text=True)
    check(p.returncode == BASE and (p.stderr == "" or BASE), "config file run: silent (%d %s)" % (p.returncode, p.stderr))
    head = json.loads(open(out).readline())
    check(head["threads"] == 2 and head["limits"]["max_depth"] == 1 and head["config_file"] == good,
          "header records the config")
    p = scan("--no-lock", "-o", out, root)
    head = json.loads(open(out).readline())
    check(head["threads"] == 1, "one worker by default")
    check(head["limits"]["max_hits_per_file"] == 10000, "10,000 hits listed per file by default")

    # max_hits_per_file: the file is read to the end, the hits over the limit are counted
    many = os.path.join(tmp, "many")
    write(many, "cards.txt", "".join(card() + "\n" for _ in range(30)))
    write(many, "few.txt", card() + "\n")
    r = run(many, "-s", "max_hits_per_file=10", expect=1)
    check(len(r["hits"]) == 11 and len(hits_in(r, many, "cards.txt")) == 10, "max_hits_per_file: ten listed, other files not affected")
    check([(s["reason"], s["hits_not_listed"]) for s in r["skips"]]
          == [("not fully listed: more hits than max_hits_per_file", 20)], "max_hits_per_file: the rest is counted")
    check(r["end"]["counters"]["hits_not_listed"] == 20 and r["end"]["coverage"] == "partial",
          "max_hits_per_file: counted at the end, partial coverage")
    r = run(many, "-s", "max_hits_per_file=0", expect=0)
    check(len(r["hits"]) == 31 and not r["skips"], "max_hits_per_file=0: no limit")

    # max_read_rate: 6000 bytes at 2K per second take about three seconds, and find the same
    slow = os.path.join(tmp, "slow")
    number = card()
    write(slow, "a.txt", "x" * 3000 + " " + number + " " + "x" * 3000)
    t0 = time.monotonic()
    p = scan("--no-lock", "-o", out, "-s", "max_read_rate=2K", slow)
    took = time.monotonic() - t0
    lines = [json.loads(l) for l in open(out)]
    check(p.returncode == 0 and 2.0 <= took <= 15.0, "max_read_rate slows the read (%.1f s)" % took)
    check(lines[0]["limits"]["max_read_rate"] == 2048 and sum(l["type"] == "hit" for l in lines) == 1,
          "max_read_rate: recorded in the header, same hit")

    with open(os.path.join(tmp, "lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        p = subprocess.run([BIN, "scan", "-c", good], capture_output=True, text=True)
        check(p.returncode == 3, "lock held by another run: exit 3")


def have_libarchive():
    return "libarchive  found" in subprocess.run([BIN, "check"], capture_output=True, text=True).stdout


def build_archives(root):
    a, b, c, d, e = card("4539"), card("5412"), card("3714", 15), card("6011"), card("4024")
    write(root, "logs/app.log.gz", gzip.compress(("rotated " + a + "\n").encode()))
    # text that libarchive would take for another archive format if every format were on
    write(root, "logs/table.csv.gz", gzip.compress(b"# name,value\na,1\nb,2\n" * 50))
    write(root, "logs/empty.gz", gzip.compress(b""))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in (("backup/orders.csv", b), ("backup/readme.txt", "nothing here")):
            info = tarfile.TarInfo(name)
            data = (text + "\n").encode()
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    write(root, "backup/site.tar.gz", buf.getvalue())
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("deep/card.txt", d + "\n")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("word/document.xml", "<w:t>" + grouped(c) + "</w:t>")
        z.writestr("inner.zip", inner.getvalue())
    write(root, "docs/letter.docx", buf.getvalue())
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.txt", "0" * (40 << 20))      # 40 MiB of zeros in a few kilobytes
        z.writestr("after.txt", e + "\n")
    write(root, "docs/bomb.zip", buf.getvalue())
    write(root, "docs/broken.zip", b"PK\x03\x04" + b"\x99" * 300)
    write(root, "plain.txt", card("4539") + "\n")


def test_archives(tmp):
    root = os.path.join(tmp, "arch")
    build_archives(root)
    real = os.path.realpath(root)

    big = ("-s", "max_ratio=100000")     # lets the 40 MiB of zeros through
    r = run(root, "-j", "2", *big, expect=1)   # partial: the broken zip
    by = {(h["path"][len(real) + 1:], h.get("member")): h for h in r["hits"]}
    check(("logs/app.log.gz", "(content)") in by, "gz content")
    check(("backup/site.tar.gz", "backup/orders.csv") in by, "tar.gz member")
    check(("docs/letter.docx", "word/document.xml") in by, "office document (zip member)")
    check(("docs/letter.docx", "inner.zip!deep/card.txt") in by, "zip inside zip")
    check(("docs/bomb.zip", "after.txt") in by, "large member within the limits is scanned")
    check(("plain.txt", None) in by and len(by) == 6, "6 hits in all (%d)" % len(by))
    check([s["path"][len(real) + 1:] for s in r["skips"]] == ["docs/broken.zip"], "broken archive is listed")
    check(r["end"]["counters"]["archives"] >= 5, "archive counter")

    r = run(root, "-s", "max_depth=1", *big, expect=1)
    check(any(s.get("member") == "inner.zip" and "max_depth" in s["reason"] for s in r["skips"]),
          "nesting over max_depth is listed")
    check(len(r["hits"]) == 5, "the nested hit is not scanned at max_depth=1")

    r = run(root, "-s", "max_unpacked=1M", *big, expect=1)
    check(any(s["path"].endswith("bomb.zip") and "max_unpacked" in s["reason"] for s in r["skips"]),
          "unpacked size limit is listed")
    r = run(root, expect=1)              # default limits: the zeros are over max_ratio
    check(any(s["path"].endswith("bomb.zip") and "max_ratio" in s["reason"] for s in r["skips"]),
          "compression ratio limit is listed")
    check(len(r["hits"]) == 5, "the member after the limit is not scanned")
    r = run(root, "-s", "max_members=1", *big, expect=1)
    check(sum(1 for s in r["skips"] if "max_members" in s["reason"]) == 3, "member limit is listed")


def test_missing_libraries(tmp):
    """Without the optional libraries: clear message, archives listed, exit 1."""
    root = os.path.join(tmp, "nolib")
    build_archives(root)
    env = {"CHDSWEEP_NO_OPTIONAL_LIBS": "1"}
    r = run(root, env=env, expect=1)
    check("libarchive not found" in r["stderr"] and "Effect:" in r["stderr"] and "Fix:" in r["stderr"],
          "message names the library, the effect and the fix, also in quiet mode")
    check("libcrypto" not in r["stderr"], "no libcrypto message during a scan")
    check(len(r["hits"]) == 1, "plain files are still scanned")
    check(len(r["skips"]) == 7 and all(s["reason"] == "not scanned: libarchive not available" for s in r["skips"]),
          "every archive is listed as not scanned")
    check(r["header"]["libraries"]["libarchive"] is None and "libarchive not found" in r["header"]["messages"],
          "run header records the missing library")

    out = os.path.join(tmp, "strict.jsonl")
    e = dict(os.environ)
    e.update(env)
    p = subprocess.run([BIN, "scan", "-q", "--no-lock", "-o", out, "-s", "require_all_libraries=yes", root],
                       env=e, capture_output=True, text=True)
    check(p.returncode == 2 and not os.path.exists(out), "strict mode: a missing library is a failure")
    p = subprocess.run([BIN, "check"], env=e, capture_output=True, text=True)
    check(p.returncode == 1 and "MISSING" in p.stdout, "check: exit 1 when a library is missing")


def main():
    global BASE
    BASE = 0 if have_libarchive() else 1
    tmp = tempfile.mkdtemp(prefix="chdsweep-corpus-")
    try:
        test_plain(tmp)
        test_marks(tmp)
        test_package_file(tmp)
        test_boundary(tmp)
        test_journal(tmp)
        test_health(tmp)
        test_missing_libraries(tmp)
        if have_libarchive():
            test_archives(tmp)
        else:
            print("SKIPPED: archive tests (libarchive not found on this machine)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("corpus tests: %d checks, %d failed" % (checks, len(failures)))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
