#!/usr/bin/env python3
"""Trim the upstream BIN data set to the fields chdsweep uses.

    python3 tools/bin-trim.py <bin-list-data.csv> <upstream commit> <date pulled> data/bin-table.csv.gz

Upstream: https://github.com/venelinkochev/bin-list-data (CC BY 4.0).
Output: a gzip file. Line 1 is a '#' header with the source, upstream commit, date
pulled and number of entries; then one line per prefix:
    prefix,brand,type,category,issuer,country      (country: ISO 3166-1 alpha-2)
Sorted by prefix; a prefix that occurs twice keeps its first line. The output is
the same bytes for the same input, so a refresh shows up in git only when the data changed.
"""
import csv
import gzip
import io
import sys


def main():
    src, commit, pulled, dst = sys.argv[1:5]
    rows = {}
    with open(src, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            prefix = r["BIN"].strip()
            if not prefix.isdigit() or not 6 <= len(prefix) <= 8:
                continue
            rows.setdefault(prefix, [prefix] + [" ".join(r[k].split()) for k in
                                                ("Brand", "Type", "Category", "Issuer", "isoCode2")])
    out = io.StringIO(newline="")
    out.write("# chdsweep BIN table; source=venelinkochev/bin-list-data; licence=CC BY 4.0; "
              "changed=trimmed to six fields; upstream_commit=%s; pulled=%s; entries=%d\n"
              % (commit, pulled, len(rows)))
    w = csv.writer(out, lineterminator="\n")
    for prefix in sorted(rows):
        w.writerow(rows[prefix])
    with open(dst, "wb") as f:
        with gzip.GzipFile(fileobj=f, mode="wb", compresslevel=9, mtime=0, filename="") as g:
            g.write(out.getvalue().encode("utf-8"))
    print("%d entries written to %s" % (len(rows), dst))


if __name__ == "__main__":
    main()
