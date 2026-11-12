#!/bin/sh
# chdsweep self-test, to run on the target server after copying or installing the binary.
#
#   sh selftest.sh /path/to/chdsweep
#
# Makes a few files with made-up, Luhn-valid numbers in its own temporary folder, scans
# only that folder, checks the result and removes the folder. It reads nothing else on
# the server and needs no root. Ends with "N passed, 0 failed" when all is well.
BIN=${1:-chdsweep}
T=$(mktemp -d "${TMPDIR:-/tmp}/chdsweep-selftest.XXXXXX") || exit 2
trap 'rm -r "$T"' EXIT
pass=0
fail=0
check() {   # check "what" actual expected
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "PASS  $1"
    else fail=$((fail + 1)); echo "FAIL  $1 (got $2, expected $3)"; fi
}
count() { grep -c "$1" "$2" 2>/dev/null || true; }

mkdir "$T/data"
printf 'paid with 4539148803436467 today\n'            > "$T/data/plain.log"
printf 'card 5412 7512 3412 3452 on file\n'            > "$T/data/spaces.txt"
printf 'amex,3782-822463-10005,2027\n'                 > "$T/data/dashes.csv"
printf ';4539148803436467=27121010000000000?\n'        > "$T/data/track2.dat"
printf 'test 4111111111111111\n'                       > "$T/data/testcard.txt"
printf 'too long 12345391488034364679 and bad 4539148803436468\n' > "$T/data/not-cards.txt"
printf 'archived 4539148803436467\n' | gzip            > "$T/data/old.log.gz"

"$BIN" version >"$T/version" 2>&1
check "the binary starts" "$(count '^chdsweep ' "$T/version")" 1
"$BIN" check >"$T/check" 2>&1
have_archive=$(count 'libarchive  found' "$T/check")
have_crypto=$(count 'libcrypto   found' "$T/check")
echo "info  libarchive: $have_archive, libcrypto: $have_crypto (1 = found)"

"$BIN" scan -q --no-lock -o "$T/run.jsonl" "$T/data" 2>"$T/stderr"
code=$?
R="$T/run.jsonl"
check "run file has a header and an end record" "$(count '"type":"header"' "$R")$(count '"type":"end"' "$R")" 11
check "number without separators" "$(grep 'plain.log' "$R" | grep -c '"masked":"45391488\*\*\*\*6467"')" 1
check "number with spaces" "$(grep 'spaces.txt' "$R" | grep -c '"brand":"mastercard"')" 1
check "number with dashes (4-6-5)" "$(grep 'dashes.csv' "$R" | grep -c '"brand":"amex"')" 1
check "track 2 data" "$(grep 'track2.dat' "$R" | grep -c '"track":2')" 1
check "test card is marked, not hidden" "$(grep 'testcard.txt' "$R" | grep -c '"rule":"test-card"')" 1
check "longer number and failed check digit are not hits" "$(count 'not-cards.txt' "$R")" 0
check "no full number in the run file" "$(grep -c -e 4539148803436467 -e 5412751234123452 -e 378282246310005 "$R")" 0
if [ "$have_archive" = 1 ]; then
    check "number inside a .gz file" "$(grep 'old.log.gz' "$R" | grep -c '"type":"hit"')" 1
    check "exit code 0: everything was scanned" "$code" 0
else
    check ".gz listed as not scanned without libarchive" "$(grep 'old.log.gz' "$R" | grep -c 'libarchive not available')" 1
    check "exit code 1: partial coverage without libarchive" "$code" 1
fi
"$BIN" report -o "$T/report" "$R" >/dev/null 2>&1
check "report is made (Markdown, HTML, CSV)" "$(ls "$T/report.md" "$T/report.html" "$T/report.csv" 2>/dev/null | wc -l | tr -d ' ')" 3
check "report names the data source" "$(grep -c 'CC BY 4.0' "$T/report.md")" 2

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
