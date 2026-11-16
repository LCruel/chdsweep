#!/bin/sh
# Tries a chdsweep .deb on this system: install, scan, remove, purge, and checks after each
# step what is there and what is gone. Run as root on a system without chdsweep; it ends
# without chdsweep and without anything of it left behind.
#
#   tools/try-deb.sh /full/path/chdsweep_<version>_<arch>.deb
#
# Only the packages the .deb depends on are installed with it (not libarchive or
# poppler-utils), and those stay. Ends with "N passed, 0 failed" when all is well.
set -u
deb=${1:?give the .deb file}
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
case "$deb" in /*) ;; *) deb=$(pwd)/$deb ;; esac
[ -f "$deb" ] || { echo "$deb: not found" >&2; exit 2; }
places="/etc/chdsweep.conf /etc/chdsweep /etc/cron.d/chdsweep /var/log/chdsweep /var/lib/chdsweep /usr/bin/chdsweep /usr/share/chdsweep /usr/share/doc/chdsweep /run/chdsweep.lock"
for p in $places; do
    [ -e "$p" ] && { echo "$p is already here: this system has chdsweep or its files; not touching it" >&2; exit 2; }
done
dpkg -s chdsweep >/dev/null 2>&1 && { echo "chdsweep is installed; not touching it" >&2; exit 2; }

pass=0
fail=0
check() {   # check "what" actual expected
    if [ "$2" = "$3" ]; then pass=$((pass + 1)); echo "PASS  $1"
    else fail=$((fail + 1)); echo "FAIL  $1 (got '$2', expected '$3')"; fi
}
there() { [ -e "$1" ] && echo yes || echo no; }
left() { for p in $places; do [ -e "$p" ] && printf '%s ' "$p"; done; }
T=$(mktemp -d "${TMPDIR:-/tmp}/chdsweep-try.XXXXXX") || exit 2
trap 'rm -rf "$T"' EXIT
export DEBIAN_FRONTEND=noninteractive

echo "--- install"
apt-get install -y --no-install-recommends "$deb" >"$T/install.log" 2>&1 || { tail -15 "$T/install.log"; echo "FAIL  install"; exit 1; }
check "the binary starts" "$(chdsweep version 2>/dev/null | grep -c '^chdsweep ')" 1
check "the package placed /etc/chdsweep.conf" "$(there /etc/chdsweep.conf)" yes
check "dpkg knows it as a config file" "$(dpkg-query -W -f='${Conffiles}' chdsweep | grep -c /etc/chdsweep.conf)" 1
check "no cron job by itself" "$(there /etc/cron.d/chdsweep)" no
chdsweep check >"$T/check" 2>&1
check "chdsweep check runs" "$(grep -c 'check of this host' "$T/check")" 1
sh /usr/share/chdsweep/selftest.sh >"$T/selftest" 2>&1
check "the self test that comes with the package passes" "$(tail -1 "$T/selftest" | grep -c ' passed, 0 failed')" 1

echo "--- scan with the placed config"
mkdir "$T/data"
printf 'paid with 4539148803436467 today\n' > "$T/data/plain.log"
chdsweep scan -q "$T/data" >"$T/scan.log" 2>&1
code=$?
check "scan ends with exit 0 or 1" "$([ $code -le 1 ] && echo ok || { echo "exit $code"; cat "$T/scan.log"; })" ok
run=$(ls /var/log/chdsweep/*.jsonl 2>/dev/null | head -1)
check "run file in /var/log/chdsweep" "$([ -n "$run" ] && echo yes || echo no)" yes
check "the run used /etc/chdsweep.conf" "$(grep -c '"config_file":"/etc/chdsweep.conf"' "$run")" 1
check "the number was found, masked" "$(grep -c '"masked":"45391488\*\*\*\*6467"' "$run")" 1
check "run files are for root only" "$(stat -c %a /var/log/chdsweep)" 700

echo "--- what an admin adds"
# The examples are taken from the .deb itself: a container image may be set up to leave
# /usr/share/doc out.
dpkg-deb -x "$deb" "$T/deb"
ex=$T/deb/usr/share/doc/chdsweep
check "the package has the cron and rules examples" "$(there "$ex/chdsweep.cron.example")$(there "$ex/fp-rules.conf.example")" yesyes
cp "$ex/chdsweep.cron.example" /etc/cron.d/chdsweep
echo "threads = 2" >> /etc/chdsweep.conf
mkdir -p /etc/chdsweep /var/lib/chdsweep/bin
cp "$ex/fp-rules.conf.example" /etc/chdsweep/fp-rules.conf
chdsweep scan -q "$T/data" >"$T/scan2.log" 2>&1
check "a scan with the rules example and the changed config works" "$([ $? -le 1 ] && echo ok || cat "$T/scan2.log")" ok
: > /var/lib/chdsweep/bin/bin-table-2099-01-01.csv.gz
: > /run/chdsweep.lock
cronline=$(grep -v '^#' /etc/cron.d/chdsweep | sed 's/^[^r]*root *//')

echo "--- remove (dpkg -r)"
dpkg -r chdsweep >"$T/remove.log" 2>&1
check "binary gone" "$(there /usr/bin/chdsweep)" no
check "documentation and self test gone" "$(there /usr/share/doc/chdsweep)$(there /usr/share/chdsweep)" nono
check "lock file gone" "$(there /run/chdsweep.lock)" no
check "the changed config is kept" "$(grep -c '^threads = 2' /etc/chdsweep.conf 2>/dev/null)" 1
check "run files are kept" "$(there "$run")" yes
check "the cron line does nothing and says nothing without the binary" "$(sh -c "$cronline" 2>&1 | wc -c | tr -d ' ')" 0

echo "--- purge (dpkg -P)"
dpkg -P chdsweep >"$T/purge.log" 2>&1
check "config gone" "$(there /etc/chdsweep.conf)" no
check "rules folder gone" "$(there /etc/chdsweep)" no
check "cron file gone" "$(there /etc/cron.d/chdsweep)" no
check "BIN tables gone" "$(there /var/lib/chdsweep)" no
check "run files are kept, and dpkg said so" "$(there "$run")$(grep -c 'run files in /var/log/chdsweep are kept' "$T/purge.log")" yes1
check "dpkg no longer knows the package" "$(dpkg -s chdsweep 2>/dev/null | grep -c '^Status')" 0
check "only the run files are left" "$(left)" "/var/log/chdsweep "

echo "--- the run files of this trial"
rm -rf /var/log/chdsweep
check "nothing of chdsweep is left" "$(left)" ""
echo "$pass passed, $fail failed"
[ $fail = 0 ]
