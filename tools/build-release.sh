#!/bin/sh
# Builds the release files into dist/, tries them on clean systems and writes down what was
# tried and how it went. Needs Docker; the arm64 files are built under emulation, which
# Docker Desktop has built in.
#
#   tools/build-release.sh           from the repository root
#
#   dist/chdsweep_<version>_amd64.deb       built on Ubuntu 20.04, uses the distribution's
#   dist/chdsweep_<version>_arm64.deb       libraries; for Debian 10+ and Ubuntu 20.04+. The
#                                           package names the C library version it needs.
#   dist/chdsweep-<version>-static-x86_64   built on Alpine with musl; needs nothing installed
#   dist/chdsweep-<version>-static-arm64    the same for 64-bit ARM (Raspberry Pi, ARM servers)
#   dist/SHA256SUMS                         of the files of this version
#   dist/TEST-REPORT-<version>.md           every step below with its result and its output
#
# Ends with exit code 1 when a step failed; the report is written either way.
set -u
src=$(pwd)
[ -f "$src/Makefile" ] || { echo "run from the repository root" >&2; exit 2; }
mkdir -p dist
version=$(sed -n 's/^.define CHD_VERSION "\(.*\)"/\1/p' src/chdsweep.h)
# The files of this version only: dist/ may still hold those of an earlier one.
debver=$(echo "$version" | tr - "~")
deb="chdsweep_${debver}_amd64.deb"
static="chdsweep-$version-static-x86_64"
report="dist/TEST-REPORT-$version.md"
logs=$(mktemp -d) || exit 2
trap 'rm -rf "$logs"' EXIT
: > "$logs/steps"
nfail=0
nstep=0

# step "title" function: runs the function, keeps its output for the report, notes the result.
step() {
    nstep=$((nstep + 1))
    echo "=== $1"
    if "$2" > "$logs/$nstep.raw" 2>&1; then res=passed; else res=FAILED; nfail=$((nfail + 1)); fi
    # without what Docker prints while it fetches an image
    grep -vE '^Unable to find image|Pulling from|^Digest:|^Status:|Pull complete|Already exists|Verifying Checksum|Download complete|Waiting$|^[0-9a-f]{12}: |^WARNING: The requested image' \
        "$logs/$nstep.raw" > "$logs/$nstep.log"
    printf '%s\t%s\n' "$res" "$1" >> "$logs/steps"
    tail -n 12 "$logs/$nstep.log"
    echo "--- $res"
}

build_deb() {   # $1: amd64 or arm64. The tests run on amd64; under emulation the timing tests are not reliable.
    docker run --rm --platform "linux/$1" -v "$src:/src:ro" -v "$src/dist:/out" \
        -e ARCH="$1" -e DEBVER="$debver" ubuntu:20.04 sh -c '
        pkgs="gcc make libc6-dev zlib1g-dev"
        [ "$ARCH" = amd64 ] && pkgs="$pkgs python3 libarchive13 libssl1.1 poppler-utils"
        (apt-get update && apt-get install -y --no-install-recommends $pkgs) >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
        cp -r /src /build && cd /build && make clean >/dev/null
        if [ "$ARCH" = amd64 ]; then
            make test >/tmp/test.log 2>&1; rc=$?
            grep -E "warning|error|FAIL|SKIPPED|tests:" /tmp/test.log
            [ $rc = 0 ] || { tail -5 /tmp/test.log; exit 1; }
            if grep -qE "warning|SKIPPED" /tmp/test.log; then echo "a warning or a skipped test"; exit 1; fi
        else
            make >/tmp/make.log 2>&1 || { tail -5 /tmp/make.log; exit 1; }
            if grep -q warning /tmp/make.log; then grep warning /tmp/make.log; exit 1; fi
        fi
        make deb >/tmp/deb.log 2>&1 || { tail -5 /tmp/deb.log; exit 1; }
        cp "dist/chdsweep_${DEBVER}_${ARCH}.deb" /out/
        dpkg-deb -f "dist/chdsweep_${DEBVER}_${ARCH}.deb" Package Version Architecture Depends Recommends'
}
deb_amd64() { build_deb amd64; }
deb_arm64() { build_deb arm64; }

build_static() {   # $1: x86_64 or arm64
    platform=linux/amd64
    [ "$1" = arm64 ] && platform=linux/arm64
    docker run --rm --platform "$platform" -v "$src:/src:ro" -v "$src/dist:/out" \
        -e OUT="chdsweep-$version-static-$1" alpine:3.20 sh -c '
        apk add --no-cache gcc make musl-dev pkgconf zlib-dev zlib-static libarchive-dev libarchive-static \
            openssl-dev openssl-libs-static acl-static bzip2-static xz-static zstd-static lz4-static \
            expat-static libxml2-static >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
        cp -r /src /build && cd /build && make clean >/dev/null
        make static >/tmp/make.log 2>&1 || { tail -5 /tmp/make.log; exit 1; }
        if grep -q warning /tmp/make.log; then grep warning /tmp/make.log; exit 1; fi
        build-static/chdsweep version | head -1
        build-static/chdsweep check | grep -E "found|MISSING"
        build-static/chdsweep check | grep -q "libarchive  found" || exit 1
        cp build-static/chdsweep /out/$OUT'
}
static_x86_64() { build_static x86_64; }
static_arm64() { build_static arm64; }

# The .deb without its recommended packages, then with libarchive: what check says each time.
deb_bare() {
    docker run --rm -v "$src/dist:/dist:ro" -e DEB="$deb" ubuntu:24.04 sh -c '
        set -e
        dpkg -i "/dist/$DEB" >/dev/null
        chdsweep version | head -1
        chdsweep check | grep -E "found|MISSING" || true
        (apt-get update && apt-get install -y --no-install-recommends libarchive13t64) >/dev/null 2>&1
        chdsweep check | grep -E "found|MISSING"
        chdsweep scan -q --no-lock -o /tmp/run.jsonl /etc && echo "scan of /etc: full coverage"
        chdsweep report -o /tmp/report /tmp/run.jsonl'
}

# Install, scan, remove and purge, with a check after each step of what is there and gone.
try_deb() {
    docker run --rm -v "$src/dist:/dist:ro" -v "$src/tools:/tools:ro" -e DEB="$deb" "$1" sh -c '
        apt-get update >/dev/null 2>&1
        sh /tools/try-deb.sh "/dist/$DEB"'
}
try_debian() { try_deb debian:12; }
try_ubuntu() { try_deb ubuntu:24.04; }

# The .deb as a server gets it, with the recommended packages: the self test that comes
# with the package, and the trial of every written form.
deb_full() {
    docker run --rm -v "$src/dist:/dist:ro" -v "$src/tools:/tools:ro" -e DEB="$deb" ubuntu:24.04 sh -c '
        export DEBIAN_FRONTEND=noninteractive
        (apt-get update && apt-get install -y python3 "/dist/$DEB") >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
        sh /usr/share/chdsweep/selftest.sh || exit 1
        echo
        python3 /tools/formats-trial.py /usr/bin/chdsweep'
}

# The static binary where nothing is installed.
static_bare() {
    docker run --rm -v "$src/dist:/dist:ro" -v "$src/tests:/tests:ro" -e B="/dist/$static" busybox sh -c '
        $B version | head -1
        sh /tests/selftest.sh $B'
}

# The static binary with pdftotext next to it: every written form, also in PDF text.
static_formats() {
    docker run --rm -v "$src/dist:/dist:ro" -v "$src/tools:/tools:ro" -e B="/dist/$static" alpine:3.20 sh -c '
        apk add --no-cache python3 poppler-utils >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
        python3 /tools/formats-trial.py $B'
}

step "Build the amd64 .deb on Ubuntu 20.04 and run the test suite" deb_amd64
step "Build the arm64 .deb on Ubuntu 20.04" deb_arm64
step "Build the static binary for x86_64 on Alpine 3.20" static_x86_64
step "Build the static binary for arm64 on Alpine 3.20" static_arm64
step "The .deb on Ubuntu 24.04 without, then with libarchive" deb_bare
step "Install, scan, remove and purge the .deb on Debian 12" try_debian
step "Install, scan, remove and purge the .deb on Ubuntu 24.04" try_ubuntu
step "Self test and formats trial with the installed .deb on Ubuntu 24.04" deb_full
step "Self test with the static binary on busybox, nothing installed" static_bare
step "Formats trial with the static binary on Alpine 3.20" static_formats

files="chdsweep_${debver}_amd64.deb chdsweep_${debver}_arm64.deb chdsweep-$version-static-x86_64 chdsweep-$version-static-arm64"
(cd dist && sha256sum $files > SHA256SUMS 2>"$logs/sums.err") || { nfail=$((nfail + 1)); cat "$logs/sums.err"; }

# When git cannot say, its own message goes into the report instead of the commit.
commit=$(git rev-parse --short HEAD 2>&1) || commit="unknown ($(echo "$commit" | head -n 1))"
git status --porcelain 2>/dev/null | grep -q . && commit="$commit, with changes that are not committed"
{
    echo "# chdsweep $version: test report"
    echo
    echo "- **Result:** $([ $nfail = 0 ] && echo "all $nstep steps passed" || echo "$nfail of $nstep steps FAILED")"
    echo "- **Source:** commit $commit"
    echo "- **Made:** $(date -u '+%Y-%m-%d %H:%M UTC') by \`tools/build-release.sh\`, in Docker containers"
    echo
    echo "The release files were built from that source and then tried on clean systems. Every"
    echo "card number in the tests is made up. Each step's own output is further down."
    echo
    echo "## Steps"
    echo
    echo "| | Step | Result |"
    echo "|---|---|---|"
    n=0
    while IFS="$(printf '\t')" read -r res title; do
        n=$((n + 1))
        echo "| $n | $title | $res |"
    done < "$logs/steps"
    echo
    echo "## Release files"
    echo
    echo '```'
    cat dist/SHA256SUMS
    echo '```'
    echo
    echo "## Not covered by this report"
    echo
    echo "- The arm64 files are built and started, not run through the test suite."
    echo "- A real system journal, a real FIPS-mode server and RHEL-family systems (the test"
    echo "  suite runs there with \`tools/test-distros.sh\`, which is not part of the release build)."
    echo "- PDF files made by office programs: the PDFs here are written by the tests. \`tools/pdf-trial.sh\`"
    echo "  checks files made by LibreOffice, Ghostscript and ReportLab and is run by hand."
    echo
    echo "## Output of each step"
    n=0
    while IFS="$(printf '\t')" read -r res title; do
        n=$((n + 1))
        echo
        echo "### $n. $title: $res"
        echo
        echo '```'
        tail -n 120 "$logs/$n.log"
        echo '```'
    done < "$logs/steps"
} > "$report"

echo
echo "=== $([ $nfail = 0 ] && echo "all $nstep steps passed" || echo "$nfail of $nstep steps FAILED")"
cat dist/SHA256SUMS
echo "report: $report"
[ $nfail = 0 ]
