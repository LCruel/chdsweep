#!/bin/sh
# Builds the release files into dist/ and tries them on a clean system. Needs Docker;
# the arm64 binary is built under emulation, which Docker Desktop has built in.
#
#   tools/build-release.sh           from the repository root
#
#   dist/chdsweep_<version>_amd64.deb       built on Ubuntu 20.04 (glibc 2.31), so it runs on
#                                           Debian 11+, Ubuntu 20.04+ and uses their libraries
#   dist/chdsweep-<version>-static-x86_64   built on Alpine with musl; needs nothing installed
#   dist/chdsweep-<version>-static-arm64    the same for 64-bit ARM (Raspberry Pi, ARM servers)
set -eu
src=$(pwd)
[ -f "$src/Makefile" ] || { echo "run from the repository root" >&2; exit 2; }
mkdir -p dist
version=$(sed -n 's/^.define CHD_VERSION "\(.*\)"/\1/p' src/chdsweep.h)
# The files of this version only: dist/ may still hold those of an earlier one.
deb="chdsweep_$(echo "$version" | tr - "~")_amd64.deb"

echo "=== .deb on ubuntu:20.04"
docker run --rm -v "$src:/src:ro" -v "$src/dist:/out" ubuntu:20.04 sh -c '
    set -e
    (apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev zlib1g-dev \
        python3 libarchive13 libssl1.1) >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
    cp -r /src /build && cd /build && make clean >/dev/null
    make test 2>&1 | grep -E "warning|error|FAIL|SKIPPED|tests:"
    make deb >/dev/null && cp dist/*.deb /out/'

for arch in x86_64 arm64; do
    platform=linux/amd64
    [ "$arch" = arm64 ] && platform=linux/arm64
    echo "=== static binary for $arch on alpine:3.20"
    docker run --rm --platform "$platform" -v "$src:/src:ro" -v "$src/dist:/out" \
        -e OUT="chdsweep-$version-static-$arch" alpine:3.20 sh -c '
        set -e
        apk add --no-cache gcc make musl-dev pkgconf zlib-dev zlib-static libarchive-dev libarchive-static \
            openssl-dev openssl-libs-static acl-static bzip2-static xz-static zstd-static lz4-static \
            expat-static libxml2-static >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
        cp -r /src /build && cd /build && make clean >/dev/null
        make static 2>&1 | grep -E "warning|error" || true
        build-static/chdsweep check | grep -E "found|MISSING"
        cp build-static/chdsweep /out/$OUT'
done

echo "=== try the .deb on ubuntu:24.04 (libraries not installed, then installed)"
docker run --rm -v "$src/dist:/dist:ro" -e DEB="$deb" ubuntu:24.04 sh -c '
    set -e
    dpkg -i "/dist/$DEB" >/dev/null
    chdsweep version | head -1
    chdsweep check | grep -E "found|MISSING" || true
    (apt-get update && apt-get install -y --no-install-recommends libarchive13t64) >/dev/null 2>&1
    chdsweep check | grep -E "found|MISSING"
    chdsweep scan -q --no-lock -o /tmp/run.jsonl /etc; echo "scan exit $?"
    chdsweep report -o /tmp/report /tmp/run.jsonl'

echo "=== try the static binary on busybox (nothing installed)"
docker run --rm -v "$src/dist:/dist:ro" -e B="/dist/chdsweep-$version-static-x86_64" busybox sh -c '
    set -e
    $B version | head -1
    $B check | grep -E "found|MISSING"
    mkdir -p /data && echo "card 4539148803436467 here" > /data/a.txt
    echo "card 4539148803436467 here" | gzip > /data/a.txt.gz
    $B scan -q --no-lock -o /tmp/run.jsonl /data; echo "scan exit $?"
    grep -c "\"type\":\"hit\"" /tmp/run.jsonl
    $B report -o /tmp/report /tmp/run.jsonl'

ls -la dist/
