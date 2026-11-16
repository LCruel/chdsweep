#!/bin/sh
# Build chdsweep and run "make test" as root in a container of each supported
# distribution family. Needs Docker; pulls the official images.
#
#   tools/test-distros.sh            from the repository root
#
# The source is mounted read-only; each container builds in its own /tmp.
set -u
src=$(pwd)
[ -f "$src/Makefile" ] || { echo "run from the repository root" >&2; exit 2; }
deb='apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev zlib1g-dev python3 libarchive13 libssl3 poppler-utils'
failed=0
run() {
    echo "=== $1"
    docker run --rm -v "$src:/src:ro" "$1" sh -c \
        "($2) >/tmp/prep.log 2>&1 || { tail -5 /tmp/prep.log; exit 1; }
         cd /src && make BUILD=/tmp/build test 2>&1 | grep -E 'warning|error|Error|FAIL|SKIPPED|tests:'
         ! make BUILD=/tmp/build test 2>&1 | grep -qE 'warning|FAIL|SKIPPED|Error'" || failed=1
}
# Debian 11 is past its long-term support: its security updates have moved from the live
# mirror to archive.debian.org, and the live index still names files that are gone.
run debian:11 "sed -i 's|deb.debian.org/debian-security|archive.debian.org/debian-security|' /etc/apt/sources.list && apt-get -o Acquire::Check-Valid-Until=false update && apt-get install -y --no-install-recommends gcc make libc6-dev zlib1g-dev python3 libarchive13 libssl1.1 poppler-utils"
run ubuntu:20.04 "apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev zlib1g-dev python3 libarchive13 libssl1.1 poppler-utils"
run debian:12 "$deb"
run ubuntu:22.04 "$deb"
run ubuntu:24.04 "apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev zlib1g-dev python3 libarchive13t64 libssl3t64 poppler-utils"
run rockylinux:9 "dnf install -y gcc make zlib-devel python3 libarchive openssl-libs poppler-utils"
run alpine:3.20 "apk add --no-cache gcc make musl-dev zlib-dev python3 libarchive openssl poppler-utils"
[ $failed = 0 ] && echo "all distributions passed" || echo "FAILED on at least one distribution"
exit $failed
