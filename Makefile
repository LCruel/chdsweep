# chdsweep build. Needs a C compiler, make and the zlib headers (zlib1g-dev, zlib-devel).
# libarchive and libcrypto are loaded at run time, so they are not needed to build.
# pdftotext (poppler-utils) is started as a program when it is installed.
CC      ?= cc
CFLAGS  ?= -O2 -g
WARN    := -std=c11 -Wall -Wextra -Wshadow -Wformat=2 -Wstrict-prototypes
DEFS    ?= -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64
# Level 3 where the C library supports it (glibc 2.35 and newer), otherwise 2.
FORTIFY := $(shell printf '\043include <features.h>\n' | $(CC) -O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -E - 2>&1 >/dev/null | grep -q 'treated like' && echo 2 || echo 3)
HARDEN  := -fstack-protector-strong -fPIE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(FORTIFY)
LDLIBS  ?= -lpthread -ldl -lz
LINK    ?= -pie
BUILD   ?= build
VERSION := $(shell sed -n 's/^.define CHD_VERSION "\(.*\)"/\1/p' src/chdsweep.h)
PREFIX  ?= /usr
DESTDIR ?=

SRC  := $(wildcard src/*.c)
OBJ  := $(SRC:src/%.c=$(BUILD)/%.o) $(BUILD)/bindata.o
LIB  := $(filter-out $(BUILD)/main.o,$(OBJ))

all: $(BUILD)/chdsweep

$(BUILD)/%.o: src/%.c src/chdsweep.h | $(BUILD)
	$(CC) $(WARN) $(DEFS) $(HARDEN) $(CFLAGS) -c $< -o $@

# The BIN base set, as it is in the repository, goes into the binary.
$(BUILD)/bindata.o: src/bindata.S data/bin-table.csv.gz | $(BUILD)
	$(CC) -c $< -o $@

$(BUILD)/chdsweep: $(OBJ)
	$(CC) $(CFLAGS) $(LINK) $^ $(LDLIBS) -o $@

$(BUILD)/test_unit: tests/test_unit.c $(LIB)
	$(CC) $(WARN) $(DEFS) $(CFLAGS) -Isrc $^ $(LDLIBS) -o $@

$(BUILD):
	mkdir -p $(BUILD)

# Unit tests, then the generated corpus and the report against the real binary.
test: all $(BUILD)/test_unit
	$(BUILD)/test_unit
	python3 tests/corpus.py $(BUILD)/chdsweep
	python3 tests/report.py $(BUILD)/chdsweep

# The same tests under AddressSanitizer and UndefinedBehaviorSanitizer.
asan:
	$(MAKE) BUILD=build-asan HARDEN= CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wno-format-truncation" test

# One binary with libarchive, libcrypto and zlib linked in, for copying onto a server
# that has nothing installed. Needs the static libraries; tools/build-release.sh builds
# it in an Alpine container.
static:
	$(MAKE) BUILD=build-static DEFS="$(DEFS) -DCHD_STATIC" LINK=-static \
		LDLIBS="$$(pkg-config --static --libs libarchive libcrypto zlib) -lpthread" build-static/chdsweep
	strip build-static/chdsweep

# Installs the binary and the examples. No config and no cron job: nothing runs by itself.
# (The .deb adds /etc/chdsweep.conf with the defaults; see below.)
install: all
	install -D -m 0755 $(BUILD)/chdsweep $(DESTDIR)$(PREFIX)/bin/chdsweep
	install -d -m 0755 $(DESTDIR)/etc/chdsweep
	install -d -m 0700 $(DESTDIR)/var/log/chdsweep
	install -d -m 0755 $(DESTDIR)/var/lib/chdsweep/bin
	install -D -m 0755 tests/selftest.sh $(DESTDIR)$(PREFIX)/share/chdsweep/selftest.sh
	for f in README.md docs/*.md LICENSE NOTICE etc/*.example; do \
		install -D -m 0644 $$f $(DESTDIR)$(PREFIX)/share/doc/chdsweep/$$(basename $$f) || exit 1; done

# A .deb that uses the distribution's own libraries. Build it on the oldest release it
# has to run on; tools/build-release.sh does that in a container. The package names the
# oldest C library the binary runs with, read from the binary, so that dpkg refuses an
# older system with a clear message instead of the loader failing at the first run.
# It places /etc/chdsweep.conf, the example with every value at its default, as a
# conffile: dpkg keeps a changed one on upgrade and removes it only on purge. Still no
# cron job: the package starts nothing by itself. tools/deb-postrm cleans up on remove
# and purge; tools/try-deb.sh tries all of it on a clean system.
DEBVER  := $(subst -,~,$(VERSION))
DEBARCH := $(shell dpkg --print-architecture 2>/dev/null)
STAGE   := $(BUILD)/deb-stage
deb: all
	mkdir -p $(STAGE)/DEBIAN dist
	$(MAKE) BUILD=$(BUILD) DESTDIR=$(STAGE) install
	strip $(STAGE)$(PREFIX)/bin/chdsweep
	sed '1s|.*|# chdsweep configuration, read by every scan unless -c names another file.|' \
		etc/chdsweep.conf.example > $(STAGE)/etc/chdsweep.conf
	chmod 0644 $(STAGE)/etc/chdsweep.conf
	install -m 0755 tools/deb-postrm $(STAGE)/DEBIAN/postrm
	echo /etc/chdsweep.conf > $(STAGE)/DEBIAN/conffiles
	glibc=$$(objdump -T $(STAGE)$(PREFIX)/bin/chdsweep | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1 | cut -d_ -f2); \
	[ -n "$$glibc" ] || { echo 'deb: no GLIBC version found in the binary (is objdump installed?)' >&2; exit 1; }; \
	printf '%s\n' 'Package: chdsweep' 'Version: $(DEBVER)' 'Architecture: $(DEBARCH)' \
		'Maintainer: D.J.S. van den Akker' 'Section: admin' 'Priority: optional' \
		"Depends: libc6 (>= $$glibc), zlib1g, libssl3t64 | libssl3 | libssl1.1" \
		'Recommends: libarchive13t64 | libarchive13, poppler-utils' \
		'Description: Cardholder data discovery for servers' \
		' Finds payment card numbers on Linux servers, masked, and merges the' \
		' results of many runs and hosts into one report.' > $(STAGE)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(STAGE) dist/chdsweep_$(DEBVER)_$(DEBARCH).deb

clean:
	rm -rf build build-asan build-static dist

.PHONY: all test asan static install deb clean
