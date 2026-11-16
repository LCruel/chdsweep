# Building

## Build and test

Needs a C compiler, `make` and the zlib headers (`zlib1g-dev` on Debian and Ubuntu, `zlib-devel` on RHEL, `zlib-dev` on Alpine). libarchive and libcrypto are loaded at run time, so they are not needed to build. `pdftotext` is started as a program when it is installed.

```
make                     # build/chdsweep
make test                # unit tests, then a generated corpus against the binary
make asan                # the same under AddressSanitizer and UndefinedBehaviorSanitizer
tools/test-distros.sh    # make test as root in Debian, Ubuntu, Rocky and Alpine containers (needs Docker)
```

```
build/chdsweep check                                  # what this host has for a full scan, and what is missing
build/chdsweep scan --no-lock -o run.jsonl /var/www   # one run, one JSON Lines run file
```

## Tests

| Test | What it does | How to run it |
|---|---|---|
| Unit tests | the matcher itself: every brand, length, layout, separator and encoding, the false-positive rules, the limits | `make test` |
| Corpus | builds a folder of test files and scans it with the real binary: archives, PDF files, the journal, missing libraries, exit codes | `make test` |
| Report | makes reports from run files and checks what is in them | `make test` |
| Sanitizers | all of the above with memory and undefined-behaviour checks | `make asan` |
| Distributions | `make test` as root on Debian 11 and 12, Ubuntu 20.04, 22.04 and 24.04, Rocky 9 and Alpine | `tools/test-distros.sh` |
| Formats trial | 15 made-up numbers in 30 written forms, as a table of what is found; fails when a row is not as [detection.md](detection.md) says | `python3 tools/formats-trial.py build/chdsweep` |
| PDF trial | PDF files made by LibreOffice (Writer, Calc, an HTML table), Ghostscript and ReportLab, and one that is only a picture; checks the hits per file | `tools/pdf-trial.sh` (needs Docker, fetches about 400 MB) |
| Package trial | installs a `.deb` on a clean system, scans, removes, purges, and checks each step | `tools/try-deb.sh FILE.deb`, as root |
| Self test | 14 checks with made-up numbers in a folder of its own; for a server, after installing | `sh /usr/share/chdsweep/selftest.sh`, or `sh tests/selftest.sh /path/to/chdsweep` |

Every card number in the tests is made up. The PDF files in `make test` are written by the tests themselves: with text, with several pages, with a password, with copying forbidden, broken, and with pages that hold no text. The PDF trial adds files made by real programs; it is run by hand, not by `make test` or the release build. PDF files from Microsoft Office, a browser's print-to-PDF or a real scanner are in neither.

## Release files

`tools/build-release.sh` (needs Docker) builds these into `dist/` and tries each on a clean system. It writes `dist/TEST-REPORT-<version>.md`: every step with its result and its output, the commit it was built from and the checksums of the files. It ends with an error when a step fails.

| File | For | Needs on the server |
|---|---|---|
| `chdsweep-<version>-static-x86_64`, `-static-arm64` | copying onto any Linux server (Intel/AMD or 64-bit ARM, check with `uname -m`) and running it there | nothing; `poppler-utils` for the text inside PDF files |
| `chdsweep_<version>_amd64.deb`, `_arm64.deb` | Debian 10+ and Ubuntu 20.04+, uses the distribution's libraries | `libc6` 2.28 or newer, `zlib1g` and `libssl`, which every server has and the package asks for; `libarchive13` for archives; `poppler-utils` for the text inside PDF files |

`tools/try-deb.sh FILE.deb`, as root on a system without chdsweep, installs the package, scans, removes and purges it, and checks after each step what is there and what is gone. The release build runs it in Debian and Ubuntu containers.

The `.deb` names the oldest C library the binary runs with. That version is read from the binary when the package is built, so dpkg refuses an older system with a clear message.

## Dependencies

- **At load time:** the C library and zlib.
- **Loaded at run time:** libcrypto, for the `package-file` rule; libarchive, optional, for archives. The static binary has both built in.
- **Started as a program:** `pdftotext`, optional, for PDF text; `journalctl`, for the system journal.

No plugins; rules and tables are plain data files.
