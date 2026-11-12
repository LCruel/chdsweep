# chdsweep

Fast cardholder data discovery for servers.

chdsweep searches a server's file system for payment card numbers (PANs) and track data, and reports what it found with every number masked. It is built for Linux servers, runs unattended from cron, and combines the results of many runs and many hosts into one report.

**Status:** in development. The scanner and the combined report work. Still open are mainly packaging, CI and rpm support.

## Build and try

Needs a C compiler, `make` and the zlib headers (`zlib1g-dev` on Debian and Ubuntu, `zlib-devel` on RHEL, `zlib-dev` on Alpine). libarchive and libcrypto are loaded at run time, so they are not needed to build.

```
make                 # build/chdsweep
make test            # unit tests, then a generated corpus against the binary
make asan            # the same under AddressSanitizer and UndefinedBehaviorSanitizer
tools/test-distros.sh  # make test as root in Debian, Ubuntu, Rocky and Alpine containers (needs Docker)
```

```
build/chdsweep check                                  # which optional libraries are there
build/chdsweep scan --no-lock -o run.jsonl /var/www   # one run, one JSON Lines run file
```

Settings come from `/etc/chdsweep.conf` ([example](etc/chdsweep.conf.example)) and the false-positive rules from `/etc/chdsweep/fp-rules.conf` ([example](etc/fp-rules.conf.example)); both are optional. `chdsweep help` lists the options.

The run file has a `header` line, one `hit` line per number (masked, with brand, offset and the marks of the false-positive rules), one `skip` line per file that was not or not fully scanned, and an `end` line with the counters. A run file without an `end` line is incomplete.

Exit codes report the health of the run, never whether cards were found: 0 full coverage, 1 partial coverage, 2 failed, 3 another run holds the lock.

## First test run on a server

`tools/build-release.sh` (needs Docker) builds two files into `dist/` and tries each on a clean system:

| File | For | Needs on the server |
|---|---|---|
| `chdsweep-<version>-static-x86_64`, `-static-arm64` | copying onto any Linux server (Intel/AMD or 64-bit ARM, check with `uname -m`) and running it there | nothing |
| `chdsweep_<version>_amd64.deb` | Debian 11+ and Ubuntu 20.04+, uses the distribution's libraries | `zlib1g`; `libarchive13` for archives; `libssl` for the `package-file` rule |

A first run by hand, as root, with the static binary:

```
scp dist/chdsweep-*-static-x86_64 root@server:/root/chdsweep
ssh root@server
./chdsweep check                                    # the static build has everything built in
./chdsweep scan --no-lock -o /root/run.jsonl      # the default scope, see below
./chdsweep scan --no-lock -o /root/all.jsonl /    # or everything on the root file system
```

Without a path, a scan covers `/root`, `/home`, the current logs in `/var/log` and the system journal of the last 35 days (read from `journalctl`; nothing is written). Rotated and compressed logs under `/var/log` are ignored. Paths, excludes and the journal period can be set on the command line (`-x`, `-s journal_days=N`, paths) or in a config file (`-c FILE`, default `/etc/chdsweep.conf`); `etc/pan-scan.conf.example` is the default scope written out. An exclude that starts with a folder (`/var/log/*.gz`) applies under that folder only; a pattern without one (`*.iso`) applies everywhere.

What to expect and check:

- **It only reads.** It runs at low CPU and I/O priority and writes one file, the run file. It prints nothing while it works and a short summary at the end; add `-p` to see what each worker is doing. Ctrl-C stops it and marks the run file as incomplete.
- **Disk load.** A scan reads every file in its scope, so it competes with the server's own disk use and pushes other data out of the file cache. By default one worker reads, at low priority. The low I/O priority only has an effect with the `bfq` I/O scheduler; with `none` or `mq-deadline`, which most servers use, it does nothing. On a busy server set a ceiling that works everywhere: `-s max_read_rate=20M` reads at most 20 MB per second. On a quiet server `-j 4` finishes sooner.
- **At most 10,000 numbers are listed per file.** A file with more is read to the end and the rest are counted (`hits_not_listed` in the run file), so one file full of numbers cannot use up the server's memory or fill the disk with the run file. Change it with `-s max_hits_per_file=N`; 0 is no limit.
- **One file system per path.** A run stays on the file system of each path it is given. At the end it lists the folders it did not enter (for example `/var` or `/home` on their own file system); add those as extra paths to search them. Network mounts are left out the same way, which is usually what you want.
- **Exit code 1 is normal** on a first run: it means some files were not or not fully scanned (unreadable, over a limit, a broken archive). The run file and the report say which.
- **Then make the report** on your own machine, not on the server: copy `run.jsonl` back and run `chdsweep report -o first-run run.jsonl`. Start with the suspected PANs; the likely false positives are listed per rule.

Once the result looks right, install the `.deb`, copy `/usr/share/doc/chdsweep/chdsweep.conf.example` to `/etc/chdsweep.conf` and the cron example to `/etc/cron.d/chdsweep`. Installing the package starts nothing by itself.

Not covered yet: the `package-file` rule only knows the dpkg database, so on RHEL-family servers unchanged package files are not marked; bz2, xz and zstd files are not unpacked; PDF text is not read.

## Report

Collect the run files of all hosts and dates on one machine and merge them:

```
build/chdsweep report -o pci-2026-11 --triage triage.csv runs/*.jsonl
```

This writes `pci-2026-11.md`, `pci-2026-11.html` (one self-contained page) and `pci-2026-11.csv` (every hit, for a spreadsheet). The newest run of each host is its current state; older runs of the same host give the trend and the differences against the previous run.

- **Kinds of hits, never added together:** suspected PANs (no rule marks them; a person must look), likely false positives (marked by a rule, with the reason) and, only when a triage file is given, accepted false positives (with who decided and when).
- **Where:** per location, then every file with each masked number in it, per host, per file type, host by brand. All counts are occurrences.
- **Whose:** per brand, issuer, country and card type. The issuer comes from a BIN table built into the binary and is looked up offline; nothing is ever sent anywhere.
- **Coverage:** what was not or not fully scanned, per host and reason.

The triage file ([example](etc/triage.csv.example)) is applied in the report only; the run files stay as they are. Entries that match nothing are listed as stale, entries older than 12 months for review.

`chdsweep bin-update --commit HASH bin-list-data.csv` turns a newer download of the BIN data set into a dated table in `/var/lib/chdsweep/bin`, which then replaces the built-in one. chdsweep never downloads anything itself. Local corrections go in `/etc/chdsweep/bin-overrides.csv`, in the same six-field format, and may use eight-digit prefixes.

## Why

PCI DSS asks an organisation to confirm where account data lives. The open-source scanners that do this are either unmaintained (ccsrch, archived 2023) or built for workstations and file shares (PANhunt). chdsweep is a new tool for servers: a small C binary, fast, read-only, and safe to leave on a schedule.

## Principles

- **Servers only.** Linux, run as root from cron or by hand. No GUI, no Windows.
- **Never a full PAN in output.** Masking is always on and cannot be switched off: at most the first six (or eight, for numbers of 16 digits or more, as PCI DSS allows) and the last four digits.
- **Nothing written to disk except the result.** Archives and documents are unpacked in memory.
- **Read-only and gentle.** Never changes a scanned file, runs at low CPU and I/O priority, stays on one file system.
- **False positives are marked, not hidden.** Common look-alikes (test cards, IMEIs, IDs, package files) are flagged with the rule and reason, and kept in the report so the triage can be checked.
- **Portable.** One binary that depends only on well-known libraries (libc, zlib, libarchive, libcrypto), also built fully static. No plugins; rules and tables are plain data files.
- **Clear about missing libraries.** If an optional library is missing, chdsweep says what is affected and how to install it, scans what it can, and reports the rest as not scanned. `chdsweep check` tests a machine before the first run.
- **Coverage is reported.** Every file skipped (too large, unreadable, too deeply nested) is counted with its reason, so a clean result only claims what was searched.

## Licence

[MIT](LICENSE): use, change and redistribute freely, also commercially. The only condition is credit: keep the copyright notice and the licence text with every copy.

## Credits

Inspired by [ccsrch](https://github.com/adamcaudill/ccsrch) (Mike Beekey, Adam Caudill) and [PANhunt](https://github.com/Dionach/PANhunt) (Dionach; the zbalkan fork). The full list of credits is in [NOTICE](NOTICE).

chdsweep was developed with AI assistance.

The built-in BIN table is derived from [bin-list-data](https://github.com/venelinkochev/bin-list-data) (Venelin Kochev / BinLookup.io), under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), trimmed to the fields chdsweep uses. It is not an official BIN register.
