# chdsweep

Fast cardholder data discovery for servers.

chdsweep searches a server's file system for payment card numbers (PANs) and track data, and reports what it found with every number masked. It is built for Linux servers, runs unattended from cron, and combines the results of many runs and many hosts into one report.

**Status:** in development. The scanner and the combined report work. Still open are mainly packaging, CI and rpm support.

## Try it on a server

Copy the static binary to the server and run it as root. It needs nothing installed.

```
scp chdsweep-<version>-static-x86_64 root@server:/root/chdsweep   # -static-arm64 on ARM; check with uname -m
ssh root@server
./chdsweep check                         # what this host has for a full scan, and what is missing
./chdsweep scan --no-lock -o run.jsonl   # /root, /home, the current logs and the journal of the last 35 days
```

Then copy `run.jsonl` to your own machine and make the report there:

```
chdsweep report -o first-run run.jsonl   # first-run.md, first-run.html and first-run.csv
```

Good to know before the first run:

- **It only reads.** One worker at low priority, and one file written: the run file.
- **Exit code 1 is normal on a first run.** It means some files were not or not fully scanned; the report says which and why.
- **To scan more,** give paths: `./chdsweep scan --no-lock -o all.jsonl /` scans the whole root file system.

Scope, limits, disk load and the run file are in [docs/scanning.md](docs/scanning.md).

## Install for scheduled scans

On Debian 10+ and Ubuntu 20.04+:

```
apt install ./chdsweep_<version>_amd64.deb     # _arm64.deb on ARM
cp /usr/share/doc/chdsweep/chdsweep.cron.example /etc/cron.d/chdsweep
```

The package places `/etc/chdsweep.conf` with every setting at its default; change what you need, and an upgrade keeps your changes. Installing the package starts nothing by itself; the cron file does. `apt remove chdsweep` keeps your config and the run files; `apt purge chdsweep` also removes the config, the rules and the cron file, and keeps only the run files in `/var/log/chdsweep`.

To check an installation, run the self test that comes with the package. It scans a few files it makes itself, with made-up numbers, and ends with "14 passed, 0 failed":

```
sh /usr/share/chdsweep/selftest.sh
```

On any other Linux, put the static binary in `/usr/local/bin` and copy [chdsweep.conf.example](etc/chdsweep.conf.example) to `/etc/chdsweep.conf` and [chdsweep.cron.example](etc/chdsweep.cron.example) to `/etc/cron.d/chdsweep`; in the cron file, change the path to `/usr/local/bin/chdsweep`.

## What it needs

chdsweep uses what a server already has. Two parts are optional:

| Part | Used for | Without it |
|---|---|---|
| libarchive | tar, zip and gz archives, office documents | archives are listed as not scanned (the static binary has it built in) |
| `pdftotext`, from the package `poppler-utils` | the text inside PDF files | each PDF is listed as not fully scanned |

`chdsweep check` shows what is there and, for anything missing, the effect and how to install it. If chdsweep does not start at all, see [docs/troubleshooting.md](docs/troubleshooting.md).

## What it detects

A number is reported when a card brand issues it (first digits and length), its check digit is right, and it stands apart from other letters and digits. Lengths from 12 to 19 digits; Visa, Mastercard, American Express, Diners Club, Discover, JCB, UnionPay, Maestro and Mir.

| Written as | Example |
|---|---|
| without separators | `4556737586899855` |
| in groups of four | `4556 7375 8689 9855` |
| as printed on the card (American Express, Diners Club) | `3714 496353 98431` |
| with a space, dash, dot, tab or two spaces between the groups | `4556-7375-8689-9855` |
| as a web form or URL writes the spaces, in an access log | `4556+7375+8689+9855`, `4556%207375%20...` |
| magnetic stripe track 1 and track 2 | `;4556737586899855=2712...` |

It reads every file in the scope as bytes, also inside archives, office documents and PDF text, in ASCII, UTF-8 and UTF-16. The full list, what is not detected and the false-positive rules are in [docs/detection.md](docs/detection.md).

## Report

Collect the run files of all hosts and dates on one machine and merge them:

```
chdsweep report -o pci-2026-11 --triage triage.csv runs/*.jsonl
```

The report shows the suspected PANs, the likely false positives with the rule that marked them, where they are, whose cards they are (brand, issuer, country) and what was not scanned. The newest run of each host is its current state; older runs give the trend. More in [docs/report.md](docs/report.md).

## Not covered yet

- The `package-file` rule only knows the dpkg database, so on RHEL-family servers unchanged package files are not marked.
- bz2, xz and zstd files are not unpacked.
- Pictures are not read, so a card number in a scanned PDF or a photo is not found, also not when the same page has text.

## Why

PCI DSS asks an organisation to confirm where account data lives. The open-source scanners that do this are either unmaintained (ccsrch, archived 2023) or built for workstations and file shares (PANhunt). chdsweep is a new tool for servers: a small C binary, fast, read-only, and safe to leave on a schedule.

## Principles

- **Servers only.** Linux, run as root from cron or by hand. No GUI, no Windows.
- **Never a full PAN in output.** Masking is always on and cannot be switched off: at most the first six (or eight, for numbers of 16 digits or more, as PCI DSS allows) and the last four digits.
- **Nothing written to disk except the result.** Archives and documents are unpacked in memory.
- **Read-only and gentle.** Never changes a scanned file, runs at low CPU and I/O priority, stays on one file system.
- **False positives are marked, not hidden.** Common look-alikes (test cards, IMEIs, IDs, package files) are flagged with the rule and reason, and kept in the report so the triage can be checked.
- **Few outside parts, and clear about a missing one.** One binary, also built fully static. If an optional part is missing, chdsweep says what is affected and how to install it, scans what it can, and reports the rest as not scanned.
- **Coverage is reported.** Every file skipped is counted with its reason, so a clean result only claims what was searched.

## Building

`make` builds `build/chdsweep`; it needs a C compiler and the zlib headers. The tests, the release files and the test report that is written with every release are in [docs/building.md](docs/building.md).

## Licence

[MIT](LICENSE): use, change and redistribute freely, also commercially. The only condition is credit: keep the copyright notice and the licence text with every copy.

## Credits

Inspired by [ccsrch](https://github.com/adamcaudill/ccsrch) (Mike Beekey, Adam Caudill) and [PANhunt](https://github.com/Dionach/PANhunt) (Dionach; the zbalkan fork). The full list of credits is in [NOTICE](NOTICE).

chdsweep was developed with AI assistance.

The built-in BIN table is derived from [bin-list-data](https://github.com/venelinkochev/bin-list-data) (Venelin Kochev / BinLookup.io), under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/), trimmed to the fields chdsweep uses. It is not an official BIN register.
