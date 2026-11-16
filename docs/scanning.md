# Scanning

## Scope

Without a path, a scan covers `/root`, `/home`, the current logs in `/var/log` and the system journal of the last 35 days (read from `journalctl`; nothing is written). Rotated and compressed logs under `/var/log` are ignored.

Paths, excludes and the journal period can be set on the command line (`-x`, `-s journal_days=N`, paths) or in a config file (`-c FILE`, default `/etc/chdsweep.conf`). [pan-scan.conf.example](../etc/pan-scan.conf.example) is the default scope written out. An exclude that starts with a folder (`/var/log/*.gz`) applies under that folder only; a pattern without one (`*.iso`) applies everywhere.

A run stays on the file system of each path it is given. At the end it lists the folders it did not enter (for example `/var` or `/home` on their own file system); add those as extra paths to search them. Network mounts are left out the same way, which is usually what you want.

## Settings

Settings come from `/etc/chdsweep.conf` ([example](../etc/chdsweep.conf.example)) and the false-positive rules from `/etc/chdsweep/fp-rules.conf` ([example](../etc/fp-rules.conf.example)); both are optional. `chdsweep help` lists the options.

## What to expect

- **It only reads.** It runs at low CPU and I/O priority and writes one file, the run file. It prints nothing while it works and a short summary at the end; add `-p` to see what each worker is doing. Ctrl-C stops it and marks the run file as incomplete.
- **Disk load.** A scan reads every file in its scope, so it competes with the server's own disk use and pushes other data out of the file cache. By default one worker reads, at low priority. The low I/O priority only has an effect with the `bfq` I/O scheduler; with `none` or `mq-deadline`, which most servers use, it does nothing. On a busy server set a ceiling that works everywhere: `-s max_read_rate=20M` reads at most 20 MB per second. On a quiet server `-j 4` finishes sooner.
- **At most 10,000 numbers are listed per file.** A file with more is read to the end and the rest are counted (`hits_not_listed` in the run file), so one file full of numbers cannot use up the server's memory or fill the disk with the run file. Change it with `-s max_hits_per_file=N`; 0 is no limit.
- **Nothing is written to disk except the run file.** Archives and documents are unpacked in memory, and so is the copy of a PDF from inside an archive that `pdftotext` reads.

## PDF files

The text inside a PDF is compressed and encoded, so reading the bytes finds next to nothing. chdsweep hands each PDF to `pdftotext` (package `poppler-utils`), with a time and a memory limit, and scans the text that comes back; a hit names the page. `pdftotext` runs as a separate program, so the PDF parser is never part of chdsweep and is patched by the distribution.

Listed as not fully scanned:

- every PDF, when `pdftotext` is not on the server;
- PDFs that ask a password;
- pages without text (scanned pictures are not read);
- PDFs of more than 2000 pages (the first 2000 are read);
- PDFs over 100 MB.

The settings are `pdf_text`, `max_pdf_pages`, `max_pdf_size` and `max_pdf_memory`.

## Notices

When the host cannot do something that leaves nothing unscanned, chdsweep says so once at the start, with the effect and the fix:

- not running as root;
- a `package-file` rule that cannot work: no dpkg database, or an OpenSSL that refuses MD5, as in FIPS mode;
- a `journal_days` setting on a host without `journalctl`.

A notice does not change the exit code. It is in the run file and the report, and on the terminal unless the run is quiet (`-q`).

## Exit codes

Exit codes report the health of the run, never whether cards were found:

| Code | Meaning |
|---|---|
| 0 | full coverage |
| 1 | partial coverage: some files were not or not fully scanned (unreadable, over a limit, a broken archive). Normal on a first run; the run file and the report say which |
| 2 | failed |
| 3 | another run holds the lock |

## The run file

One JSON Lines file per run:

- a `header` line with the settings of the run;
- one `hit` line per number: masked, with brand, offset and the marks of the false-positive rules;
- one `skip` line per file that was not or not fully scanned, with the reason;
- an `end` line with the counters.

A run file without an `end` line is incomplete.
