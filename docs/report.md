# Report

Collect the run files of all hosts and dates on one machine and merge them:

```
chdsweep report -o pci-2026-11 --triage triage.csv runs/*.jsonl
```

This writes `pci-2026-11.md`, `pci-2026-11.html` (one self-contained page) and `pci-2026-11.csv` (every hit, for a spreadsheet). The newest run of each host is its current state; older runs of the same host give the trend and the differences against the previous run.

Start with the suspected PANs; the likely false positives are listed per rule.

## What is in it

- **Kinds of hits, never added together:** suspected PANs (no rule marks them; a person must look), likely false positives (marked by a rule, with the reason) and, only when a triage file is given, accepted false positives (with who decided and when).
- **Where:** per location, then every file with each masked number in it, per host, per file type, host by brand. All counts are occurrences.
- **Whose:** per brand, issuer, country and card type. The issuer comes from a BIN table built into the binary and is looked up offline; nothing is ever sent anywhere.
- **Coverage:** what was not or not fully scanned, per host and reason.

## Triage

The triage file ([example](../etc/triage.csv.example)) is applied in the report only; the run files stay as they are. Entries that match nothing are listed as stale, entries older than 12 months for review.

## The BIN table

`chdsweep bin-update --commit HASH bin-list-data.csv` turns a newer download of the BIN data set into a dated table in `/var/lib/chdsweep/bin`, which then replaces the built-in one. chdsweep never downloads anything itself.

Local corrections go in `/etc/chdsweep/bin-overrides.csv`, in the same six-field format, and may use eight-digit prefixes.
