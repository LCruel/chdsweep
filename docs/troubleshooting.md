# Troubleshooting

## chdsweep does not start

These messages come from the shell or the system's loader, before chdsweep runs, so chdsweep cannot explain them itself.

| Message | What it means | What to do |
|---|---|---|
| ``version `GLIBC_2.28' not found (required by ...)`` | The server's C library is older than the `.deb` binary needs (2.28, as in Debian 10). | Use the static binary. |
| `No such file or directory` or `not found`, although the file is there | The `.deb` binary on a system without the GNU C library, such as Alpine. | Use the static binary. |
| `cannot execute binary file: Exec format error` | The binary is for another processor. | Check with `uname -m` and take `-static-x86_64` or `-static-arm64`. |
| `Permission denied`, also as root | The file is not executable, or it is on a file system mounted `noexec` (often `/tmp` and `/home` on hardened servers). | `chmod +x chdsweep`; if that is not it, move the file to `/root` or `/usr/local/bin`. |
| `dpkg: dependency problems prevent configuration of chdsweep` | The server lacks a package the `.deb` asks for, or its C library is too old; dpkg says which. | For a missing package, `apt-get install -f` installs it. For `libc6 (>= 2.28)`, use the static binary. |

## chdsweep starts, but something is missing

`chdsweep check` lists what the host has and what is missing, each with its effect and the fix. The same messages appear at the start of a scan.

## Installing the package asks about `/etc/chdsweep.conf`

The package places `/etc/chdsweep.conf` itself. On a server where that file was made by hand before, or was changed and a newer package brings new defaults, dpkg asks which one to keep. Answer `N` to keep yours; the package's version is put next to it as `chdsweep.conf.dpkg-dist`.

An install with nobody to answer stops at that question. Give the answer beforehand:

```
apt install -o Dpkg::Options::=--force-confold ./chdsweep_<version>_amd64.deb
```

## Debian 11: `apt install poppler-utils` fails with "404 Not Found"

Debian 11 is past its long-term support and its security updates have left the live mirror, so the install fails on a server with the default package sources. The package is still in `archive.debian.org/debian-security` (frozen, no further fixes) and in Extended LTS (`deb.freexian.com/extended-lts`, suite `bullseye-lts`). chdsweep itself runs on Debian 11 either way.
