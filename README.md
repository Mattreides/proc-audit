# proc-audit

A read-only Bash script for Arch-based Linux (Arch, Manjaro, EndeavourOS, ...).
It checks every running process's executable against the package database and
flags the ones that no installed package can account for. For each finding it
also prints that process's network sockets.

## Why

A common way to hide malware is "drop, execute, unlink". The attacker writes a
binary somewhere, starts it, and deletes the file, so the code only exists in
memory. On Linux this still leaves a trace: `/proc/<pid>/exe` reads
`/path/to/file (deleted)`.

The catch is that normal package upgrades leave the same trace. `pacman -Syu`
replaces binaries under processes that are still running, so a naive check
reports dozens of "deleted" executables after every update. proc-audit
separates the two cases. You get a short list of things worth a closer look,
not a wall of false alarms.

## How it classifies processes

Processes whose executable exists and is owned by an installed package are
skipped. Everything else gets one of three tags:

| Tag | Meaning | What to do |
|---|---|---|
| **RED** | No package owns the executable and it is outside the known unpackaged locations, **or** it was deleted and nothing package-owned is back at that path | Investigate now |
| **STALE** | Deleted while running, but a package-owned file is back at the same path. This is the normal result of a package upgrade | Benign. Restart the program, log out or reboot to clear it |
| **INFO** | Not owned by a package, but in a location where unpackaged software normally lives | Usually fine. Review if unexpected |

Known unpackaged locations (INFO rather than RED): `/snap`, `/var/lib/snapd`,
Flatpak directories, `/opt`, AppImages, `~/.cargo`, `~/.rustup`,
`~/.local/bin`, `~/.nvm`, `~/.npm-global`, uv-managed Pythons and
`~/.pyenv/versions`.

**Sandboxed processes.** Snap, Flatpak and container processes resolve
`/proc/<pid>/exe` inside their own mount namespace, so pacman can't own their
files. For these, proc-audit compares the running executable with the file at
the same path inside that namespace (`/proc/<pid>/root/...`). It names the
sandbox type from the process's cgroup. A foreign mount namespace it can't
identify is tagged RED.

**Optional `--checksums`.** For each STALE binary, this also runs
`pacman -Qkk` on the owning package and adds a note if pacman reports altered
files. It is advisory only and never changes a tag, because `-Qkk` output
varies too much to decide on.

### Example output (illustrative)

The output below was written by hand from the script's print statements to show
the format. It is not from a real system. The user, paths and addresses are
made up (192.0.2.0/24 and 203.0.113.0/24 are documentation ranges).

```
=== Unowned/stale executable audit — 2026-01-01T12:00:00+00:00 ===
Scanning 312 processes...

########## RED — investigate ##########
[RED] pid=4242 user=alice comm=updater
        exe:     /tmp/.cache/updater [DELETED and no package-owned file at this path — INVESTIGATE]
        cmdline: /tmp/.cache/updater --daemon
        sockets:
        tcp   ESTAB 0      0      192.0.2.10:51544 203.0.113.7:443 users:(("updater",pid=4242,fd=3))


########## STALE — benign, restart to clear ##########
[STALE] pid=1337 user=alice comm=firefox
        exe:     /usr/lib/firefox/firefox [deleted, but clean package file back on disk — restart to clear]
        cmdline: /usr/lib/firefox/firefox
        sockets: none


########## INFO — legitimately unpackaged ##########
[INFO] pid=2001 user=alice comm=rust-analyzer
        exe:     /home/alice/.cargo/bin/rust-analyzer
        cmdline: /home/alice/.cargo/bin/rust-analyzer
        sockets: none


=== Summary ===
RED   (investigate now):            1
STALE (benign — restart to clear):  1
INFO  (unpackaged but expected):    1

Run down each RED with:
    ls -l /proc/<pid>/exe ; sudo lsof -p <pid>
Recover the in-memory image of a deleted binary (private temp dir, not a fixed /tmp name):
    d=$(mktemp -d) && sudo cp /proc/<pid>/exe "$d/pid<pid>.bin" && echo "$d"
```

## Requirements

- Bash 4+ (associative arrays)
- `pacman` (Arch-based distributions only)
- `cmp` (diffutils)
- `ss` (iproute2), optional: without it, socket details are skipped
- coreutils, awk, sed, grep

## Usage

```sh
sudo ./proc-audit.sh               # full audit
sudo ./proc-audit.sh --checksums   # plus advisory pacman -Qkk notes on STALE binaries
./proc-audit.sh --help
```

| Option | Meaning |
|---|---|
| `--checksums` | Run an advisory `pacman -Qkk` on the package that owns each STALE binary. Slower, and never changes a tag |
| `-h`, `--help` | Show usage and exit |

The exit status is 0 after a completed audit, whatever it finds. It is 1 if a
required tool is missing and 2 for bad arguments.

## Privileges

proc-audit only reads. It looks at `/proc`, queries the package database
(`pacman -Qo`, `-Qoq`, `-Qkk`) and lists sockets with `ss`. It does not kill,
modify, quarantine or upload anything, and it writes no files.

It runs without root, but then it can only inspect your own processes and
sockets, and it says so on startup. Use `sudo` for a full audit.

## Limitations

- **Arch-only.** Ownership checks use `pacman`. Debian-, RPM- or Nix-based
  systems would need `dpkg -S`, `rpm -qf` or similar.
- **User-writable locations count as expected.** A binary dropped into
  `~/.local/bin`, `~/.cargo/bin`, `/opt` or named `*.AppImage` is tagged INFO,
  not RED. Look over the INFO list too.
- **Interpreted code is not covered.** A malicious script run by
  `/usr/bin/python3` or `/usr/bin/bash` shows the package-owned interpreter as
  its executable, so it is skipped.
- **STALE trusts the path.** A STALE tag means a package-owned file is back at
  the same path. It does not compare the in-memory image with that file.
- **Names are untrusted.** Process names and command lines can be set to
  anything. Control characters in them are replaced with `?` before printing.
  Don't treat a familiar-looking name as proof of anything.
- A snapshot, not a monitor: each run shows the moment it was taken.

## License

MIT. See [LICENSE](LICENSE).
