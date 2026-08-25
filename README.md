# smolvault

[![python](https://img.shields.io/badge/python-3.9%2B-blue)](#requirements)
[![dependencies](https://img.shields.io/badge/dependencies-zero-success)](#requirements)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
![version](https://img.shields.io/badge/version-0.3.1-lightgrey)

**smolvault is an immutable, content-addressed vault for everything you have —
that speaks just enough HTTP to be mistaken for a local disk.**

One file, zero dependencies, no install step. Drop files into the terminal to
seal them write-once (WORM), deduplicated by content and verified on every
read — then stream any of it to mpv, your phone, or a browser with instant
seeking. Media is the headline act; documents, archives and disk images are
equal citizens.

```bash
git clone https://github.com/smolfiddle/smolvault.git
cd smolvault
python3 smolvault.py        # that's the whole install
```

---

## Why

- **Backups you can't corrupt by accident.** Files are sealed forever:
  overwrite → `409`, delete → `403`. Bit-rot fails loudly instead of silently.
- **Storage that shrinks.** Content-defined chunking + dedup means identical
  content costs zero extra bytes, across files *and* folders.
- **Remote without setup.** One command serves the vault on your LAN;
  phones, TVs and other machines get full read/write parity — discovery
  included, IPs optional.
- **It gets out of the way.** Single-file stdlib Python: copy it anywhere,
  run it, done.

## Quick start

```bash
python3 smolvault.py                    # creates vault.vault + opens the hub
```

Press `a`, drag any files from your file manager into the terminal, Enter:

```
  ✓ sealed /movie.mkv  8.4 GB · 9 chunks
  ── 1 added · 0 skipped · 0 failed · 8.4 GB of 8.4 GB newly stored (0% saved)
```

Point it at a folder to ingest a whole tree — or `[b]` to open the
**browse navigator**: a tiny file manager that takes over the screen,
starting at your current directory and **locked to it** (you can
descend into subdirectories, never climb out). `↑↓` move · `→` descend
· `←` up · Space toggles (on a folder = its whole subtree, `◐ n/m`
while partial) · `a` select-all · live filter · `s` seals. Vault
internals (`*.vault`, `__pycache__`) never appear. Then press `p` and
start typing — results filter as you type:

```
  watch ❯ dune · 2
   ❯ /movies/dune.2021.mkv      (8.4 GB)
     /movies/dune.part.two.mkv  (9.1 GB)
```

Enter plays in mpv. When an episode ends, `[Enter]=next` chains the season in
real numeric order (`E2 → E10`). The banner shows a LAN URL — open it on your
phone and the same library streams there.

## What it looks like

```
  ┌────────────────────────────────────────────────────────┐
    smolvault 0.3.1
    vault    vault.vault · 12 files · 22.3 GB logical · 11 GB stored
    local    http://127.0.0.1:8100/
    network  http://192.168.1.14:8100/   ● running   ← phone/TV ready
    auth     password protected · AES-256-GCM at rest
  └────────────────────────────────────────────────────────┘

    a add       drop files · path · [b]rowse a folder
    s search    find something
    p play      live search → mpv        (w works too)
    l library   browse everything (paged)
    d du        space by folder · find double-sealed files
    m board     this vault's messages · clients & server post here
    i info      details about a file
    g get       export a copy out of the vault
    c copy      stream link → clipboard
    y sync      mirror another smolvault
    S server    start/stop network sharing
    v verify    check every chunk's hash
    q quit
```

After each action the hub collapses to a one-line prompt —
`❯ vault.vault · 12f ● :8100 ❯` — so long sessions stay calm. The menu is one
`h` away.

## Features

- **WORM immutability** — sealed means sealed; perfect for media libraries,
  evidence, datasets, anything that must not quietly change. Race-tested:
  12 parallel same-path PUTs yield exactly one seal.
- **Streaming-grade HTTP** — HTTP/1.1 keep-alive, full RFC 7233 byte ranges
  (`N-M`, `N-`, `-N`), `If-Range`, 416s, `ETag` = content hash,
  `Cache-Control: immutable`. Players seek as if the file were local.
- **Content-defined chunking** — gear-hash CDC (64 KB–1 MB chunks) makes dedup
  work across shifted/ressembled files, not just identical copies: a mid-file
  edit still dedups roughly half or more of the file on re-seal (up to ~98%).
- **Entropy-adaptive storage** — high-entropy media stored raw and scanned on
  a coarse fast stride (~2× seal speed); compressible text is compressed.
- **Folder-aware ingest** — recursive walks keep structure
  (`s01/e1.mkv → /movies/s01/e1.mkv`), with a live Space-toggle multi-picker.
- **Vault sync** — additive gap-filling replication between instances;
  nothing ever deleted, safe on a schedule.
- **Remote ingest (opt-in)** — run the server with `--share-root DIR`
  and password-holding clients can browse that directory remotely and
  seal server-local files into the vault (traversal-locked, additive).
- **Space insight** — `--du` breaks storage down by folder and surfaces
  byte-identical files sealed under different paths (WORM keeps them all,
  so knowing matters).
- **Integrity on every read** — per-chunk BLAKE2b-256 verified end-to-end;
  `--check` scrubs the whole vault. Crash-tested: `kill -9` mid-ingest
  recovers clean (`--gc` + `--check`).
- **At-rest encryption (opt-in)** — every chunk sealed with AES-256-GCM
  via the system's OpenSSL; key derived from your vault password
  (scrypt). Zero PyPI dependencies. Dedup fully preserved.
- **Message board, live** — each vault carries a small public board
  (MMO-style): clients and the server post notes and system events
  (`sealed 12 files`, `sync pushed X`). Press `m`: new messages stream
  in as they arrive while you type.
- **Optional password** — PBKDF2-HMAC-SHA256 over HTTP Basic; doubles as
  the encryption key wrapper, and the network gate it controls is an
  independent switch (`--auth on|off`) so trusted LANs can stream freely.

## Requirements

| | |
|---|---|
| Runtime | Python **3.9+** (uses `str.removeprefix`) |
| Dependencies | none — standard library only |
| Install | copy `smolvault.py` anywhere |
| Platforms | Linux · macOS · Windows · Android/Termux |

## Usage

### Wizard (default)

```bash
python3 smolvault.py                    # hub, as shown above
```

### Sealing from scripts

```bash
python3 smolvault.py lib.vault --add /data/movies          # whole folder, structure kept
python3 smolvault.py lib.vault --add a.mkv notes.txt --into /docs/
python3 smolvault.py lib.vault --list
python3 smolvault.py lib.vault --du
python3 smolvault.py lib.vault --search marvel
python3 smolvault.py lib.vault --play dune [--player mpv]
python3 smolvault.py lib.vault --info dune
python3 smolvault.py lib.vault --get dune -o copy.mkv
python3 smolvault.py lib.vault --check                     # scrub all chunks
python3 smolvault.py lib.vault --gc                        # prune orphaned chunks
python3 smolvault.py lib.vault --encrypt                   # at-rest AES-256-GCM (resumable)
python3 smolvault.py lib.vault --decrypt                   # strip encryption
```

`--du` output at a glance:

```text
  space by folder:
  /movies        12 files ·     14.2 GB
  /docs         210 files ·      1.8 GB
  ── vault: 16.0 GB logical · 10.3 GB stored · 36% deduped

  byte-identical sets (WORM keeps them all):
    8.4 GB ×2  /movies/cut.mkv
               = /movies/old/cut.mkv
  ── 1 set · 8.4 GB sealed twice under different names
```

Exit codes: `0` ok · `1` no match/refused · `2` usage error — pipe-friendly.

### Remote access

The same file is client and server. Copy it anywhere:

```bash
python3 smolvault.py lib.vault --serve                  # plain server + live feed
python3 smolvault.py --connect                          # discover vaults on the LAN
python3 smolvault.py --connect 192.168.1.14:8100        # or aim directly
SMOLVAULT_SERVER=host:port python3 smolvault.py --connect
```

Full parity over the network: list, live search, watch in your *local* player
(streams go straight from the vault — never proxied), export, even remote
drag-paste uploads. Discovery runs over UDP broadcast (`--no-discover`
silences it).

| Platform | Playback |
|---|---|
| Linux / Windows / macOS | mpv (default) · VLC via `SMOLVAULT_PLAYER` |
| Android Termux | video auto-opens in **mpv-android** via intent (CLI mpv there is audio-only); falls back to any video app |
| iPhone / TV | browser at the banner URL, or VLC network-stream |

### Vault sync

Because vaults are immutable and content-addressed, syncing is pure
gap-filling — zero conflict logic:

```bash
python3 smolvault.py lib.vault --sync-to   192.168.1.20:8100   # push mine → theirs
python3 smolvault.py lib.vault --sync-from 192.168.1.20:8100   # pull theirs → mine
```

Additive-only: fills gaps, skips already-sealed paths, deletes nothing.
Every pulled file is chunk-hash-verified on arrival. A transfer plan prints
first; in the wizard, `y sync` adds a LAN discovery picker.

## Configuration

No config files — flags and environment only.

| Env var | Purpose |
|---|---|
| `SMOLVAULT_VAULT` | default vault path when none given |
| `SMOLVAULT_PLAYER` | player binary (default `mpv`; `mpvapp` = mpv-android intent) |
| `SMOLVAULT_SERVER` | default `host:port` for client mode |
| `SMOLVAULT_DEBUG` | verbose debug output + SIGUSR1 stack dumps |
| `SMOLVAULT_NAME` | node name on the message board (else hostname) |
| `NO_COLOR` | disable ANSI color everywhere |

| Flag | Effect |
|---|---|
| `--serve` | plain server mode (no wizard) |
| `--host` / `--port` | bind address (default `127.0.0.1`:8100, remembered per-vault; `--port` validated 1-65535) |
| `-p/--password` | set/verify vault password (also unlocks encrypted vault) |
| `-v/--verbose` | verbose logging |
| `-i/--wizard` | force the interactive wizard (even with a vault) |
| `--no-discover` | do not answer LAN discovery probes |
| `--connect [HOST[:PORT]]` | client mode: `auto` discovers LAN, or `SMOLVAULT_SERVER` |
| `--add PATH… [--into DIR]` | seal files/folders (folders walk recursively) |
| `--list` | print library table |
| `--search Q` | search the library |
| `--play Q [--player BIN]` | search + play in mpv |
| `--info PATH_OR_Q` | file details |
| `--get PATH_OR_Q [-o FILE]` | export a file |
| `--du` | space by folder + byte-identical duplicate report |
| `--encrypt` / `--decrypt` | toggle at-rest encryption in place (resumable) |
| `--name NAME` | node name on the message board (default hostname / `$SMOLVAULT_NAME`) |
| `--auth on\|off` | require the vault password over HTTP — **independent of encryption**: `off` keeps files sealed at rest while streaming openly on trusted LANs |
| `--share-root DIR` | expose DIR to password-holding clients for remote browse + ingest (traversal-locked, symlink-blocked, additive; **persisted** in vault config — re-run without flag stays exposed) |
| `--check` / `--gc` | verify all chunks (`--check` needs vault) / reclaim orphaned chunks (locked, `VACUUM` under write lock) |
| `--sync-to HOST` / `--sync-from HOST` | push/pull additive gap-filling sync (hash/size verified) |

### HTTP API

| Endpoint | Behaviour |
|---|---|
| `GET/HEAD /path` | full file or RFC 7233 range; canonical path (resolves `..`); `ETag`/`304`; `423` if vault locked |
| `PUT /path` | seal a new file (`409` if exists — WORM; `400` on truncated `Content-Length`; `0-byte` allowed; `423` locked) |
| `DELETE /path` | always `403` — WORM |
| `GET /__api/list` | JSON listing (path, size, mime, created_at, root_hash) |
| `POST /__api/msg` | post to the vault's message board `{"body": …}` → 201 (max 2000 chars, control chars stripped) |
| `GET /__api/msg?since=N&limit=M` | board messages after id N (max 500) |
| `GET /__api/browse?dir=` | listing under `--share-root` (403 when off / escaping) |
| `GET /__api/browse?dir=&recursive=1` | internal recursive listing (used by remote picker) |
| `POST /__api/ingest` | seal server-local files `{paths:[...max 200], into}` (max 2000 files, `409` WORM, `403` traversal/symlink) |
| `GET /__api/auth` | `{"auth": bool, "share_root": bool}` — password gate + share-root presence |

Auth (if set): HTTP Basic, PBKDF2-HMAC-SHA256, 100k iterations.
Disable it for trusted LANs with `--auth off` — encryption stays on.

## Benchmarks

Loopback · NVMe · 6 cores ([full sheet](BENCHMARKS.md), reproduce with
`python3 benchmark.py`):

| Metric | Result |
|---|---|
| Ingest (700 MB seal) | ~14 s (~51 MB/s) — media scans a hot stride |
| Dedup | identical content → **+0 bytes**; WORM reject < 1 ms |
| Full read 700 MB | **~150–550 MB/s** hash-verified (cold / warm cache) |
| Concurrent reads | **230–725 MB/s** aggregate |
| Range read p50/p95 | **~2–6 ms / 3–17 ms** (256 KB, keep-alive) |
| Playback vs local disk | startup ≈+0.0–0.2 s · deep seek ≈+0.0 s |
| Vault sync | push @ **13–35 MB/s** · no-op re-sync **< 25 ms** |

### On a 1 GB box

The server itself runs inside a hard **1 GB RAM / no-swap / 4-core** cgroup
envelope (`systemd-run --user -p MemoryMax=1G`) while a 700 MB movie is
sealed and streamed back out of it:

| Metric | Result |
|---|---|
| PUT 700 MB into the constrained server | 201 · **~48–68 MB/s** |
| GET full + sha256 verify | byte-exact |
| Seek p50/p95 | 5 ms / 21 ms |
| Server peak memory | **~220–880 MB of 1024** (incl. reclaimable mmap 512 MB + cache 64 MB) — latest run `~226 MB` |

> Note: `PRAGMA mmap_size=512M` + `cache_size=-64000` are tunable; `MemoryMax=1G` leaves headroom but a real Pi will ingest slower while the memory profile holds.

Memory stays flat because files stream in chunks — the ceiling is your disk,
not your RAM. Reproduce with `python3 benchmark.py --lowmem` (Linux +
user systemd session). Caveat: this is x86 under a memory ceiling, not ARM
silicon — a real Pi will ingest slower, but the memory profile holds.

### Resilience & scale

Every promise the docs make, measured ([full sheet](BENCHMARKS.md)):

| Promise | Measured |
|---|---|
| **CDC survives edits** — insert 1 MB mid-file into 192 MB, re-seal | **≈50–98% deduped** (varies with edit position/content) · effective write speed still *exceeds* naive copy |
| **Small-file reality** — 1500 mixed 0–64 KB files | **370–544 files/s** · seal p50 0.5–1 ms |
| **Library scale** — 10k / 50k entries | `--list` 7 / 70 ms · search 18 / 88 ms · `du` 5 / 22 ms |
| **Reads don't block on writes** — 6 range-readers during a 256 MB PUT | 1560 reads · p50 **23 ms** / p95 63 ms while writer ran at 35 MB/s |
| **WORM is race-safe** — 12 parallel PUTs, same path | exactly **1×201 + 11×409** in ~1 s, file serves intact after |
| **Crash consistency** — `kill -9` mid-ingest, restart | pre-crash file byte-exact · half-written file invisible (`404`) · `--gc` reclaimed orphans · `--check` PASS |
| **Multi-viewer storm** — 3 simultaneous decoders + seek noise | ≈**64 fps** aggregate · seek-noise p50 4.2 ms under load |
| **Write endurance** — 5 GB sustained in 45 s | 113 MB/s mean · commit latency stable (259→293 ms p50) · WAL capped at 32 MB |
| **At-rest encryption cost** — AES-256-GCM on/off | seals ≈14–25% slower (`+22%` measured) · reads within ~40% · range seeks `~2–3 ms p50` · unlock `~42–60 ms` |
| **Message board** — post → readable | ~0.3 ms roundtrip |
| **Remote ingest** — `--share-root`, 96 MB via one POST | **82.7 MB/s** server-side · 20-file batch in 160 ms · traversal/symlink → `403` |
| **Remote ingest** — batch 20 × 512 KB in one POST | 20/20 sealed in `~160 ms` · re-ingest → `409` |

The WORM race test earned its keep: it exposed a real bug (losing writers
stalled 60 s on SQLite lock timeouts, then died without a response) which is
now fixed with explicit single-writer discipline — contenders get instant
`409`s instead.

## Troubleshooting

**"Could not connect to socket" (Termux intents)** — your Termux *app* build
predates the AM socket server (needed on Android 12+/14+ where raw `am` is
blocked). Fix: update the Termux app itself from
[github.com/termux/termux-app/releases](https://github.com/termux/termux-app/releases)
(≥ 0.119), fully close & reopen, then `pkg reinstall termux-am`. smolvault
also auto-falls back to `termux-open`, which bypasses `am` entirely.

**LAN devices can't reach the vault**

1. Firewall: `sudo ufw allow 8100/tcp && sudo ufw allow 8100/udp`
2. Router **AP/Wireless Client Isolation** enabled (common on ISP routers) —
   disable it, or use a hotspot:
   `nmcli dev wifi hotspot ssid vaultnet password …`

**Port already in use** — smolvault remembers the last port per vault and
suggests the next free one.

## Security model

**What encryption protects:** a stolen disk, SD card, laptop or leaked
backup of `vault.vault`. Chunks are unreadable without your password.

**What it does not protect:**
- the running server (keys live in RAM while unlocked),
- network traffic — smolvault speaks plain HTTP; put it behind Tailscale,
  WireGuard or an SSH tunnel for remote access,
- **content equality**: nonces derive from chunk hashes so dedup keeps
  working, which means an attacker who already knows a file's exact bytes
  can confirm it exists in your vault.

**Auth vs encryption are independent:** encryption always protects the
stored bytes; whether *network requests* need the password is a separate
switch (`--auth on|off`, default on). Media-server on a trusted LAN?
`--auth off` gives players password-free streaming while everything stays
sealed on disk.

Passphrase strength matters: the key is only as strong as the password
wrapping it (scrypt, n=2¹⁵). Password changes re-wrap the master key in
milliseconds — data is never re-encrypted. The message board is visible
to anyone holding the vault password and is not replicated by sync.
`--share-root` grants password holders read+seal access to that one
directory (traversal- and symlink-locked, additive-only, **persisted** in vault config) — point it at a downloads
folder, never at `/` (`/` is now refused). Paths are canonicalized (`/a/../b` → `/b`), truncated uploads are rejected (`400`), and `gc` holds a write lock to avoid orphans.

## Design notes
smolvault is the distilled successor of DenseVault.
Deliberately absent: delta encoding, WebDAV lock theater, hidden system
collections, compression pipelines, config files, worker-thread ingest
pipelines (measured slower on boost-heavy consumer CPUs — the GIL-bound
chunker runs fastest alone). Deliberately kept verbatim: the gear-hash
chunker and hash-verified reads; the entropy gate now also picks each
file's sealing stride.

### How it compares

No single pillar here is new — CDC chunking comes from the backup world
(borg/restic/FastCDC), WORM-over-HTTP from stores like
[verm](https://github.com/willbryant/verm) and S3 Object Lock, and
stdlib-Python range-streaming servers are practically a genre. What we
could not find elsewhere is **all of it at once in one dependency-free
file**: write-once + content-defined dedup + verified reads + RFC-7233
streaming + LAN discovery + client/server parity. The CAS engines
([casq](https://github.com/roobie/casq),
[Kloset](https://github.com/PlakarKorp/kloset),
[farchive](https://github.com/eliask/farchive)) stop before the serving
layer — several advertise "no network" as a feature; the tiny Python
servers ([servery](https://pypi.org/project/servery/),
[neev](https://pypi.org/project/neev/), pi-media-server) serve plain
filesystems with none of the storage semantics. smolvault lives in the
gap between those two camps.

## Contributing

Issues and PRs welcome — it's one file on purpose; keep additions honest
about that budget. Reproduce before/after with `python3 benchmark.py`.

## License

[MIT](LICENSE) — see also the header of `smolvault.py`.
