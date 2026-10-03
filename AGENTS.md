# dcload-ip-rs — Agent Notes

The host tool that loads and runs software on a Sega Dreamcast over a LAN, and
serves a running title's disc (GD-ROM sectors and CD-DA audio) from an image on
the PC. The Dreamcast side is `dcload-ip`, in its own repository at
`/opt/toolchains/dc/dcload-ip`; **its `AGENTS.md` is the manual for the
loader**, and its §16 lists the contracts the two sides must keep in step. This
repo is only the host.

This file states rules and where things live; the reasoning and measurements
behind them are in the module doc comments, the commit history, and
`docs/agents-notes-2026-09-12.md` (older investigation notes). If this file and
the code disagree, the code wins — fix this file.

Single binary crate, edition 2024, no `lib.rs`, no integration tests. Main
dependencies: `clap` (derive), `elf`, `polling`, `indicatif` + `console`
(terminal), `md5` (DreamShell preset keys), `miniz_oxide` with
`block-boundary` (random access into zipped images), `oxideav-adpcm` (AICA
ADPCM decoding).

## 1. What a `u-exec` session does

1. **Socket** — `DcIoUDP` (`io.rs`): non-blocking UDP driven by `polling`, to
   `<host>:53535` (legacy mode: 31313, §8).
2. **Handshake** — `VERS`, five tries; `-i/--infinite` waits for a booting
   console (`wait_for_any_loader`). The reply carries the loader's base and
   the video cable (`loaders::parse_version_payload`).
3. **Loader placement** (disc image only; `main.rs::wanted_loader_base`,
   `presets.rs`, `loaders.rs`). Retail titles treat RAM around the loader as
   free, so the loader is moved per title before the title is uploaded:
   - Identify the disc (MD5 of IP.BIN sector 0, DreamShell's key; else by
     title, reported as approximate) and look up its `memory` preset in
     `game-presets.tsv`.
   - A candidate base is rejected if the title **names** it (constants in
     the loader footprint, `literals_in_loader_footprint`; 64 KB-aligned
     region starts near a high span, `region_reaching_loader`), **writes** it
     (disc reads and CPU writes learned in `game-memory.tsv`), its **stack**
     would reach it (`low_base_has_stack_headroom`), or a **constant-bounds
     fill loop** covers it (`low_loader_painted_by_title`). The Katana crt0
     paints `0x8c00c000..0x8c00f400` before anything else runs, so with a
     CD-DA loader **the low family is out for every retail title**.
   - Presets below `0x8c004000` cannot be built; a split vote including one
     (`low_family_contested`) or a low base the set cannot provide
     (`LoaderSet::can_provide`) moves the loader off the low family. A high
     preset refused by the constant scan is read as a window
     (`preset_window_base`). Off the low family the search starts at
     `ISOLDR_HIGH_ADDR` for a known title, `SCRATCH_BASE` otherwise.
   - Windows CE (§5) and KOS (§5) titles have their own rules.
   - Chainload: relocate `loaders/dcload-relocatable.elf` in memory
     (`loaders::relocate`) and upload it, **always hopping via `0x8ce00000`**
     (a direct low→high move overwrites the running loader's packet buffers).
     A running loader whose image differs from the file is replaced even at
     the same base. `refuse_self_overwrite` blocks any upload over the running
     loader, on every path.
   - `--loader-base` pins a base; `--no-relocate` keeps whatever runs.
4. **Payload** — `resolve_payload`: a file as is, or the boot binary an image
   names (`disc_formats::boot::extract`). Then, in the buffer before upload:
   PPF (§6), the GAPS guard (loader AGENTS.md 4.12), VGA, GD-body, CE and KOS
   patches (§5), descrambling. Every patched word is re-applied whenever a
   later disc read reloads it.
5. **Upload** — `dispatch::upload_bytes` → `send_data`: ELF section by section
   (`loaders::is_uploadable`), anything else at `--address` (default
   `0x0c010000`). `LBIN`, `PBIN` parts, then `DBIN` probes and resends.
   Transfers over `MAX_XFER` (256 × 1440) are split.
6. **VM2 / VMUPro** (`vm2.rs`, disc image only) — tell a multi-game memory
   card the product number (§11). Never fatal; `--no-vm2`.
7. **Memory marks** (`marks.rs`) — the loader paints witness words over free
   64 KB blocks; while the title runs, changed blocks are recorded as used.
   Not for CE; `--no-marks`.
8. **Execute** — `dispatch::execute`: `EXEC` with console/CDFS flags. `-d`,
   `-m` or a disc image turn console redirection on (silently).
9. **Syscall loop** — `dispatch::receive_syscalls` until `DC00` Exit:
   `ReadSector`, `ReadAudio` (§4), `ReadToc` (`cd::build_dc_toc`), `FSCommand`
   (`fs.rs`), `DC25` (console text, printed, never answered). The counter
   panel, stack watch and marks post their `SBIQ` reads from the top of the
   loop and never block it.

`upload` does steps 1, 2, 4 and 5 only. `reboot` sends `RBOT` (honoured by
dcload itself only).

## 2. Build, run, commands

- `cargo build` (dev: this crate at opt-level 1, `miniz_oxide` at 3, so zip
  indexing is usable), `cargo build --release` (fat LTO, slow).
- **From WSL, never build in the project's `target/`**: the user builds and
  debugs on Windows there. Use `CARGO_TARGET_DIR=<elsewhere> cargo …`.
- No `make`, `xtask`, CI, formatter or lint configuration.

**Global options go before the subcommand**: `dcload-ip-rs -H <IP> u-exec
game.gdi` (`u-exec --host …` is rejected).

| Command | What it does |
| --- | --- |
| `u-exec <file or image>` | upload and run; with an image, also serve its disc. `-d <image>` serves another image, `-m <dir>` a host directory (conflict), `-c` console output |
| `upload <file or image>` | upload only |
| `identify <image>` | what the image is, the base placement would choose, patches that apply; no network |
| `extract <image> [-o out]` | write the boot binary out |
| `audit-audio <image> [--track N]` | judge audio tracks for pipeline defects (§4); no network |
| `relocate <elf> <base> -o <out>` | write the in-memory relocation out |
| `selftest-readback` | write patterns to free RAM and read them back |
| `reboot` | `RBOT` |

Global options: `-H/--host`, `-v`/`-vv`, `-p/--port`, `-i/--infinite`,
`-a/--address`, `--loader-dir`, `--game-db`, `--memory-db`, `--patch-dir`,
`--loader-base`, `--no-relocate`, `--patch ADDR=VALUE`, `--ppf FILE`,
`--no-ppf`, `--no-gaps-guard`, `--no-marks`, `--no-vm2`, `--no-wince`,
`--vga auto|always|never`, `--no-cdda`, `--cdda-tone`, `--probe ADDR=ID[:PEEK]`
(a stub that logs when ADDR executes), `--descramble auto|always|never`,
`--boot-ipbin`, `--diag`, `--diag-interval`. `src/main.rs` (`Args`) is the
list of record.

**Data files live at the project root** (outside `target/`, so `cargo clean`
cannot take them and debug and release share them): `loaders/`,
`game-presets.tsv`, `game-memory.tsv`, `patches/`. Each has an option and an
environment variable; a copy beside the executable is honoured last. **Never
keep a second loader set under `target/`**: a stale loader answers with
counters at moved addresses, and every value reads back plausible and wrong.
A/B loader sets go in a directory of their own, passed with `--loader-dir`.

| Variable | Effect |
| --- | --- |
| `DCLOAD_LOADER_DIR`, `DCLOAD_GAME_DB`, `DCLOAD_MEMORY_DB`, `DCLOAD_PATCH_DIR` | data file locations |
| `DCLOAD_CDDA_TRIM=0` | do not send the CD-DA clock trim (§4) |
| `DCLOAD_CDDA_SAFE=1` | audio through the acknowledged path; times out against current loaders |
| `DCLOAD_RT_BURST`, `DCLOAD_RT_DELAY_US` | runtime pacing (default 6 packets, 600 µs spin) |
| `DCLOAD_VERIFY_READS=1` | read every served disc read back with `SBIQ` and compare |
| `DCLOAD_ZERO_LBA`, `DCLOAD_REDIRECT_ABOVE` / `_TO` | diagnostics: blank one LBA; redirect reads above an address |
| `DCLOAD_LOAD_BAR_KB` (256, 0 = off), `DCLOAD_LOAD_IDLE_MS` (250) | in-game loading bar |
| `DCLOAD_ZIP_INDEX_BUDGET` | MiB of deflate checkpoints per zip member (default 64) |
| `DCLOAD_VM2_PACE_MS`, `DCLOAD_VM2_WARMUP` | VM2 scan pacing and warm-up rounds (§11) |
| `DCLOAD_TEST_ORIG`, `DCLOAD_TEST_PATCHED`, `DCLOAD_TEST_CDI`, `DCLOAD_TEST_KOS_BIN` | inputs of tests that need real dumps |

## 3. Tests

`cargo test` runs the unit tests (about 270, one ignored). Tests that need a
real dump skip when it is absent: the GDI and zip tests want files under
`test/`; `relocating_reproduces_every_native_link_byte_for_byte` wants a loader
set (point `DCLOAD_LOADER_DIR` at a fresh build to test the loader tree rather
than what was deployed).

`test/` is gitignored payload data. **Do not rename it to `tests/`**: Cargo
would treat it as integration tests.

Past `EXEC`, verification needs a console or flycast. Without one:
`dispatch::cdda::tests` drives `send_audio` through an in-memory
`ExternalDcIo`; `vm2` tests run against a scripted `MapleBus`; and a small
Python UDP stub on `127.0.0.1:53535` that answers `VERS`, echoes `LBIN` and
answers `DBIN` with the first missing part can drive a whole `upload`.

Watch `cargo test` warnings: a `#[test]` separated from its function by a doc
comment silently stops the test running (happened twice).

## 4. CD-DA

The loader plays audio tracks itself (loader AGENTS.md §4.13, its `cdda.c`);
this host answers its requests (`dispatch/cdda.rs`).

- `DC23`: raw 2352-byte sectors. value0 = LBA, value1 = destination,
  value2 = bytes.
- `DC24` (default): 4-bit AICA ADPCM, left block then right. value2 = frames
  (sectors = value2 / 588), **bit 31 = restart the encoder**.

The answer is LoadBinary + parts with **no acknowledgement round trips**, then
a ReturnValue whose **`address` is the LBA served** (the loader rejects any
other) and whose **`size` is the clock trim in ppm**. A refused read
(`u32::MAX`) is re-asked forever and the music stops, so **a sector inside a
track's span is never refused**: anything past the track's file (e.g. the next
track's undumped pregap) is served as silence. Only a read past the last track
is an error.

Rules:

1. **`CDDA_GIVE_UP` (15 ms) stays below the loader's
   `CDDA_FETCH_DEADLINE_TICKS` (20 ms).** A late answer is dropped entirely,
   ReturnValue included; the loader would take it for its next request's.
2. **The ADPCM encoder is one continuous stream** (`adpcm::Stream`), mirroring
   the AICA decoder's state. It resets only on bit 31. A re-ask is served from
   the last `RECENT` (48) answers *before* the disc is read (`Stream::replay`);
   `RECENT` must cover the loader's whole ring, and `lost_replay` must stay 0.
3. **The codec must be the AICA's** (`the_crate_still_decodes_like_the_aica`),
   and **no nibble may decode two ways** (clamped vs unclamped decoders
   disagree on near full-scale swings, and the offset never heals). `adpcm.rs`
   picks its own nibbles (`pick_nibble`) and uses the crate only to decode;
   `no_nibble_decodes_two_ways` is the test. No loader counter can see this
   class of defect.
4. **Nothing slow on this path** — the title is frozen from request to
   ReturnValue. That includes locks held across I/O elsewhere
   (`MemoryRecorder::take_due` writes outside its lock), re-reading a suspected
   defect, and building a zip index (§7). Accounting and logging come after
   the ReturnValue.
5. **No ack round trips.** The loader detects incomplete windows and re-asks;
   one request in 256 is probed with a DoneBinary to catch a lossy link.

**Clock trim** (`CddaClock`): nothing on the console is locked to the AICA, so
the host measures audio staged per second of real time by disc position and
returns the scale (first after 90 s, then every 300 s; implausible windows and
estimates are refused). **The `CDDA_TRIM_*` thresholds encode the loader's
stream pacing** (one 4-sector sub-fetch every ~53 ms). If that pacing changes,
re-check them and the `feed_stream` tests — a mismatch makes the estimator
silently accept nothing while every test passes.

**Continuity** (`SlewWatch`, `audit_audio`): a pipeline defect lands at a fixed
offset inside a sector, so hits are histogrammed modulo 588 frames and only a
spike over 8 σ is a defect. Live, only such a spike warns; `audit-audio`
judges a whole image.

**TOC** (`cd.rs`): built from `DiscFormat::toc_tracks()` with CTRL (audio 0,
data 4). Without audio tracks in the TOC a title never asks for music.

**Switches**: `--no-cdda` refuses every audio read; `--cdda-tone` serves a test
triangle instead of the disc (encoder, network and loader still run).

All CD-DA logging during play is at DEBUG (`-v`): a summary block every 250
requests, plus late requests, dropped answers and lossy probes. CD-DA reads
are not recorded in `game-memory.tsv`.

## 5. Patches found by content

All are found by scanning the payload (no per-game tables), applied before
upload, verified, re-applied on reload, and listed by `identify`
(`dispatch/patches.rs`, `wince.rs`).

- **VGA** (`--vga`, default `auto`). The cable check (a read of SH4 port
  `0xff800030`, bits 8-9) becomes `mov #0,r4` (`vga_cable_patches`), and
  IP.BIN's peripheral field declares VGA (`declare_vga_in_ip_bin`). `auto`
  patches only when the loader reports a VGA cable, asked at decision time
  (`query_cable`, since a chainload replaces the loader); unknown means leave
  the title alone. It cannot add a 480p mode a title lacks.

  | title (PAL) | cable check | IP.BIN peripherals |
  | --- | --- | --- |
  | Sonic Adventure | 0x8c10d866 | `0601A10` (declares VGA) |
  | Sonic Adventure 2 | 0x8c137276 | `0799A10` |
  | Crazy Taxi | 0x8c162dee | `0799A10` |
  | Snow Surfers | 0x8c0e9026 | `0799A00` |

- **Direct BIOS GD driver calls** (`gd_body_patches`, always on). Every
  4-aligned `0x8c0010f0`/`0xac0010f0` is rewritten to the loader's
  `_gd_bios_entry` (`main.rs::gd_bios_entry`), since a direct call bypasses
  the syscall vectors the loader holds. Windows CE does this; Katana titles
  do not.
- **Windows CE** (`boot::WinCe`, `wince.rs`). Recognised by name
  (`0WINCEOS.BIN`, whose first 2048-byte sector is dropped, as DreamShell's
  isoldr does) or by `"ECEC"` at +64; entered through the disc's second
  bootstrap. The loader goes at `ulRAMEnd - LOADER_SPAN` from CE's `ROMHDR`,
  and `ulRAMEnd` is lowered under it (`ram_end_patch`). `pio_patches` sends
  CE's GD driver down its PIO path, because its DMA path waits for a G1
  interrupt this transport never raises. Reads into the loader's `_gd_stage*`
  buffers are not collisions (`loader_stage`). `--no-wince` uploads it whole.
  Open questions: the loader's `docs/wince-investigation.md`.
- **KOS** (`is_kos_binary`). The loader is told via `g_gd_kos`; KOS's top of
  RAM is lowered under the loader (`kos_mem_top_patches`); the dcload magic at
  `0x8c004004` is pointed at the live loader (`update_dcload_magic`) so KOS's
  console reaches this host.

## 6. Shipped patches (PPF)

For fixes nobody can derive, only carry: `patches/patches.tsv` plus `.ppf`
files (`patchdb.rs`, `ppf.rs`: PPF 1.0/2.0/3.0).

- **A row is a claim the patch checks**: a PPF3.0 blockcheck must match, or
  the patch is refused (also with `--ppf`); `bin_md5`/`disc_md5` cover formats
  without one.
- `apply` is `auto` or `manual` (offered, not applied). A `.ppf` without a row
  is offered only if its blockcheck matches. `--no-ppf` disables the list but
  still reports what it held back.

## 7. Architecture

- **`main.rs`** — CLI, placement decisions, payload resolution and patching,
  `measure_rtt`, session wiring.
- **`dispatch/`** (items re-exported as `dispatch::…`) — `session.rs`
  handshake, placement, upload, execute, read-back self-test; `transfer.rs`
  `send_data`, `send_sectors`, `receive_data`, pacing; `syscalls.rs` the loop;
  `sectors.rs` `SectorServer` (disc reads, collision and memory-map checks,
  `DCLOAD_VERIFY_READS`, guard re-application); `cdda.rs` (§4); `patches.rs`
  (§5); `image.rs` `open_disc`, `identify`; `probes.rs` `--probe`.
- **`loaders.rs`** — VERS parsing, the layout table (the host's copy of the
  loader Makefile's: `layout()`, `live_footprint()`, `LOADER_SPAN`),
  relocation, chainload plan. The relocator refuses what it cannot classify;
  keep its layout in step with the loader.
- **`presets.rs`**, **`memmap.rs`** — DreamShell presets and disc identity; the
  learned per-title map (256 bits of 64 KB, merged by OR) and `sp_min`
  (merged by minimum), written by a ticker thread so a killed session still
  leaves it.
- **`marks.rs`** — CPU writes, learned by witness words (§1 step 7).
- **`stackwatch.rs`** — reads the loader's `g_gd_sp_min` every 10 s and
  records it. A value outside RAM means a different loader is answering (the
  title went back to the BIOS) and is not recorded; a CE thread stack (MMU
  on) is reported once and not recorded.
- **`adpcm.rs`** (§4), **`wince.rs`** (§5), **`vm2.rs`** (§11).
- **`diag.rs`**, **`ui.rs`** — counter panel and everything drawn on the
  terminal.
- **`io.rs`** — `DcIoUDP`; `handle_data` drains the socket each wakeup;
  `PacketSink` lets the panel, stack watch and marks claim their replies
  wherever the host happens to be polling.
- **`cmds.rs`**, **`types.rs`** — wire formats. Headers, payloads and syscall
  parameters are big-endian; the TOC and `DCLoadStat`/`DCLoadDirEnt` are
  little-endian.
- **`fs.rs`** — host file syscalls for `-m`, sandboxed by
  `join_and_check_path`; errors are `u32::MAX` return values, not `Err`.
- **`cd.rs`** — the TOC.
- **`disc_formats/`** — `DiscFormat` (`types.rs`), `iso`, `gdi`, `cdi`, read
  through `ImageSource` (`source.rs`), so `zip.rs` serves images from inside a
  `.zip` in place (deflated members via `deflate.rs`'s checkpoint index,
  CRC-verified); `iso9660.rs`, `boot.rs`, `scramble.rs`.

Disc-reader facts that cost time:

- **Filesystem LBAs are `read_sector` LBAs − 150** on every format;
  `DiscFormat::fs_lba` converts, once. Wrong is silent (an empty directory).
  A CDI track's stored lba is an LBA, not a FAD.
- **A GDI's boot track is the first data track at or above LBA 45000**
  (CD-DA can sit in the high-density area). `start_sector()` stays the
  low-density track: that is what DreamShell hashes.
- **A CDI's boot track** has an ISO9660 PVD at sector 16 whose root extent
  lies inside it.
- Names from a dump are untrusted: `plain_track_name`, `boot_file_name`,
  `safe_output_name`; `ZipArchive::find` is exact.
- A scrambled binary uploads and verifies perfectly, then runs noise.
  Detection is one-sided; `--descramble always` for a retail CDI conversion
  that does nothing.
- The first read of a **deflated** zip member builds its index (seconds for a
  GiB track; `zip -0` avoids it). `CURSORS` (8) is a cliff: fewer and
  interleaved reads cost 10x.
- **An audio track's index must never be built on a syscall path**: it blows
  the loader's fetch budget and the music starts late, invisibly to every
  counter. `zip::warm_track_indexes` builds them on a thread when the image is
  opened.

## 8. Protocol modes

`CHUNK_SIZE` in `main.rs` switches the protocol version and the local bind:

- `1440` (default): version `[2, 0, 3]`, remote port `--port` (53535), local
  bind `0.0.0.0:0`.
- `<= 1024`: legacy `[0, 0, 0]`, remote **and** local port forced to 31313.

No negotiation: check the mode first when a console does not answer.

## 9. Debugging

- `-v`/`-vv` or `RUST_LOG`. Commands log through `Display`; `DoneBinary` is at
  TRACE.
- A slow read-back chunk is re-requested, so a late duplicate is dropped at
  DEBUG, not reported as unexpected.
- `.vscode/`, `.continue/`, `.zed/` hold personal launch configurations: do not
  commit them as is.
- **Terminal** (`ui.rs` owns it): one `MultiProgress`; logs print inside
  `suspend`, so bars must come from `ui::bytes_bar`. Nothing is drawn when
  stderr is not a terminal. The in-game loading bar (`LoadMonitor`) groups
  disc reads into bursts and updates only after the ReturnValue.
- **Counter panel** (`--diag`, `diag.rs`): `d` toggles sampling, `w` writes a
  snapshot to `dcload-diag.txt`, `+`/`-` change the interval. The loader image
  is verified against the uploaded ELF before any counter is decoded. The
  loader answers only inside `bb->loop()`, so a title that stopped reading its
  disc may leave the panel unanswered; the header shows the measured
  interval. The panel and stack watch overlap, so only one is active at a time.

## 10. Gotchas

- **Runtime transfers are paced with a spin (`spin_for`), never
  `thread::sleep`**: every host wait freezes the title, and Windows rounds
  sleeps up to the timer tick. Pre-`EXEC` code may sleep.
- The runtime pacing default (600 µs every 6 packets) is a deliberate cost: it
  protects the loader's 16 KB RX ring, whose overflow does not recover well.
- **A failed disc transfer must not end the session**: no ReturnValue is sent,
  the loader times out and re-asks.
- **A malformed `ReadSector`** (size not a sector multiple) means the loader's
  state was overwritten (usually a stack at a low base): logged, refused,
  session kept.
- **A reply to an earlier read can arrive during the next one**:
  `receive_data` accepts only chunks that fit (`chunk_is_ours`).
- **A disc read landing on the loader** is an error; within 256 KB of a high
  loader, a warning.
- `cdi2iso.c` at the root is untracked third-party GPLv2 reference, not built.

## 11. VM2 / VMUPro

`vm2.rs` tells a multi-game memory card (VM2, VMUPro, compatible USB/BT
adapters) which product is booting, over the loader's `MAPL` passthrough
(loader AGENTS.md §8). Needs a loader from 2026-09-20 or later (earlier ones
mangle `MAPL` payloads; there is no feature bit, redeploying `loaders/` keeps
them in step).

- **Detection**: `DEVINFO` then `ALLINFO` to units 1 and 2 of each port; the
  card is named by a substring of the 40-byte `extended` field after the
  112-byte device info (`KNOWN`). `DEVINFO` first mirrors what KOS/openMenu
  do. A plain VMU also answers, with its own version string in `extended`.
- **Selection**: Maple command 33; payload = function code `00 00 00 02`,
  12 bytes of product number, optionally 128 bytes of title (`strncpy`
  semantics).
- **Transport**: `MAPL` takes port, unit, command and payload length **in
  longwords**; response codes are signed (-1 none, -4 busy).
- **Every answer is matched to its request** by the tag the loader echoes in
  `address`: the scan runs right after an upload, and the first batch it sees
  is routinely the upload's tail.
- **Bounded and never fatal**: retries on `AGAIN`, three sends per request,
  two consecutive silent probes end the scan. Transactions are paced
  `PACE_MS` (17 ms, one vblank) apart, as KOS does; a slot the controller
  reports (`slots_reported`, from the sender byte) but that answers empty gets
  a Maple reset and one more try. Every rejected slot is explained
  (`explain`).
- **Open (2026-09-20)**: on the test console a VMUPro in controller A's slot 1
  is still not found — the first transaction to it returns 32 bytes of
  non-frame data and port A's slots then answer empty, while port B works.
  The next control is physical: move the VMUPro to port B and see whether the
  fault follows the device.
