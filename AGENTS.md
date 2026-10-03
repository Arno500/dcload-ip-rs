# dcload-ip-rs — Agent Notes

The host tool that loads and runs software on a Sega Dreamcast over a LAN, and
serves a running title's disc (GD-ROM sectors and CD-DA audio) from an image on
the PC. The Dreamcast side is `dcload-ip`, in its own repository at
`/opt/toolchains/dc/dcload-ip`; **its `AGENTS.md` is the manual for the loader**,
and its §16 lists the contracts the two sides must keep in step. This repo is
only the host.

This file describes the code that is present. The previous, longer version of
it (with the investigation narratives) is archived in
`docs/agents-notes-2026-09-12.md`. If this file and the code disagree, the code
wins.

Single binary crate `dcload-ip-rs`, edition 2024, no `lib.rs`, no integration
tests. Main dependencies: `clap` (derive), `elf`, `polling`, `indicatif` and
`console` (terminal), `md5` (DreamShell preset keys), `miniz_oxide` with the
`block-boundary` feature (random access into zipped images),
`oxideav-adpcm` (the AICA ADPCM codec; it pulls in `oxideav-core`, `serde_json`
and friends, about 11 crates).

## 1. What a run looks like

A `u-exec` session:

1. **Socket.** `DcIoUDP` (`src/io.rs`): non-blocking UDP driven by `polling`,
   connected to `<host>:53535` (legacy mode: 31313, §8).
2. **Handshake.** `VERS`; five tries, then give up. `--infinite` (`-i`) instead
   waits quietly for a console that is still booting (`wait_for_any_loader`).
   The VERS reply carries the loader's base and the video cable after the
   version string (`loaders::parse_version_payload`).
3. **Loader placement** (`src/presets.rs`, `src/loaders.rs`, `main.rs`
   `wanted_loader_base`), with a disc image only. Retail titles treat RAM around
   the loader as free, so the loader is moved per title before the title is
   uploaded:
   - Identify the disc (MD5 of IP.BIN sector 0, DreamShell's key; else the
     title, reported as approximate) and look up DreamShell's `memory` preset in
     `game-presets.tsv`.
   - Reject a base the title **names** (constants its code loads into the
     loader's footprint, `literals_in_loader_footprint`; or a region start --
     a 64 KB-aligned word anywhere in the image, `dispatch::region_starts` --
     inside a high span or less than one block under it,
     `region_reaching_loader`), **writes** (blocks its disc reads landed in,
     and since 2026-09-30 blocks it wrote with the CPU, learned by `marks.rs`;
     both in `game-memory.tsv`), whose **stack** would reach
     (`low_base_has_stack_headroom`: `sp_min - _end >= LOW_BASE_MIN_MARGIN`,
     4096), or that a **fill loop with constant bounds** covers
     (`constant_range_fills` + `low_loader_painted_by_title`). The last is the
     Katana crt0 painting `0x8c00c000..0x8c00f400` with `"SEGA"` before it calls
     anything — six of six boot binaries examined do it — so with a CD-DA loader
     (`_end` 0x8c00cb48) **the low family is out for every retail title**. It is
     a write and not a mention, which is why it counts inside the image the
     constant scan deliberately skips at a low base (loader AGENTS.md 4.6).
     Presets below `0x8c004000` cannot be built and send the loader to
     the largest free region instead; a split vote that includes such a preset
     moves the loader off the low family (`low_family_contested`), and so does
     a low base the set cannot be relocated to (`LoaderSet::can_provide`
     relocates for real below `0x8c010000`: since 2026-09-30 the image does not
     fit under the BIOS VBR). A high preset refused by the constant scan is
     read as a window (`preset_window_base`): the loader goes against the
     lowest address the title names above the preset, with no map margin --
     0x8cfe0000 for Shenmue II (measured) and Crazy Taxi (not yet), under
     their Maple DMA list at 0x8cff0000. Off the low
     family the search is seeded from `ISOLDR_HIGH_ADDR` for a title in the
     database and from `SCRATCH_BASE` for one that is not: no preset has an
     opinion there, it is one hop, and it is where Snow Surfers ran every CD-DA
     session.
   - Chainload: relocate `loaders/dcload-relocatable.elf` in memory
     (`loaders::relocate`, four region deltas plus `.guestvbr` patched by
     content) and upload it, **always hopping via `0x8ce00000`** (a direct move
     to `0x8cfe8000` from a low base writes over the running loader's packet
     buffers and leaves a deaf loader). A running loader whose image differs from
     the file is replaced even at the same base. `refuse_self_overwrite` blocks
     uploading over the running loader's own physical RAM, on every path.
   - `--loader-base 0x…` pins a base; `--no-relocate` keeps whatever runs.
4. **Payload.** `main.rs::resolve_payload`: a file as is, or the boot binary an
   image names (`disc_formats::boot::extract`). Then, in the buffer and before
   upload: PPF patches (§6), the GAPS guard (loader AGENTS.md 4.12), `--vga`
   (§5), descrambling (`--descramble`). The patched words are also re-applied
   whenever a later disc read reloads them.
5. **Upload** (`dispatch::upload_bytes` → `send_data`): an ELF is uploaded
   section by section (`loaders::is_uploadable`: `SHF_ALLOC` and a non-zero
   address); anything else at `--address` (default `0x0c010000`). `LBIN`, the
   `PBIN` parts, then `DBIN` probes and resends from the address it reports
   (runs doubling up to 64). Transfers larger than `MAX_XFER` (256 × 1440, the
   loader's map) are split.
6. **VM2 / VMUPro** (`src/vm2.rs`), with a disc image only: probe the four
   Maple ports for a card that selects games, and hand each one the disc's
   product number so the saves that come up are the right game's. Eight `MAPL`
   round trips in the last idle moment before the title starts; never fatal,
   `--no-vm2` to skip.
7. **Execute** (`dispatch::execute`): `EXEC` with console/CDFS flags. `-d`, `-m`
   or a disc image turn console redirection on.
8. **Syscall loop** (`dispatch::receive_syscalls`), until `DC00` Exit:
   `ReadSector` (disc sectors), `ReadAudio` (CD-DA, §4), `ReadToc`
   (`cd::build_dc_toc`), `FSCommand` (`src/fs.rs`). At the top of each
   iteration the counter panel and the stack watch may post one `SBIQ` each.

`upload` connects, resolves the payload and uploads it, with no loader
placement and no execution. `reboot` sends `RBOT` (only honoured by dcload
itself).

## 2. Build, run, commands

- `cargo build` (dev profile builds this crate at opt-level 1 and `miniz_oxide`
  at 3, so zip indexing is usable), `cargo build --release` (fat LTO, slow).
- **From WSL, never build in the project's `target/`**: the user builds and
  debugs this project on Windows in that directory. Use
  `CARGO_TARGET_DIR=<somewhere else> cargo …`.
- No `make`, no `xtask`, no CI, no formatter or lint configuration.

Subcommands (`src/main.rs`, clap derive). **Global options such as `-H/--host`
go before the subcommand**: `dcload-ip-rs -H <IP> u-exec game.gdi`
(`u-exec --host …` is rejected).

| Command | What it does |
| --- | --- |
| `u-exec <file or image>` | upload and run; with an image, also serve its disc. `-d <image>` serves another image, `-m <dir>` a host directory (`-d` and `-m` conflict), `-c` console output |
| `upload <file or image>` | upload only |
| `identify <image>` | what the image is, the base the placement would choose, patches that apply, VGA info; no network |
| `extract <image> [-o out]` | write the boot binary out |
| `audit-audio <image> [--track N]` | judge the image's audio tracks for defects (§4); no network |
| `relocate <elf> <base> -o <out>` | the in-memory relocation, written out (e.g. to point `dc-counters.py --elf` at it) |
| `selftest-readback` | write known patterns to free RAM and read them back: can a read-back from this console be believed |
| `reboot` | `RBOT` |

Global options worth knowing: `-H/--host`, `-v`/`-vv` (or `RUST_LOG`), `-p/--port`,
`-i/--infinite`, `-a/--address`, `--loader-dir`, `--game-db`, `--memory-db`,
`--loader-base`, `--no-relocate`, `--patch ADDR=VALUE` (poke after upload),
`--ppf FILE`, `--no-ppf`, `--patch-dir`, `--no-gaps-guard`, `--no-vm2`, `--no-wince`,
`--vga auto|always|never`, `--no-cdda`, `--cdda-tone`, `--probe ADDR=ID[:PEEK]`
(a stub that logs when ADDR executes),
`--descramble auto|always|never`, `--boot-ipbin`, `--diag`, `--diag-interval`.

Data files live at the **project root**, outside `target/` so `cargo clean`
cannot take them and debug and release read the same set: `loaders/`,
`game-presets.tsv`, `game-memory.tsv`, `patches/`. Each has an option and an
environment variable; a directory beside the executable is honoured last.
**Never keep a second loader set under `target/`**: a stale loader answers with
counters at addresses that have moved, and every value reads back believable
and wrong.

Environment variables:

| Variable | Effect |
| --- | --- |
| `DCLOAD_LOADER_DIR`, `DCLOAD_GAME_DB`, `DCLOAD_MEMORY_DB`, `DCLOAD_PATCH_DIR` | data file locations |
| `DCLOAD_CDDA_TRIM=0` | do not send the CD-DA clock trim (§4) |
| `DCLOAD_CDDA_SAFE=1` | send audio through the acknowledged path; times out against current loaders (§4) |
| `DCLOAD_RT_BURST`, `DCLOAD_RT_DELAY_US` | runtime transfer pacing (default 6 packets, 600 µs spin) |
| `DCLOAD_VERIFY_READS=1` | read every served disc read back with `SBIQ` and compare |
| `DCLOAD_ZERO_LBA`, `DCLOAD_REDIRECT_ABOVE` / `_TO` | diagnostics: blank one LBA's payload; redirect reads above an address |
| `DCLOAD_LOAD_BAR_KB` (256, 0 = off), `DCLOAD_LOAD_IDLE_MS` (250) | in-game loading bar |
| `DCLOAD_ZIP_INDEX_BUDGET` | MiB of deflate checkpoints per indexed zip member (default 64) |
| `DCLOAD_TEST_ORIG`, `DCLOAD_TEST_PATCHED` | inputs of the ignored PPF reproduction test |

## 3. Tests

`cargo test` runs the unit tests in `adpcm`, `cd`, `diag`, `dispatch`,
`loaders`, `main`, `marks`, `memmap`, `patchdb`, `ppf`, `presets`, `stackwatch`, `ui`
and `disc_formats::{cdi, deflate, gdi, scramble, source, zip}` (228 at the time
of writing, one ignored). Tests that need a real dump skip when it is absent:
the GDI and zip tests want `test/Sonic Adventure ….gdi` and
`test/sa-deflate.zip`; `relocating_reproduces_every_native_link_byte_for_byte`
wants a loader set (point `DCLOAD_LOADER_DIR` at a fresh
`target-src/dcload/loaders` to test the tree rather than what was deployed).
Only `loaders/` is kept in this project root: an A/B set is built into a
directory of its own and passed with `--loader-dir`.

The `test/` directory is gitignored Dreamcast payload data. **Do not rename it
to `tests/`**: Cargo would treat its contents as integration tests.

Past `EXEC`, verification needs a console or flycast. Two things help without
one: `dispatch::cdda::tests` drives `send_audio` through an in-memory
`ExternalDcIo`; and a small Python UDP stub on `127.0.0.1:53535` that answers
`VERS`, echoes `LBIN` and answers `DBIN` with the first missing part can drive
a whole `upload` (answering `DBIN size=0` unconditionally ends the upload after
eight packets).

Watch `cargo test` warnings: a `#[test]` attribute separated from its function
by a stacked doc comment silently stops a test running (this happened twice in
`adpcm.rs`).

## 4. CD-DA

The loader plays a disc's audio tracks itself (loader AGENTS.md §4.13, and the
header of its `cdda.c`). This host answers its audio requests.

**Requests** (`cmds.rs`, `DCLoadClientCmds::ReadAudio`):

- `DC23`: raw 2352-byte sectors (16-bit PCM). value0 = LBA, value1 =
  destination, value2 = bytes.
- `DC24` (the loader's default): 4-bit Yamaha ADPCM, left block then right.
  value2 = frames (= bytes; sectors = value2 / 588), **bit 31 = restart the
  encoder**.

**The answer** (`receive_syscalls`, `ReadAudio` arm): the samples come from
`DiscFormat::read_audio` (GDI and CDI; refuses a data track), or from the test
tone, are scanned by `SlewWatch`, encoded if ADPCM, then sent by `send_audio`:
LoadBinary and parts, **no acknowledgement round trips**, then a ReturnValue
whose **`address` is the LBA served** (the loader rejects any other) and whose
**`size` is the clock trim in ppm**. A refused read gets `u32::MAX`, and the
loader asks for the same sectors again, forever: the music stops there. So
**a sector inside a track's span is never refused**: a play range runs to the
next track's start, and what lies past the track's file (the next track's
undumped pregap, 150 sectors after Snow Surfers' track 18) is served as
silence. Only a read past the last track is an error.

Rules:

1. **`CDDA_GIVE_UP` (15 ms) must stay below the loader's
   `CDDA_FETCH_DEADLINE_TICKS` (20 ms).** An answer that took longer to produce
   is dropped entirely, ReturnValue included: the loader has given up on it and
   would otherwise take it for its next request's answer.
2. **The ADPCM encoder is one continuous stream** (`adpcm::Stream`): its state
   is the AICA decoder's state. It never resets except on bit 31, and a re-ask
   gets the bytes that were sent the first time, from the last `RECENT` = 48
   requests. `lost_replay` (a re-ask older than that) must stay 0; `RECENT` must
   cover the loader's whole ring (26 sub-fetches), of which it asks for the
   lead (20) back to back at every PLAY. **A re-ask is served from that history before the
   disc is read** (`Stream::replay`): the loader re-asks because an answer was
   late, usually because the read was slow, and re-reading made every re-ask
   late too (19 dropped in a row on one LBA, 2026-09-16).
3. **The codec must be the AICA's.** `oxideav-adpcm`'s `Chip::Aica` has the
   AICA step constants, not the YM2608's; a mismatch drifts rather than failing
   loudly. `the_crate_still_decodes_like_the_aica` pins it. **And no nibble may
   decode two ways**: flycast and Sega's encoder clamp a nibble's contribution
   to `0x7fff`, the crate and MAME do not, and the silicon is unmeasured. The
   crate's own encoder emits such nibbles on near full-scale swings, and the
   offset they leave does not heal (Snow Surfers, simulated 2026-09-16: twice
   in the intro track, 14 260 times in track 14). So `adpcm.rs` picks its own
   nibbles (`pick_nibble`) and only uses the crate to decode;
   `no_nibble_decodes_two_ways` is the test, and a loader counter can never see
   this class of defect (sound RAM holds exactly the bytes sent).
4. **Never do slow work on this path.** The title is frozen from its request
   until the ReturnValue. That includes waiting on a lock another thread holds
   across I/O: the memory map's ticker takes its data under the lock and writes
   the file without it (`MemoryRecorder::take_due`). Accounting and logging come after it; a suspected
   defect is not re-read on the live path (that once took 223 ms).
5. **No acknowledgement round trips on audio.** Measured 2026-08-31, they were
   2.4 ms of the 3.0 ms an audio request froze the title. The loader detects an
   incomplete window itself and re-asks. One request in 256 is probed with a
   DoneBinary to catch a lossy link. `AUDIO_BURST_PACKETS` (8) guards the
   loader's RX ring but does not fire at the default geometry (2 packets ADPCM,
   5 PCM).

**The clock trim** (`CddaClock`). The loader times its ring with an SH4 timer
of compiled-in period; nothing on the console is locked to the AICA. This host
measures audio staged per second of real time **by disc position** (a re-asked
request repeats an LBA), over free-running intervals banked in 2 s segments,
and returns the estimated scale: first after 90 s of accepted stream, then
every 300 s, each a fresh estimate of one constant. Windows that do not look
like real time are discarded (±3 %), estimates outside ±1.5 % are refused. On
the test console it settles near 184 ppm.
**The thresholds (`CDDA_TRIM_*`) describe the loader's geometry**: since
2026-09-20 it paces its stream, one sub-fetch of 4 sectors every ~53 ms, so a
window may begin and end anywhere -- the phase it cannot account for is one
service call, ~190 ppm over the first 90 s window and less as the accumulated
span grows. The segment length is what refuses a **catch-up**: an interval
longer than `CDDA_TRIM_GAP_MAX` is dropped, but the audio it owed is delivered
in a burst just after, and counted it is worth 3000 ppm. If the pacing changes
on the loader, re-check these and the `feed_stream` tests; they once described
an 80 ms half and the estimator accepted nothing for days while every test
passed. `DCLOAD_CDDA_TRIM=0` is the A/B.

**Continuity** (`SlewWatch`, `audit_audio`). Large sample-to-sample steps are
normal in loud music, so their count means nothing; a defect in the pipeline
(dropped sector, wrong deflate cursor, ring seam) lands at a fixed offset inside
a sector. `verdict()` histograms hit positions modulo 588 frames and only a
spike over 8 sigma is a defect. Live, only such a spike produces a warning (with
32 bytes around the first run); `audit-audio` judges a whole image offline.
The Snow Surfers image was judged clean this way.

**The TOC** (`src/cd.rs`). Built from `DiscFormat::toc_tracks()` with the CTRL
nibble (audio 0, data 4), per area; area 2 is the loader's own request for the
whole disc. A format that cannot enumerate tracks gets the old one-data-track
table byte for byte. Without audio tracks in the TOC a title never asks for
music.

**Switches**: `--no-cdda` refuses every audio read (the title keeps its data);
`--cdda-tone` serves a 344.5/689.1 Hz triangle instead of the disc read (encoder,
network and loader still run). `DCLOAD_CDDA_SAFE=1` uses the acknowledged
`send_data` path, which waits for a LoadBinary echo current loaders do not send
on audio, so it only works with a loader built without that suppression.

**The log**: every 250 audio requests, a block of lines — request rate against
real time (a runaway guard; counts requests), the clock estimator's view, the
continuity counts, the ADPCM history (`replays`, `out_of_order`, `lost_replay`),
and what the music costs the title (ms frozen per request, disc vs rest, share
of wall time; this host's half only). Also, as they happen: any request over
20 ms, any answer dropped as too late, and lossy probes. CD-DA reads are not
recorded in `game-memory.tsv` (they land in the loader's staging buffer).

## 5. Forcing VGA

`--vga` makes a title believe a VGA box is plugged in, with two changes found
by content (no per-game table), applied before the title runs:

- **The cable check** (`dispatch::vga_cable_patches`). A Katana title reads the
  SH4 port `0xff800030` once and takes bits 8-9 (0 VGA, 2 RGB, 3 composite).
  The read (`mov.w @r3,r4`) becomes `mov #0,r4`. Found by an `mov.l @(disp,PC)`
  that loads the address followed by a read through that register.
- **IP.BIN's peripheral field** (`declare_vga_in_ip_bin`), bit 4 of the hex
  string at +0x38, for IP.BIN's own bootstrap (`--boot-ipbin`) and titles that
  read the header back from `0x8c008000`.

| title (PAL) | cable check | IP.BIN peripherals |
| --- | --- | --- |
| Sonic Adventure | 0x8c10d866 | `0601A10` (declares VGA) |
| Sonic Adventure 2 | 0x8c137276 | `0799A10` |
| Crazy Taxi | 0x8c162dee | `0799A10` |
| Snow Surfers | 0x8c0e9026 | `0799A00` (does not) |

`auto` (default) patches only when the loader reports a VGA cable, asked at the
moment of decision (`query_cable`, since a chainload replaces the loader).
Unknown means "leave the title alone": the VGA code is 0, so a loose decode must
never read as VGA. `always` covers adapters that do not ground the detect pins.
`--vga` cannot add a 480p mode a title was never built with; `identify` says
what it can do. Patched words survive a reload (§1 step 4).

**Direct calls to the BIOS GD driver** (`dispatch::gd_body_patches`), always
on. The loader emulates the GD driver by holding its syscall vectors
(`0x8c0000bc`, `0x8c0000c0`); a title that calls the driver body at
`0x8c0010f0` by address goes past them to the real drive. Every 4-aligned
`0x8c0010f0`/`0xac0010f0` in the payload is rewritten to the running loader's
`_gd_bios_entry` symbol (read from the relocated ELF, `gd_bios_entry()` in
`main.rs`), verified, and added to the reload guards. Windows CE does this
(23 sites in Sega Rally 2); none of the Katana test titles does. `identify`
prints the count on a `gd body` line.

**Windows CE titles** (`boot::WinCe`). A boot file named `0WINCEOS.BIN`, or
carrying `"ECEC"` at +64, is a CE title. For the named case the first 2048-byte
sector is dropped before anything else sees the payload (upload, PPF, every
content scan, placement), as DreamShell's isoldr does, and the title is entered
through the disc's own second bootstrap as `--boot-ipbin` would. `--no-wince`
uploads it whole and enters it directly. The skip is parity with isoldr, not a
proven entry point: see the loader's `docs/wince-investigation.md` and its
AGENTS.md §4.15 for what is known and what is still open.

## 6. Shipped patches (PPF)

For fixes nobody can derive, only carry (e.g. a 60 Hz/VGA patch for Snow Surfers
PAL): `patches/patches.tsv` plus `.ppf` files, found like the other data files
(`src/patchdb.rs`, `src/ppf.rs`: PPF 1.0/2.0/3.0).

- **A row is a claim the patch checks.** A PPF3.0 blockcheck (1024 bytes of the
  original) must match, or the patch is refused, including one given by hand
  with `--ppf`; `bin_md5`/`disc_md5` columns cover formats without a blockcheck.
- Applied to the payload **before** upload (so read-back verification and the
  scans see the patched code), then guarded against reloads like the GAPS guard.
- `apply` is `auto` or `manual`; a manual patch is offered, not applied. A
  `.ppf` without a row is offered only if its blockcheck matches.
- `--no-ppf` disables the list but still reports what it held back.
- `ppf::tests::reproduces_the_shipped_patched_binary` (ignored; needs the
  retail dump) checks the result against the patch author's own output.

## 7. Architecture

- **`main.rs`** — CLI, logging, placement decisions (`wanted_loader_base` and
  helpers), payload resolution and patching, `measure_rtt` (five 4-byte `SBIQ`
  round trips before EXEC: the link's baseline), and the session wiring.
- **`dispatch/`** — everything on the wire after the socket is open; its
  items are re-exported, so callers name them `dispatch::…`.
  `session.rs`: handshake, loader placement, upload, `execute`, read-back
  self-test. `transfer.rs`: `send_data`, `send_data_one`, `send_sectors`,
  `receive_data`, `await_result`, pacing. `syscalls.rs`: the loop
  (`receive_syscalls`), which hands each `ReadSector` to `sectors.rs`
  (`SectorServer`: the read, the loader-collision and memory-map checks,
  `DCLOAD_VERIFY_READS`, guard re-application) and each `ReadAudio` to
  `cdda.rs` (`AudioServer`, `send_audio`, `CddaClock`, `SlewWatch`,
  `audit_audio`). `patches.rs`: GAPS/VGA/GD-body/literal/fill scans,
  `apply_patches`, KOS. `image.rs`: `open_disc`, `identify`. `probes.rs`:
  `--probe`.
- **`adpcm.rs`** — the ADPCM stream (§4).
- **`loaders.rs`** — VERS payload parsing, the layout table (the host's copy of
  the loader Makefile's: `layout()`, `live_footprint()`, `HIRAM_RESERVED` 12 KB,
  `LOADER_SPAN`), relocation, the chainload plan.
- **`presets.rs`**, **`memmap.rs`** — DreamShell presets and disc identity;
  the learned per-title map (256-bit, 64 KB per bit, merged by OR) and `sp_min`
  (merged by minimum), written by a ticker thread every 2 s rather than on the
  read path, so a killed session still leaves it.
- **`marks.rs`** — what a title writes with the CPU (2026-09-30). Before
  `EXEC` the loader paints witness words over every 64 KB block above the
  title's image that is neither known used nor its own (`MARK`, dcload-ip
  AGENTS.md 8); while the title runs, 16 blocks are checked each second and a
  changed one is recorded as used. Not for Windows CE; `--no-marks`. Replies
  come through a `PacketSink` that claims every `MARK`. The loader answers
  between reads too (its idle listen, `IRQ_IDLE_LISTEN`), BBA only.
- **`stackwatch.rs`** — reads `g_gd_sp_min`/`g_gd_sp_in_image` every 10 s in
  every session and records `sp_min`. A reading outside RAM is neither recorded
  nor a verdict, it is reported as "not the loader this session verified": a
  title that goes back to the BIOS menu makes the disc boot another build,
  which answers the same addresses with other globals (measured 2026-09-17,
  `0x00010100` = three flag bytes of the CD build).
  A 4-aligned value in `0x02000000..0x42000000` outside main RAM's P0
  window is a Windows CE thread stack (MMU on), said once and not recorded.
- **`wince.rs`** — Windows CE titles (2026-09-27; dcload-ip:
  docs/wince-investigation.md). CE's kernel owns RAM `ulRAMStart..ulRAMEnd`
  from its `ROMHDR` and allocates top-down, so `wanted_loader_base` puts the
  loader at `ulRAMEnd - LOADER_SPAN` (`0x8cee0000` for Sega Rally 2), ahead
  of any preset, and the upload lowers `ulRAMEnd` to the loader's base
  (`ram_end_patch`). `pio_patches` turns the branch of CE's GD driver that
  sends an aligned read to DMA into a branch to its PIO path: CE chains DMA
  stream pieces from the G1 DMA-end interrupt, which this transport never
  raises, while PIO pieces are chained from a callback the loader calls. Both
  found by content, applied with `apply_patches`, guarded like the others;
  `identify` prints them (`ce ram`, `ce gd`). The syscall loop does not count
  a read into the loader's `_gd_stage` or `_gd_stage_big` as a collision or as
  title memory: the loader stages reads for translated addresses there
  (`loader_stage`). `send_sectors` scales its post-LoadBinary pause to the
  window (full `DCLOAD_RT_DELAY_US` at 16 KB, never below 100 us): a CE title
  reads through those 6-10 KB stages hundreds of times per file and waits for
  every trip.
- **`diag.rs`**, **`ui.rs`** — the counter panel (§9) and everything that draws
  on the terminal.
- **`io.rs`** — `DcIoUDP`; `handle_data` drains the socket each wakeup;
  `PacketSink` lets the panel and stack watch claim their replies wherever the
  host happens to be polling (they arrive inside other transfers).
- **`vm2.rs`** — the VM2/VMUPro game ID over the loader's Maple passthrough
  (§11). Pure frame building and answer reading, plus a `MapleBus` seam so the
  scan is testable: `polling::Events` cannot be fabricated, so a fake
  `ExternalDcIo` can record what was sent but can never answer.
- **`cmds.rs`**, **`types.rs`** — wire formats. Command headers, payloads and
  syscall parameters are big-endian; the TOC and `DCLoadStat`/`DCLoadDirEnt`
  are little-endian.
- **`fs.rs`** — host file syscalls for `-m`: sandboxed by
  `join_and_check_path`; first fd 10, first dir handle 1337; errors are
  `u32::MAX` return values, not `Err`.
- **`cd.rs`** — the TOC (§4).
- **`disc_formats/`** — `DiscFormat` (`types.rs`), `iso`, `gdi`, `cdi`; readers
  get bytes through `ImageSource` (`source.rs`), so `zip.rs` can serve an image
  from inside a `.zip` in place (stored members directly, deflated ones through
  `deflate.rs`'s checkpoint index, CRC-32 verified while indexing); `iso9660.rs`,
  `boot.rs`, `scramble.rs`.

Disc-reader facts that cost time:

- **Filesystem LBAs are not `read_sector` LBAs**: +150 on `.gdi`, `.iso`
  and `.cdi` alike. `DiscFormat::fs_lba` converts, once, in `iso9660.rs`. Getting it wrong
  is silent (an empty directory).
- **A GDI's boot track is the first data track at or above LBA 45000**, not the
  first or last data track (a disc with CD-DA in the high-density area is
  `data / audio / … / data`). `start_sector()` stays the low-density track,
  because that is the sector DreamShell hashes.
- **A CDI's boot track** is the one with an ISO9660 PVD at sector 16 whose root
  extent lies inside it (images start with an audio track; "SEGA SEGAKATANA in
  the first sector" picks a stub session).
- One read per request, not per sector, when a track stores plain 2048-byte
  sectors; a request spanning tracks falls back to per-sector reads.
- Names from a dump are untrusted: `plain_track_name`, `boot_file_name`,
  `safe_output_name`; `ZipArchive::find` is exact.
- A scrambled binary uploads and verifies perfectly, then runs noise. Detection
  is one-sided (homebrew only); `--descramble always` for a retail CDI
  conversion that does nothing.
- The first read of a **deflated** zip member builds its index: ~4.7 s for a
  1.1 GiB track in release (~5.7 s in dev), ~130 ms for a 17 MiB audio track.
  `zip -0` avoids it. The index pass logs `waited / inflate / crc` at debug
  level; read it before optimising. `CURSORS` (8) is a cliff: too few and
  interleaved reads cost 10x.
- **An audio track's index must never be built on a syscall path.** It used to
  be, inside the first CD-DA read of the track, and 140 ms there is the
  loader's whole fetch budget seven times over: the loader's first sub-fetch
  failed, `cdda_prime()` keyed the channels on short, and the music began with
  693 ms of silence — every track, every session, and invisible to every
  counter on the console. `zip::warm_track_indexes` now builds them on a thread
  when the `.gdi` is opened (before the title is even uploaded), filling the
  same `INDEX_CACHE` the read path consults; nothing waits on it, and a track
  the title reaches first is indexed by the read path as before.
- Every image open failure is reported with its reason; a mistyped `-d` does not
  silently leave CDFS dead.

## 8. Protocol modes

`CHUNK_SIZE` in `main.rs` switches both the protocol version and the local bind:

- `1440` (default): version `[2, 0, 3]`, remote port from `--port` (53535),
  local bind `0.0.0.0:0`.
- `<= 1024`: legacy `[0, 0, 0]`, remote **and** local port forced to 31313,
  whatever `--port` says.

No negotiation: check the mode first when a console does not answer.

## 9. Debugging

- `-v`/`-vv` or `RUST_LOG=debug|trace`. Commands log through `Display`
  (`LBIN 0x0c010000 +368640`); `DoneBinary` is at TRACE. **Everything the
  CD-DA path logs while a title plays is at DEBUG** (late answers, the clock
  trim, throughput, continuity, re-asks): `-v` to see it.
- A memory read-back (`receive_data`) re-requests a chunk that was slow, so the
  first answer can arrive after the second: that duplicate is dropped at
  DEBUG, not reported as an unexpected command.
- `.vscode/launch.json` holds personal launch configurations (console at
  `192.168.1.64`, Windows paths): templates, not to be committed as is; the same
  goes for `.continue/` and `.zed/`.

**Terminal** (`src/ui.rs` owns it): one `MultiProgress`; log records are printed
inside `suspend`, so bars must come from `ui::bytes_bar` or they get shredded.
One bar per upload, advanced on bytes the loader acknowledged; no bar under
10 KB; nothing drawn when stderr is not a terminal. The in-game loading bar
(`LoadMonitor`) groups consecutive disc reads into bursts, shows bytes and rate
but no percentage (the wire does not carry the total), is updated only after
the ReturnValue, and makes the loop poll with a timeout only while a burst is
open.

**Counter panel** (`--diag`, `src/diag.rs`):

- `d` switches sampling on and off at any time (off means nothing is asked);
  `w` prints a plain-text snapshot, zeros included, and appends it to
  `dcload-diag.txt`; `+`/`-` change the interval (default 2 s, floor 250 ms).
- The image is verified (256 bytes of code against the uploaded ELF, relocated
  ones included) before anything is decoded: two builds at one base put counters
  at different addresses.
- Samples are posted from the top of the syscall loop and never block it; the
  replies are claimed by address in the IO layer. The panel and the stack watch
  overlap in range, so only one is active at a time.
- The loader answers only from inside `bb->loop()`, so a title that has stopped
  reading its disc may leave the panel unanswered (the loader's CD-DA idle
  window helps while music plays). The header shows the **measured** interval
  between samples, which can be longer than the setting; rates use it.
- Requests are sent one packet at a time and retransmitted every 300 ms; a
  sample times out after 5 s. On the first miss a control read of known loader
  bytes says whether the loader answers `SBIQ` at all.
- The panel is a paged grid drawn in indicatif's live region, so it never enters
  the scrollback.

## 10. Gotchas

- **Runtime transfers are paced with a spin, never `thread::sleep`**
  (`spin_for`). The loader answers a disc read synchronously, so every host-side
  wait freezes the title, and Windows rounds sleeps up to the timer tick:
  removing three sleeps per chunk took Sonic Adventure from 45.6 ms to 1.5 ms of
  freeze per 16 KB read. The upload path (before EXEC) still uses sleeps.
- **The runtime pacing default is itself a cost**: a 600 µs spin every 6
  packets, two per 16 KB read (`DCLOAD_RT_BURST`/`DCLOAD_RT_DELAY_US`), bought as headroom in the
  loader's 16 KB RX ring, whose overflow does not recover gracefully.
- **A failed disc transfer must not end the session**: the loader times out and
  re-asks. No ReturnValue is sent for an unanswered read, so a title never gets
  a half-filled buffer marked complete.
- **A malformed `ReadSector`** (size not a sector multiple) means the loader's
  state was overwritten, usually by a title's stack at a low base: logged,
  refused, session kept.
- **A reply to an earlier read can arrive during the next one**: `receive_data`
  accepts a chunk only if its address and length fit (`chunk_is_ours`) and bounds
  itself by progress, not by packets received.
- **A disc read landing on the loader** is reported as an error (it overwrites
  the loader silently); reads coming within 256 KB of a high loader are a warning.
- **The relocator refuses what it cannot classify.** When `.hiram` grew, a
  symbol at its end stopped fitting the old 4 KB classification and relocation
  failed at every base; the unit test caught it.
- `cdi2iso.c` at the root is untracked third-party GPLv2 reference code, not
  built.
- `-d`/`-m` turn console mirroring on with no warning.

## 11. VM2 / VMUPro

**Status 2026-09-20: the VMUPro is still not found, and the fault is now
localised to one transaction.** Hardware: a VMUPro in A1, a VMU in A2, two VMUs
on port B.

| slot | answer |
| --- | --- |
| A0 (controller) | `5` from `0x23` -- **it reports slots 1 and 2 occupied** |
| A1 (VMUPro) | `0` from `0xff`: eight longwords of `0xffffff00`, then the cleared buffer |
| A2 (VMU) | `-1`, as if empty |
| B0 (controller) | `5` from `0x63`, slots 1 and 2 occupied |
| B1, B2 | `5` then `6`, "Visual Memory", extended `"Version 1.005,…"` |

Everything on port B is perfect, so the parsing, the addressing and the
enumeration are right. The controller on port A **sees both its cards**. What
fails is one transaction: the first one addressed to A1. It produces exactly
32 bytes -- the buffer clear shows where the DMA stopped -- of a pattern that
is not a Maple frame and is not the controller's `-1` timeout either. **After
that burst, both of port A's slots answer as empty**, which is the wedge the
owner otherwise clears by unplugging the controller.

Two things remain that KOS does and this did not, both now done:

- **Pacing.** KOS flushes its frame queue from the vblank handler, at most once
  per frame, and never starts a burst before the previous one's completion
  interrupt. Every frame a device sees under KOS therefore arrives at 60 Hz or
  slower. This host drove the bus once per UDP round trip, about a
  millisecond. `PACE_MS` (17, `DCLOAD_VM2_PACE_MS`) puts a vblank between
  transactions; the sleep is legitimate here because this is before `EXEC`.
- **Reset.** A controller that reports a slot occupied while the slot answers
  as empty is a contradiction, not a verdict, and KOS has the software
  equivalent of unplugging a device: `maple_dev_reset` sends Maple command 3,
  which KOS does to every device on shutdown "to leave them as we found them".
  The scan now sends it to a reported-but-silent slot and asks once more.

If that does not do it, the question is no longer software, and the control is
physical: **move the VMUPro to controller B's slot 1**. If port B then fails
the same way and port A recovers, the fault follows the device.

The one byte that can say why was not being printed: **the response frame's
sender byte**. Bit 5 marks a port's main device and bits 0..4 are one per
expansion slot, so `slots_reported()` reads the controller's own account of
what is plugged into it -- something no amount of addressing a slot can give,
because a slot the controller does not report answers exactly like an empty
one. **B0 is the positive control**: it must say slots 1 and 2 are occupied,
and if it does not, the instrument is wrong rather than port A.

`DCLOAD_VM2_WARMUP` overrides `WARM_UP_ROUNDS` so the amount of warming can be
found on the console without a rebuild.

Also learned: **a plain Sega VMU does not have a blank `extended` field** -- it
carries its own version string. The guess that it did is gone, and the scan
now reports by outcome rather than trying to judge each card.

- **Detection**: `DEVINFO` (command 1) then `ALLINFO` (command 2) to units 1
  and 2 of each of the four ports. Unit 0 is the controller. A plain VMU
  answers both and must be left alone: what separates them is the 40-byte
  `extended` field after the standard 112-byte device info, holding
  `"VM2 by Dreamware"`, `"8BITMODS VMUPro "`, `"USB RP2040 EMU  "` or
  `"Pico2Maple USBBT"` -- matched as a **substring**, case-insensitively, so a
  firmware that pads with NUL or appends a version still matches.
  **`DEVINFO` first is not decoration**: openMenu calls `check_vm2_present` on
  a device KOS has already enumerated on a timer, so ALLINFO is never the first
  thing that device hears. dcload never polls the Maple bus, so without this it
  was. It is not a gate -- a device that answers one and not the other is what
  this is looking for -- and its answer is logged.
- **A rejected slot explains itself.** `identify` returns `None` four ways:
  empty slot, a device that refuses `ALLINFO`, a frame too short to reach
  `extended` at offset 116, and a name nobody knows. A scan that prints nothing
  cannot be told from a scan that found nothing, which is exactly what happened
  on 2026-09-20; `explain()` now names which one, at `info` for anything that
  is not an empty slot or a blank-`extended` plain VMU.
- **Selection**: Maple command 33. Payload = the memory-card function code
  **big-endian** (`00 00 00 02`; KOS writes the same bytes as `0x02000000`),
  12 bytes of product number and, when there is one, 128 bytes of title --
  `strncpy` semantics, so NUL-padded with no terminator on an exact fit.
- **Transport**: the loader's `MAPL` passthrough. Its argument block is port,
  unit, command and **payload length in LONGWORDS**; the reply's `size` is how
  many bytes it copied, and response codes are signed (-1 nothing there, -4
  busy). Loader AGENTS.md §8 is the reference.
- **Every answer is matched to its request.** `cmd_maple` copies the request's
  header into its reply and overwrites only `size`, so `address` carries a tag
  (port, unit, command) back. **This is not optional**: the scan runs in the
  seconds after an upload and one wakeup drains the whole socket, so the first
  batch a probe sees is routinely the upload's own tail. The first version read
  that as a silent console and gave up on the very first probe, with a VMUPro
  sitting in A1 (2026-09-20). A batch without our tag is not an answer and not
  a silence; `transact` keeps waiting until its deadline.
- **Bounded, and never fatal.** `AGAIN` is retried four times on top of the 64
  the loader does. Each request is sent up to three times with a 500 ms window.
  **Two consecutive** unanswered probes end the scan -- an empty slot still
  answers promptly, so real silence means `WITH_MAPLE=0` or a dead link, and
  eight probes at three tries and 500 ms is twelve seconds in front of `EXEC`.
  One is a hiccup, and treating it as a verdict is what cost the first run.

**It needs a loader from 2026-09-20.** No payload longer than one longword had
ever gone through `MAPL`, and two defects were waiting there: the payload copy
counted longwords into a byte-counted memcpy (a 12-character ID arrived as 3),
and the response was read back through the cache, so every probe after the
first returned the first one's answer. Both are fixed on the Dreamcast side.
There is no feature bit to test for it; the host chainloads its own loader for
every disc image, so redeploying `loaders/` is what keeps the two in step.

`polling::Events` cannot be constructed by hand, so a fake `ExternalDcIo`
cannot answer anything — which is why the module's seam is `MapleBus`, one
Maple transaction, and the scan is tested against a scripted console rather
than against a socket.
