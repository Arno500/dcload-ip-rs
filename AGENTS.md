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
   - Windows CE (§5) and KOS (§5) titles have their own rules, and so does a
     title with an HLib heap (§5): the loader goes at its bottom. A base the
     rules put inside a heap a program sizes from a literal end (§5) moves to
     that heap's top.
   - **The resident image** (`variants.rs`, loader AGENTS.md 4.18). After the
     base is chosen, `choose_loader_image` serves `dcload-resident.elf` (no
     screen, no DHCP; `variants::patch_resident` writes the console's `-H`
     address and port into `.data` after relocation) for a disc image's title
     at a high base; every hop, `--loader-image universal`, `--probe`, a plain
     file, a low base or a missing file is `dcload-relocatable.elf`. When VERS
     says the resident image runs, its symbols are read from its own file
     (`note_running_loader`, `variants::running_image`). The per-title variants
     and the core were withdrawn on 2026-10-05.
   - Chainload: relocate `loaders/dcload-relocatable.elf` in memory
     (`loaders::relocate`) and upload it, **always hopping via `0x8ce00000`**
     (a direct low→high move overwrites the running loader's packet buffers).
     A running loader whose image differs from the file is replaced even at
     the same base. `refuse_self_overwrite` blocks any upload over the running
     loader, on every path.
   - `--loader-base` pins a base; `--no-relocate` keeps whatever runs.
4. **Payload** — `resolve_payload`: a file as is, or the boot binary an image
   names (`disc_formats::boot::extract`). Then, in the buffer before upload:
   PPF (§6), the GAPS guard (loader AGENTS.md 4.12), the HLib heap, VGA,
   GD-body, CE and KOS patches (§5), descrambling. Every patched word, `--patch` words inside the
   image included, is put back whenever a later disc read reloads it: in the
   read's own data before it is sent (`patch_in_flight`), and only where the
   read brings back what the disc holds there. A separate LoadBinary after the
   read is refused by the loader's door while that read waits.
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
| `swap-disc <image>` | change the disc a running `u-exec <image>` session serves (§12) |

Global options: `-H/--host`, `-v`/`-vv`, `-p/--port`, `-i/--infinite`,
`-a/--address`, `--loader-dir`, `--game-db`, `--memory-db`, `--patch-dir`,
`--loader-base`, `--no-relocate`, `--patch ADDR=VALUE`, `--ppf FILE`,
`--no-ppf`, `--no-gaps-guard`, `--no-marks`, `--no-vm2`, `--no-wince`,
`--vga auto|always|never`, `--no-cdda`, `--cdda-tone`, `--probe ADDR=ID[:PEEK]`
(a stub that logs when ADDR executes), `--descramble auto|always|never`,
`--boot-ipbin`, `--diag`, `--diag-interval`, `--keepalive SECONDS`.
`src/main.rs` (`Args`) is the
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
| `DCLOAD_VM2_PACE_MS`, `DCLOAD_VM2_WARMUP`, `DCLOAD_VM2_SETTLE_ROUNDS` | VM2 scan pacing, warm-up and settling rounds (§11) |
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

**flycast harness** (`scripts/flycast-harness.py`, Windows Python, stdlib
only): boots flycast on a static-IP dcload CDI and runs `u-exec` on an image.
Batch mode (`<images>`, `--dir`, `--list scripts/flycast-games.txt`) watches each
title for `--duration` s after EXEC, presses `--input` keys (`TIME:KEY[*N][:HOLD]`, milliseconds), and writes a
verdict (`RUNNING`, `FROZEN`, `BLACK`, `LOADER_HIT`, `CRASH`, `BIOS_MENU`, …),
screenshots and logs to `harness-runs/`. Interactive mode, for driving a title
to gameplay step by step: `start <image>`, `screen [png]`, `peek <addr> [len]`,
`press <key>...`, `status`, `check` (CPU state, PC named in the loader, loader
`.text` vs its relocated ELF), `stop`. The CDI and the `loaders-flycast/` set
come from `wsl -d Debian -- bash scripts/flycast-build-loader.sh` (a static
192.168.1.130, since DHCP never completes through flycast's bridge; built in a
copy of the loader tree; `dcload-resident-net.elf` does not fit with a static
IP and is left out). The harness copies `game-memory.tsv` per run (`--learn`
writes the real one), and passes `--no-ra --no-vm2 --keepalive 0` (keepalive
ended a live session at a title screen). **Any GDB connection makes flycast
halt for good at the guest's next illegal instruction** (`attached` is never
cleared), and the harness connects once to resume a GDB-server build, so a
title that runs `0x0000` (a loader overwritten) freezes rather than taking an
exception: `check` reports that state.

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
  the syscall vectors the loader holds. Windows CE does this, and so does
  NBA 2K2's Visual Concepts CD layer (`VCCD`): its `MAIN*.BIN` carry 13
  literals and no `0x8c0000bc` at all. A Ginsu boot's programs are patched
  in the sectors served, every program Ginsu may run; unpatched, MAIN.BIN
  rendered its frames and never asked the host for a sector (flycast,
  2026-10-17). The boot binaries of the other Katana titles measured carry
  none.
- **A DMA stream moved by the G1 DMA-end interrupt** (`gd_dma_end_slot`).
  The loader never raises that interrupt. NBA 2K2's VCCD reads its
  DMAREAD_STREAM one sector a piece and waits for it: its handler (after an
  ISTNRM read) takes its continuation from a word of its own, clears it and
  calls `G1DmaEnd(word, 0)`. Found by content (the clear, `mov #5,r7`, the
  driver literal), in the boot binary or every program of a Ginsu boot; the
  word's P1 address and the argument go into the resident loader's
  `g_gd_dmaend_slot` / `g_gd_dmaend_param` before `EXEC` (`gd_dmaend_symbols`),
  and the loader does the handler's work after each piece (loader AGENTS.md
  4.5). Only one word can be told: programs that disagree get a warning.
  Not in the network image. NBA 2K2: `0x8c7c6894`, argument 0, the same in
  its four `MAIN*.BIN`.
- **Windows CE** (`boot::WinCe`, `wince.rs`). Recognised by name
  (`0WINCEOS.BIN`, whose first 2048-byte sector is dropped, as DreamShell's
  isoldr does) or by `"ECEC"` at +64; entered through the disc's second
  bootstrap. **The loader goes at the bottom of CE's page pool**: `ulRAMFree`
  from CE's `ROMHDR` rounded up to 64 KB (Sega Rally 2 PAL: `0x8c14d000` →
  `0x8c150000`), and `ulRAMFree` is raised above it and the RetroAchievements
  room (`wince::take`, `Place::Bottom`). CE hands pages out from the top, so the
  top must stay as an unmodified CE has it: until 2026-10-09 the loader took
  `ulRAMEnd - LOADER_SPAN` and lowered `ulRAMEnd`, which moved everything CE
  loads down by as much -- Sega Rally 2's `RALLY2.EXE` at RAM `0xA85000`, not
  `0xA99000`, and its RetroAchievements set (game 8443), which finds the program
  by a signature at `base + 0x2e2da4` on the seven pages `0xA95000..0xA9B000`,
  matched nothing (its rich presence said "RALLY2.EXE=0xA85000 -- Add to
  RAScript!!"). `--wince-loader-top` restores the old placement. `pio_patches` sends
  CE's GD driver down its PIO path, because its DMA path waits for a G1
  interrupt this transport never raises. Two shapes are known: Sega Rally 2's
  inline choice (`DMA_CHOICE`, a `bf` made a `bra`) and Railroad Tycoon II's
  DMA function, whose 32-byte alignment test is made to fail
  (`DMA_ALIGN_TEST`, a `bt` made a `nop`). Reads into the loader's `_gd_stage*`
  buffers are not collisions (`loader_stage`). On a VGA box (`--vga`, `auto`
  by default), a root `.EXE` that asks DirectDraw for PAL's 25 Hz mode with
  flag `0x4000` (Railroad Tycoon II PAL's `RT2DC.EXE`) is served asking for
  60 Hz, flags 0, the only 640x480 mode DDHAL lists for VGA
  (`vga_display_mode_patches`, `DiscPatch`es); unpatched, its `SetDisplayMode`
  fails and the game stays on a black screen, with or without dcload.
  `--no-wince` uploads it whole.
  Open questions: the loader's `docs/wince-investigation.md`.
- **HLib heap** (`dispatch/heap.rs`, on by default, `--no-heap-guard`). A
  Katana allocator that owns all the RAM a title leaves free, recognised by its
  literal pool: start, start + 0x20 (first block), end, the first block's size
  (end − (start + 0x20)), and the tags `"fREe"`, `"USE "`, `"HLib"` within
  0x40 bytes; exactly one pool or nothing. The loader goes at the first 64 KB
  boundary at or above the heap's start (`loader_base`, in `wanted_loader_base`,
  before presets and the learned map, unless the recorded stack sits there),
  and the start, first block and size are moved above it (`patches`); a loader
  pinned at the heap's top lowers the end and size instead, and one in the
  middle is only warned about. The heap's own bounds are not reported by the
  constant scan.
  Shenmue II (PAL 1.001): pool at `0x8c051968`, heap `0x8c360000..0x8cebffe0`,
  loader `0x8c360000`, start `0x8c370000` -- measured to run through disc 4.
  Its fixed regions rule out the alternatives: above `0x8cec0000` cutscenes and
  stack, and a disc-4 loading buffer ending at `0x8cf046c0` runs over the
  heap's top.
- **Heap ends** (`dispatch/heap.rs`, same `--no-heap-guard`). Katana's
  `sbInitSystem` hands `syMallocInit` everything from the program's `_end` to an
  end literal, and every title compiles it in its own order: four byte
  patterns were written for three titles and the fourth matched none. So the
  rule is read off what the code DOES with the end, not its bytes
  (`Code::sizes`): **a heap's size is its end minus its start**, a `sub` whose
  minuend comes from a literal naming high RAM (P0/P1/P2, up to `0x0d000000`)
  and whose subtrahend is a known RAM address at or above the program (`_end`
  rounded). A small evaluator reads each program straight through: literals,
  immediates, words read through a known pointer (`&_end`), the ALU operations
  sbInitSystem uses, and which literal a value still names (the same RAM give
  or take `SAME_RAM`, 0x40: `& ~31`, `+ 32`, the segment); a call clobbers
  r0..r7, conditional branches are read through. rts/bra/jmp end what it
  knows, except that what follows one starts from what every forward
  `bt`/`bf`/`bra` to it knew (registers they disagree on unknown), and `nop`s
  right after one are padding (2026-10-15: NBA 2K2's MAIN.BIN sizes its heap
  past two if/elses). A literal is taken only if **every** instruction loading
  it sizes a heap or is in a function that does (no rts/bra/jmp between): a
  word also used as a buffer address would move the buffer onto the loader.
  **The end may also be a word of the program read through a pointer
  literal** (NBA 2K2's MAIN.BIN keeps its heap's bounds in two words of
  .data, `0x8c708b44`/`0x8c708b48`, and sizes it `*end - *start`): that word
  is the one lowered, and the rule above applies to the pointer's loads. At least `MIN_LEFT`
  (1 MB) of heap; nothing for a Windows CE disc (`0WINCEOS.BIN`) or a KOS
  program. Not seen: an end passed as an end (`init(start, end)`), an end that
  is not a literal, a constant-size heap (HLib, above), a stack moved to the
  top of RAM (a rule for that found "stacks" in Crazy Taxi, Sonic Adventure and
  data files read as code: dropped). Checked on ten images (2026-10-11):
  Crazy Taxi, Sonic Adventure, Sonic Adventure 2, Shenmue II, Sega Rally 2
  PAL and US give nothing; the ones below are found.

  Every `.BIN` of the boot area's root is searched (its first 64 KB, the whole
  of the program IP.BIN boots, plus the sector holding `_end`), read as run
  from 0x8c010000, because the program that sets the heap need not be the one
  uploaded: Jet Set Radio's `1ST_READ.BIN` reads `JET_PAL.BIN` into a buffer
  and runs it. A base the rules choose inside such a heap (and not given with
  `--loader-base`, nor chosen by the HLib rule) moves to the heap's top, the
  highest 64 KB boundary leaving the loader's span inside it, provided no
  program on the disc loads a constant naming that span -- else one 64 KB lower,
  down to `TOP_SLACK` (256 KB) under the top, the heap above given up; every
  end literal of a heap the loader is then in is lowered to the loader's base,
  in the uploaded program (guarded like the HLib words) and in the sectors
  served (`DiscPatch`, applied in `SectorServer::serve` wherever the read
  lands, only over the disc's own word). Not for an HLib title.

  **PSO Ver.2's decoded program** (`dispatch::PsoLate`, 2026-10-13) carries
  the same expansion probe as its bootstrap (`0x8c37a37e`, twelve switch-off
  calls); left alone it switched the adapter off as the program started (the
  last disc read answered, then the loader silent, the title back in the BIOS
  menu). The loader writes the decoded program's words itself, ten at most
  (`VNIC_LATE_MAX`; eight until 2026-10-14), so the twelve `nop`s do not fit:
  `gaps_power_down_redirect` points the one literal both switch-off functions
  jump through (their G2 write, `0x8c37a3e0`) at an `rts ; mov #0,r0` of the
  program's own (`0x8c010510`), only if nothing else loads that literal.
  **Its serial-number screen** (before going online) checks the number with
  PRIME.PRS, a module the program loads (`"prime.prs"`, three validators of
  Sega's prime-product scheme, held in one word); Sega's numbers are no longer
  issued. `pso_serial_check_patches` turns each call into the module
  (`mov.l @r0,r0 ; mov.l @(4|8,r0),r0 ; jsr @r0`) into `mov #1,r0`, so
  whatever is typed is accepted: two pairs, and **no number is carried by the
  host** (user's decision, 2026-10-14). The number itself is kept in flash
  (partition 2, logical block 7, a 32-byte record tagged `'S1'`): the host
  tells the loader to let writes of that block, and of no other, reach the
  console's flash (`g_vnic_flash_keep` = `PSO_V2_SERIAL_BLOCK`, loader
  AGENTS.md §4.21; `--no-flash-keep` to write nothing), so what was typed is
  not asked again. With the driver's six, the probe's and the heap's end: ten.

  **A Ginsu boot** (`dispatch::ginsu`, 2026-10-12): the `1ST_READ.BIN` is
  Sega's boot loader, and the title is the program `GINSU.INI`'s `[GINSU]
  FirstApp` section names in `Ginsu.Command`, copied to 0x8c010000 and run.
  **Or the configuration is built into the boot loader** (2026-10-15, NBA 2K2
  PAL): no GINSU.INI, a `SNIG` block (`0x8c06fb00`) naming `\manifest.bin`
  and `\ginxfer.bin`, neither on the disc (Ginsu falls back to JOHNNIE.BIN,
  8436 bytes, a name in its code), and the program chosen in code by the
  console's language among MAIN.BIN, MAINF.BIN, MAING.BIN and MAINS.BIN. The
  programs are then the root `.BIN` files the boot loader names (64 KB or
  more, not itself, not the transfer program) that set up a heap, the first
  named reported and the others its `variants`, each patched alike; a missing
  transfer program is taken to fit the 64 KB under `GINSU_TOP`. Measured on
  the console (2026-10-14), before this: MAIN.BIN read to
  `0x8c8d0000..0x8cfc8dc4`, then silence with the loader at `0x8cfd0000`
  (JOHNNIE.BIN's read refused) and a reset at Start with it at `0x8cfe0000`
  (the file system's work area).
  That program is read whole before the loader is placed and examined as the
  boot binary is: its heap (searched whole, not its first 64 KB), its network
  driver (the network image, `vnic`), its expansion-port probe (the GAPS guard,
  or for a network title only its switch-off). Its words change in the sectors
  served (`GinsuApp::disc_patches`), never in RAM. Unreal Tournament NTSC:
  `UTDC.BIN`, 2.6 MB, the PAL `1ST_READ.BIN`'s ETD (`ETD_Init` at
  `0x8c1c3ff4`) and the same twelve switch-off calls; served as the boot
  binary alone, its driver reset the adapter after the last read of
  `UTDC.BIN` (the loader silent, no GAPS word of the program patched).
  **Where Ginsu reads decides the base** (`GinsuApp::loader_base`): it reads
  GINXFER.BIN to the 64 KB boundary under `GINSU_TOP` (0x8cfe0000, its file
  system's work area; its directory at 0x8cff0000) minus its size, and the
  program to the 64 KB boundary under that minus the program's; all of it is
  Ginsu's until the program runs. The loader goes right under the program,
  before any other rule but `--loader-base`, and every heap it is in ends
  there however low (`KatanaHeap::patch_deep`, past `TOP_SLACK`). UT NTSC:
  `UTDC.BIN` at `0x8cd50000..0x8cfcd000`, GINXFER at `0x8cfd0000`, loader at
  `0x8cd40000`, UT's heap `0x8c312ca0..0x8cfdd000` cut to `..0x8cd40000`.
  Measured on the console (2026-10-12): at `0x8cfc0000` (the heap's top) the
  loader refused the program's read and Ginsu returned to the BIOS menu.
  **The loader goes at the bottom of the program's heap first**
  (`GinsuApp::heap_bottom`, same day): the 64 KB boundary over its start, the
  start raised above the loader (`heap_start_raise`, below), Ginsu's own heap
  (to the top of RAM) ending under it like any heap. UT NTSC: loader at
  `0x8c320000`, heap `0x8c330000..0x8cfdd000`, 117 KB given up instead of
  2.6 MB. Only when that is refused does the loader go under the program, as
  above. Run on the console (2026-10-12): Ginsu and UT boot, and UT froze
  loading its first online level exactly as with the loader under the
  program (UT allocates the level from its heap's top, wherever that is):
  the heap was not the cause.
  **Raising a start** (`Code::raise_starts`): UT computes its heap's start
  from `_end`, read through a literal `&_end` (`mov.l @Rm,Rn`) in its three
  set-ups, and its crt0 clears the BSS up to the same word, so the word itself
  cannot move. Each read becomes `mov Rm,Rn` and the literal holds the new
  start (less what the code adds), the end, from the top bits, unchanged.
  Refused unless every load of the literal is such a read, Rm is dead
  after it (written before any read, no branch or return between; a call
  kills r0..r7) and named by nothing between the pointer's load and the read
  (NBA 2K2 reads the start through the same register, adjusts it and writes
  it back first). **Then the start's word itself is raised**
  (`Code::raise_start_words`), only when crt0 does not clear the BSS through
  it: the old start must also be a literal the program loads (the BSS bound)
  and no load of a pointer to the word may sit in a function that loads that
  literal. NBA 2K2: MAIN.BIN's `0x8c708b44` `0x0c7f5040` -> `0x0c810000` in
  all four programs, loader at `0x8c800000` (above every program's BSS, under
  `0x8c8d0000` where Ginsu reads them; the boot loader never wrote
  `0x8c340000..0x8c8d0000`), the boot loader's heap ending there. 44 KB of
  MAIN.BIN's 8.2 MB heap given up. Not yet measured on the console.

  | Title (PAL) | Heap | End literal(s) | Loader |
  | --- | --- | --- | --- |
  | Jet Set Radio | `0x8c0a9120..` (1ST_READ), `0x8c35d740..0x8c800000` (JET_PAL/JET) | `0x8c013e60`, `0x8c013fe8` | `0x8c7f0000`, **measured** (2026-10-10): levels load and play; at `0x8c650000`/`0x8c580000` (the learned map's holes, inside the heap) it was overwritten while a level loaded |
  | Skies of Arcadia | `0x8c5534c0..0x8d000000` | `0x8c015eb4` (loaded twice in sbInitSystem) | `0x8cfe0000` (`0x8cff0000` is its Maple DMA list); at `0x8cfd0000` unpatched the console reset at EXEC. Not measured |
  | Tony Hawk's Pro Skater 2 | `0x8c349580..0x8d000000` | `0x8c062f0c` (sbInitSystem 0x52de0 into 1ST_READ) | `0x8cfd0000` (it names `0x8cfe0000`, `0x8cff0000`); at `0x8ce00000` reset before the menu after a 1.5 MB read to the heap's top. Not measured |
  | Unreal Tournament | `0x8c313740..0x8cfdd000` | `0x8c05b1f8` (sbInitSystem, and a function sizing it again from the same pool), `0x8c05b2a0` (a second set-up) | `0x8cfc0000`; at `0x8c940000` (middle of unread RAM) silent after seven sector reads (2026-10-11). Its stack is moved to `0x8d000000`, above the heap. Not measured |
  | Snow Surfers | `0x8c1eaec0..0x8d000000` | `0x8c081c70`, `0x8c081d7c` (two sbInitSystems) | moves off `0x8ce00000`, where every CD-DA session ran inside the heap, to the top under what it names. Not measured |

- **KOS** (`is_kos_binary`). The loader goes to the top of RAM, 0x8cff0000
  (`wanted_loader_base_by_rules`): a KOS program fills RAM from its image up
  (code, BSS its start-up zeroes, heap), and Super Mario 64's `SM64.BIN` ends
  its BSS at 0x8ce6dfe0 (`kos_program_end`, read from `arch_main`'s BSS
  memset; `disc_kos_program_ends`), over a loader at 0x8ce00000. The loader is told via `g_gd_kos`; KOS's top of
  RAM is lowered under the loader (`kos_mem_top_patches`: startup's stack
  pair, and, for a KOS built without the 32 MB toolchain patch, whose
  `_arch_mem_top` is the constant 0x8d000000, the loaded literals 0x8cff0000 /
  0x8cfeffff of the kernel thread's stack and `mm_sbrk`'s limit — lowering the
  stack alone is "Thread stack underrun" at the first switch). The same words
  change in the sectors served of every other KOS program of the disc's root
  (`disc_kos_programs`): Super Mario 64's `1ST_READ.BIN` reads `SM64.BIN`
  and `arch_exec`s it at 0x8c010000. The dcload magic at
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
- **Disc patches (`.dcp`, `dcp.rs` + `xdelta.rs`).** A row naming a `.dcp` (the
  Universal Dreamcast Patcher's zip of `<path>.xdelta` deltas and whole files)
  patches the disc's FILES, keyed on `disc_md5`; `--ppf x.dcp` names one by
  hand. The image is opened through `dcp::open_served` (the session's and a
  `swap-disc`'s, and `identify`), which lays the patched files over it: a file
  that still fits its sectors stays there with a new size in its record, one
  that grows or is new goes into a hole of the data track (below the highest
  sector used), a new record is inserted in ISO 9660 order and a directory
  that would need to move refuses the patch. **All or nothing**: a file the
  disc lacks, or an xdelta window whose Adler-32 fails (another dump), serves
  the image as it lies. xdelta3's LZMA sections are xz streams flushed without
  an end (`unlzma`): decoded with `lzma-rs` once the end byte is added. The
  boot binary is read through the overlay, so it is uploaded patched; the
  RetroAchievements hash is taken from the image as it lies. The `.dcp` files
  are gitignored (others' work, tens of MB); the row and an `.nfo` crediting
  the author are committed. Skies of Arcadia PAL (Riggles' 60 Hz desync fix
  v2): disc 1 495 files patched and `SOUND/M02S.P16` (16 MB) added in the hole
  at LBA 45261, 3.6 s at open; disc 2 388 patched, 2 moved. Every file read
  back through the overlay matched the patcher's output (2026-10-11); not yet
  run on the console. A swap to a patched disc builds its overlay inside the
  syscall loop (~3.5 s, on top of opening the image).

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
  on) is reported once and not recorded. In the same request it reads
  `g_gd_self_refused`/`_lo`/`_hi` (disc reads the loader refused because they
  would land on it, which never reach this host) and records the range as
  the title's memory, so the next run places the loader elsewhere.
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
  DEBUG, not reported as unexpected. A read-back ends only on a DoneBinary
  naming its own range (0/0 from an older loader): the one a previous read
  left in the socket used to end the next read early, costing a repair pass
  and a 500 ms timeout per patched word.
- INFO is for what a user acts on (connection, placement, title patches,
  problems); each step's detail (verified pokes, read timings, memory map,
  indexing) is at DEBUG, per-read bytes at TRACE.
- `.vscode/`, `.continue/`, `.zed/` hold personal launch configurations: do not
  commit them as is.
- **Terminal** (`ui.rs` owns it): one `MultiProgress`; logs print inside
  `suspend`, so bars must come from `ui::bytes_bar`. Nothing is drawn when
  stderr is not a terminal. The in-game loading bar (`LoadMonitor`) groups
  disc reads into bursts and updates only after the ReturnValue.
- **Counter panel** (`--diag`, `diag.rs`): `d` toggles sampling, `w` writes a
  snapshot to `dcload-diag.txt`, `+`/`-` change the interval, `r` sends `DRST`
  (retried every 300 ms for 5 s) and the loader starts its max/min counters
  over (`g_gd_sp_min` excepted: the stack watch's guard). The loader image
  is verified against the uploaded ELF before any counter is decoded. The
  loader answers only inside `bb->loop()`, so a title that stopped reading its
  disc may leave the panel unanswered; the header shows the measured
  interval. The panel and stack watch overlap, so only one is active at a time.
- **Keepalive** (`--keepalive`, default 10 s, 0 = off; `keepalive.rs`): the
  syscall loop ends the session (exit code 1) when no datagram at all has
  arrived for that long (`ExternalDcIo::last_input`, set in `handle_data`
  before the sinks). Past a third of the limit without a word it asks for
  itself (4-byte `SBIQ` of `g_irq_hooked` every 0.5 s), answered within 50 ms
  by the hook's idle listen. It is **armed only where silence means
  something**: the panel, the stack watch or the witness words up, not a KOS title, a loader with the hook's idle listen
  (`gd_idle_listen` in its ELF; `main.rs` `keepalive_config`), and
  `g_irq_hooked` read non-zero on the console (a 4-byte `SBIQ` every 10 s,
  60 s after six unanswered, until it is; read off the panel's samples while
  it has the wire). The panel does not suspend it: when it samples, its last
  sample is appended to `dcload-diag.txt` as the session ends. **Armed, it
  asks again every 2 s while the console talks, and a 0 (its own answer or
  the panel's) disarms it** until the hook is back: a title can replace the
  entry the loader hooked (Jet Set Radio, 2026-10-09, loader AGENTS.md 4.15),
  and a count armed once ended a live session in its SEGA logo.

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
- **Everything the program says goes through the `log` macros** (`error!` …
  `trace!`), never `println!`/`eprintln!`: the logger is the one writer that
  suspends the progress bars (`ui::BarAwareLogger`) and that `-v`/`RUST_LOG`
  filter. Command reports (`identify`, `ra-count`, `relocate`, `swap-disc`) are
  `info!`. Exceptions: `build.rs`'s `cargo:` directives, and tests, where no
  logger is installed (a skip notice logged there would be lost).

## 12. Disc swap

`swap-disc <image>` (`control.rs`) sends `SWAP <path>` to the session on
`127.0.0.1:--control-port` (`DCLOAD_CONTROL_PORT`, default 53536, 0 = off; the
session listens only when it serves a disc image). The session thread
(`dispatch/swap.rs`) opens the image first (a `DiscFormat` is not `Send`), asks
the loader with `DISC` (generation in `address`; reply `size` 0 accepted, 1
busy: asked again every 250 ms, `0xffffffff` refused; 10 s limit), and installs
the new image, TOC and audio state only on 0. The loader then plays the lid
(loader AGENTS.md 4.17). The memory map learned for the title keeps recording
under the first disc's identity. Needs a loader with `DISC`; an older one never
answers. A read at LBA `0x3ffffffe` (BootROM service 2, loader
AGENTS.md 4.17) is served from `DiscFormat::boot_sector()` and tagged with the
number the loader sent.

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
- **The bus settles before `EXEC`** (`settle`, 2026-10-26): after a scan that
  told a card a game (a VMUPro reloads) or reset a slot, every controller and
  reported slot is read again, paced, until two rounds agree and every slot
  answers, with one more reset half way; at most `SETTLE_ROUNDS` (100,
  `DCLOAD_VM2_SETTLE_ROUNDS`), then a warning naming the silent slot. A KOS
  title's `maple_wait_scan()` waits with no limit for every port: started on
  a card still reloading, Super Mario 64 stayed on a black screen until the
  cards were unplugged.
- **Open (2026-09-20)**: on the test console a VMUPro in controller A's slot 1
  is still not found — the first transaction to it returns 32 bytes of
  non-frame data and port A's slots then answer empty, while port B works.
  The next control is physical: move the VMUPro to port B and see whether the
  fault follows the device.

## 13. RetroAchievements

`src/ra/`, `build.rs`, `vendor/rcheevos` (MIT, plain copy of upstream
`683197d`, see `REVISION`), `src/ra/shim.c`. The loader samples RAM
(loader AGENTS.md §4.20); this host judges with rcheevos and talks to
retroachievements.org. **On by default** for a `u-exec` of a disc image once
`ra-login <user>` has been run once (password asked, only the token kept, in
`%APPDATA%` / `~/.config/dcload-ip-rs/`); without a login, for a KOS title, a
bare program or a loader without the sampler it stays off with one `info` line
(`start_ra`); `--no-ra` turns it off;
`ra-count <image>` for the size of a set.

- **One thread, one owner.** Everything that touches rcheevos runs on the
  `retroachievements` thread (`session.rs`). The packet sink (`RaSink`) only
  forwards `RAFR` frames and `RACT` replies through a channel, so the syscall
  loop never waits on the network or the achievement logic. HTTP is one short
  thread per request (`env.rs`), answered back through the same channel.
- **`shim.c` keeps rc_client's structs on the C side**; Rust sees integers,
  strings and function pointers (`ffi.rs`). Any rcheevos upgrade is a
  recompile of the shim plus its callers' check.
- **Pointers the loader follows itself** (`chains.rs`, loader AGENTS.md §4.20). The
  set is walked once with rcheevos' **public structures only** (`ra_probe_walk` in
  `shim.c`: `rc_runtime_get_achievement` / `_lboard`, a trigger's condition sets,
  a condition's operands, `rc_operand_is_memref`; the rich presence's display
  conditions and named values) -- never `rc_internal.h`. Position decides what is
  indirect: after an `AddAddress` a memref operand's `address` is an OFFSET from
  the accumulated pointer, which is documented rcheevos behaviour and is covered by
  tests that fail if an update changes it (`ra::tests::the_walk_*`). Each indirect
  read becomes a chain word; a pointer that is a 24-bit read at an address that is
  0 or 1 mod 4 and an offset within ±4 MB qualifies, anything else is left to
  discovery. The table is built from this structure first, so the pass on zeros
  finds only what it did not name (3 words in SA2: its rich presence parts).
  `Env::read` resolves a read through the table's words, then through the chains'
  addresses worked out from the frame's values; an address **past RAM reads
  nothing** and is no miss (it used to skip every frame for good).
- **Disc swaps** (`swap-disc`, §12). After the loader accepts and the new image is
  served, `dispatch/syscalls.rs` calls `ra::session::disc_changed(spec)`, which
  reaches the RA thread through a global mailbox (so one RA session at a time).
  The thread opens the new image, hashes it and calls `rc_client_begin_change_media`:
  **rc_client keeps the loaded game and only notes the new hash -- it never loads
  another game.** A multi-disc game's discs are one RetroAchievements game (Resident
  Evil 2: both discs are game 3859, one set of 179 achievements, 122 words, no
  pointers; measured 2026-10-07), so the set, the table and the generation stay and
  nothing is sent to the console. If the lookup of the new hash (`r=gameid`,
  reported by the shim as `Event::HashGame`) names ANOTHER game, `reload()` unloads,
  loads that game's set and builds a new table; frames are ignored meanwhile. A disc
  RetroAchievements does not know leaves the set as it was (hardcore, if asked for,
  is turned off by rc_client). The wiring line in the syscall loop is not covered by
  the tests, which call `disc_changed` themselves (`ra::e2e`, both paths, proven
  by mutation).
- **Merging**: the ranges merge the finest gap that fits the range budget
  (`GAPS`, `MAX_RANGES`), so a set with few ranges carries no filler words. **The
  budget is the loader's 384 ranges**; merging over gaps adds words the set does not
  read, so too small a budget makes a table too many words (Sega Rally 2,
  2026-10-08: 967 words in 155 ranges under the old 160, refused; the error now
  gives the distinct words read beside the table's). **A table goes in parts**
  (`Table::parts`, loader AGENTS.md 4.20), each at most 1460 bytes of command data
  (`MAX_PAYLOAD`), because the loader takes no IP fragment: SA2's first table, one
  1476-byte `RACT`, was fragmented by Windows and never seen (`g_ra_gen` 0, the
  "not answered 20 times" warning, 2026-10-07). Only the last part is answered; a
  lost part leaves the table unanswered and `resend_table()` sends all of it again.
  The words a table may have are the loader's room from that answer (744 under a
  Katana title, 1024 under Windows CE with the lent block); `MAX_WORDS` (1024) only
  caps it. A first table larger than the room that applies, accepted or refused,
  goes to `step_down`. Test helper: `table::Assembler` (the loader's rules, for the
  fake consoles).
- **A pointer that holds no address** (2026-10-07, SA2 on the console: the table
  grew every few frames and nothing was ever awarded). The loader reads a chain's
  word at its address rounded down to 4 (`ra.c`, `& 0x00fffffc`); `Env::word_at`
  matches it the same way, so the bytes of that word are right. But a pointer
  whose value is not a multiple of 4 -- a pointer field holding something else,
  between levels -- makes rcheevos read across two words, and a pointer it reads
  there is not the one the loader followed: its children land anywhere, differently
  each frame. Growing the table after them never ends, and a frame that grows the
  table is not judged. So a frame's misses grow the table only when no chain
  address is misaligned (`Env::skewed`). When one is and the walk left nothing to
  discovery (`unsupported` 0: every read an aligned pointer can lead to is a
  chain), the frame is judged anyway; otherwise it is skipped without growing.
  Checked against SA2's real set with a simulated console (consistent memory,
  random pointers): aligned pointers miss nothing in 3000 frames; with misaligned
  ones every miss frame is skewed. `ra::e2e::a_pointer_that_holds_no_address_*`
  fails without the rule (15 tables, nothing awarded).
- **What the log says about the user's state.** At load: how many achievements
  are already earned in this mode (rc_client never watches those again, so they
  cannot unlock a second time), each one at `debug`, the watched ones at
  `trace`. The rich presence is evaluated locally every frame and logged at
  `debug` when it changes; **the site only gets it at rc_client's ping, every
  2 minutes** (`rc_client.c`, `120 * 1000`), as in every emulator. A faster ping
  is not ours to choose: it is the server's load.
- **A table is acknowledged by its own frames only** (2026-10-08, Sega Rally 2
  on the console: host at generation 2, loader still at 1, `last 10 s: 0 frames`
  while `g_ra_frames` ran at 60 a second). `RACT` is one datagram and can be
  lost. Two faults kept it lost: `on_frame` took any `RAFR` as proof the loader
  held the table, and the old table's frames kept coming; and `resend_table()`
  ran only when nothing arrived for 250 ms, which ten `RAFR` a second never
  allow. Now only a frame of the current generation acknowledges, and the
  resend is looked at on every turn (its own 1 s timer).
  `a_lost_table_is_sent_again_while_the_old_one_is_sampled` fails with either
  fault (both checked).
- **A set too big for the loader** (`Keep`, `trim_sets`, `step_down`,
  2026-10-08). When the table does not fit (`TableError::TooBig`, at the first
  table or later as pointers move, or the `RACT` reply's room is smaller), the
  game is loaded again with the game-sets answer trimmed before rcheevos sees it,
  one step at a time (each step reloads rc_client: hit counts restart):
  1. **`SlowRichPresence`**: the PROBE's copy has no rich presence, so neither
     has the table; the REAL client keeps it, and whatever it reads that the
     table lacks comes from the **slow path** (`slow.rs`): `SBIQ` reads of
     those words, pieces of neighbouring words (gap ≤ 256 B, ≤ 5760 B), 8 in
     flight, a cycle at most every 5 s, through P1 under Katana and P2 under
     Windows CE (its MMU: a P0 address would be translated in the loader; its
     virtually indexed cache: P2 reads RAM and leaves no stale line, at the
     price of missing what sits in a dirty line). `Env::read`, in the real
     client with `slow_mode`, serves the last values read and notes the words
     it has not got (`slow_new`) -- never a miss, never a reason to grow. The
     rich presence may lag a cycle; the site gets it every 2 minutes anyway.
     `RaSink` claims `SBIN` inside a read in flight and the `DBIN` naming exactly
     one (a disc read's DoneBinary names a title buffer, never this range and
     size, and disc reads no longer ask for one).
  2. **`NoLeaderboards`**: the leaderboards leave both copies (a leaderboard
     left in the client with its words out of the table would submit scores
     read on zeros); the rich presence stays slow. Achievements are never
     dropped.
  Sega Rally 2: 1775 words in 337 ranges in all (seven copies of every
  condition, one per place the game may keep its data); the rich presence alone
  ~900 words, ~300 pieces; without it 427 at load. Tests:
  `trimming_takes_the_rich_presence_out_of_the_table_then_the_leaderboards_out_of_the_game`,
  `the_slow_path_serves_the_real_client_and_not_the_probe`, `slow::tests`, and
  `a_set_too_big_for_the_loader_reads_its_rich_presence_slowly` (a fake console
  answers `SBIQ`; fails without the step and without the reads, both checked).
  **Not yet seen on a console**: whether the loader's listen windows keep up
  (`debug!` "rich presence read slowly: … the cycle took … ms").
- **Windows CE lends the sampler 16 KB** (`wince::RA_ROOM`, 8 KB until 2026-10-09): with RetroAchievements
  on and a loader that has `g_ra_ce_room`, the block right above the loader is
  taken out of CE's RAM with it (under it with `--wince-loader-top`), and the
  block's P1 address and size are written to
  `g_ra_ce_room` / `g_ra_ce_room_words` before EXEC (`ra_ce_room_symbols`). The
  loader's own dead stack holds no table any more; the block holds its largest
  table, 1024 words (8 KB held 992) (loader AGENTS.md 4.20). Not yet seen on the console.
- **Discord** (`--discord <application id>`, `src/discord.rs`): the game's
  title, badge (a URL: Discord fetches it), rich presence, achievements earned
  and a button to its page go to the user's profile, from the Load event, each
  rich presence change and each unlock. The application id is the user's own,
  from discord.com/developers (its name follows "Playing"); none is built in.
  Discord's IPC is written by hand (frames: op and length u32 LE, then JSON)
  rather than through the usual crate (serde, uuid 0.8, thiserror). It runs on
  its own thread: Discord may be absent (looked for every 30 s) or quit, and a
  write to its pipe must not hold the RA thread. Discord takes about one update
  per 15 s, so updates are coalesced (the last wins). The profile is cleared
  when the session ends; a killed host closes the pipe, which clears it too.
  Test: `discord::tests` (a fake Discord over a socket pair, Unix only;
  checked by mutation). **Not yet seen against a real Discord.**
- **Why an achievement does not fire.** Every 10 s, at `debug`: frames that
  arrived, judged, skipped while the table grew, skipped on a pointer that is not
  an address (an achievement true only on a skipped frame cannot fire).
- **Each frame runs twice**: the *probe* (a private `rc_runtime` holding the
  whole set, `ra_probe_*`) first; whatever it reads that the table lacks
  grows the table (new generation, new `RACT`) and the frame is NOT given to
  the real client, because a frame judged on zeros could award an achievement
  for good. Pointer chains (`AddAddress`) are followed this way: the target is
  unknown until the pointer's value is. The probe puts back what fires, or it
  would stop following that chain.
- **`grow(first)`**: the first table comes from one probe pass over zeros (which
  also reads where a NULL pointer would aim, address 0x10: one wasted word);
  later growth uses the misses of the frame that failed, never a re-probe.
- **Hash**: `rc_hash_generate` with a custom cd reader over `DiscFormat`
  (`cb_sector`, `cb_track_first`): filesystem numbering is
  `fs_lba(...)`-relative, track 3 is `boot_sector()` on a GD-ROM image and the
  first data track otherwise. **Measured only against a synthetic ISO** (the
  e2e test); check a real GDI against retroachievements.org before trusting it.
- **Lost frames**: `frames::Mirror` numbers datagrams; a gap makes it distrust
  deltas until the next keyframe, and nothing is judged meanwhile. A frame is
  one or more records of at most 128 words (`WIN`), complete at the one flagged
  `last`: a keyframe of the whole table (512 words) is cut across datagrams, and
  is a base only once every window of it has arrived. A frame the LOADER drops
  (its batch full, the network busy) is not a gap in the sequence: the loader
  makes the next frame a keyframe instead, so no delta ever follows a hole.
- **Limits**: 512 words (ranges' and chains') in 160 ranges and 64 chains
  (`table.rs`, mirroring `RA_WORDS` / `RA_RANGES` / `RA_CHAINS`). Measured with
  `ra-count` on 2026-10-07: Sonic Adventure 2 270 words (213 from RAM in 155
  ranges + 57 chains), Shenmue II 157 (155 in 71 ranges + 2 chains).
- **Windows CE is served**, with less room: the loader answers each table with
  the most words it can take under Katana and under CE (`Msg::Ract.limits`), the
  session keeps the one that applies (`max_words`) and refuses a set that does
  not fit with the figures. Under CE the loader reads through P2 and overlays the
  operand cache's dirty lines (loader AGENTS.md §4.20): **never seen on a console**.
- **Softcore only in practice.** Hardcore needs RetroAchievements to have
  registered this client; `--ra-hardcore` asks anyway and warns.
- **Tests**: `ra::loader_c` compiles the loader's own `ra.c` for the PC
  (loader repo `scripts/ra-sampler-harness`, stubs for the hardware headers) and
  feeds its datagrams to `Mirror`: the one place the C encoder and the Rust
  decoder meet; skipped without gcc or `DCLOAD_LOADER_REPO`. Proven able to fail
  (a mutated bitmap in the encoder breaks it). `ra::tests` (probe against the real rcheevos), `ra::e2e` (fake
  server over TCP and fake console over UDP: login, hash, set, table, frames,
  a pointer growing the table, two awards). `DCLOAD_RA_HOST` points the client
  at another server (test hook). The e2e test needs `genisoimage` and is
  skipped without it.
- **Sizing the loader's table**: `ra-count` prints the direct words; the
  session logs `the table peaked at N of 256 words` when it ends. That figure
  decides `RA_WORDS` in the loader (128 or 256).
- **Not measured**: anything on a console or flycast, the real server, the
  Windows build (MSVC compiles `shim.c` and rcheevos through `cc`).
