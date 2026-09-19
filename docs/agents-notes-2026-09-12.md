# dcload-ip-rs AGENTS.md as of 2026-09-12 (archived)

**History, not a description of the code.** This is the agent manual as it stood before the 2026-09-13 cleanup, kept verbatim for the reasoning and measurements it records. Several statements in it were already out of date when archived (for example the CD-DA section describes the 25-fetches-a-second PCM engine, and it names counters and functions that no longer exist). The current manual is `AGENTS.md`; the loader-side history of the CD-DA work is in dcload-ip's `docs/cdda-double-buffer-investigation.md`.

---

- **A BIG SAMPLE-TO-SAMPLE STEP IS NOT EVIDENCE OF ANYTHING, AND THE WARNING
  BUILT ON ONE CRIED WOLF FOR DAYS.** `SlewWatch` counted steps over
  `LIMIT = 24000` and warned "the audio LEAVING THIS HOST is discontinuous ...
  The bytes were already wrong before they were sent." **It is arithmetically
  impossible for that threshold to mean what it claimed**: a band-limited
  44.1 kHz signal of peak amplitude A may legally step by up to 2A between
  samples, so a fully limited master — Snow Surfers peaks at 32766 — steps by
  50000+ wherever it has energy near Nyquist, which loud music has constantly.
  Worse, the test counted **runs** of consecutive big steps, and a run is
  exactly what sustained high-frequency content is, while a splice is one step
  and no run. **Falsified 2026-09-11 by its own positive control**: splicing
  three real ring seams (a jump back one whole ring revolution) into track 17
  moved the hit count from 4934 to **4933** and the runs from 442 to **441**.
  The statistic was blind to the failure it existed to find and loud on the
  content it was run over.
  **What discriminates is WHERE the hits land.** Every failure this pipeline can
  have — a dropped sector in the rip, a wrong deflate cursor, a lost sub-fetch,
  a ring seam — is aligned to a structure whose period divides a sector; music
  is aligned to nothing. `SlewWatch::verdict()` histograms hit position modulo
  588 frames and reports the largest bin in sigmas above the uniform mean, and
  only a spike (> 8σ) is a warning now. Measured on this image: every audio
  track spreads evenly, worst 6.1σ, and each track's deflate stream is
  **CRC-32 verified** on the way past. **The dump is clean**; the 36841
  "discontinuities" the old test reported were the music.
  The waveform settles it by inspection too — at a flagged step L and R track
  each other within ~30 counts while swinging ±20000 per sample, which is a
  coherent loud signal, not a seam.

# dcload-ip-rs

A Rust reimplementation of the `dcload-ip` host tool used to load and run
software on a Sega Dreamcast over a LAN. The Dreamcast side is the original
`dcload-ip` (a small serial/IP ROM payload that listens for UDP on the
console and forwards host I/O requests). This repo is **only the host tool**
— there is no Dreamcast-side code here. Anything that boots a game and talks
to a DC happens through this binary.

Single binary crate (`name = "dcload-ip-rs"`), edition 2024, v0.1.0. No
library output, no `lib.rs`, no integration tests. Edition 2024 needs a
recent stable Rust toolchain (≥ 1.85); the lockfile assumes current crates.io
versions of `clap`, `elf`, `polling`, `indicatif`, `console`, `md5`,
`miniz_oxide`, `pretty_env_logger`, `oxideav-adpcm`. (`console` is indicatif's own terminal
backend; it is declared directly so `src/ui.rs` can ask how wide the terminal
is. `miniz_oxide` is taken with its non-default `block-boundary` feature, which
is the whole reason a zipped disc image can be read without unpacking it --
see `src/disc_formats/deflate.rs`.)

## What a run actually looks like

If you only have five seconds: this binary speaks UDP to a Dreamcast, hands
it a binary, optionally tells it to start, and then sits in a long-running
loop answering the DC's runtime syscalls (read a CD sector, read the TOC,
open/read/write a host file, etc.) until the game exits.

A typical `u-exec` session, end-to-end, is roughly:

1. Open a UDP socket (`DcIoUDP::new` in `src/io.rs`). Bind to
   `0.0.0.0:0` in modern mode or `0.0.0.0:31313` in legacy mode; `connect`
   to `<DC_IP>:<port>`. The socket is non-blocking; reads are driven by the
   `polling` crate.
2. Send a `Version` (`VERS`) command. The DC replies with its protocol
   version and (optionally) a build identifier string. We refuse to
   continue if the DC doesn't answer -- five tries, then out, and the failure
   names `--infinite`.

   **`--infinite` (`-i`) waits for the console instead** (`dispatch::wait_for_any_loader`),
   which is what a session started before the Dreamcast has finished booting
   needs: it asks twice a second, forever, and picks the loader up the moment
   it answers. It is a START-UP option and covers this exchange only -- every
   command afterwards keeps its five tries, because a console that goes silent
   mid-session is a failure worth reporting rather than something to wait out.
   Deliberately not `query_loader` in a loop: `call_command` logs a warning per
   lost packet and `await_result` an error per timeout, which is ten lines
   every 2.5 s for a wait whose normal state is silence. So the question is
   asked directly, quietly, and a spinner (`ui::wait_spinner`) says it is still
   trying. For the same reason `io.rs` logs "nobody is listening there"
   (WSAECONNRESET on Windows, ECONNREFUSED on Linux -- a connected UDP socket's
   way of reporting an ICMP unreachable) at debug rather than error: with the
   console off, that is one line per poll.
3. **Loader placement** (`src/presets.rs`, `src/loaders.rs`, driven from
   `main.rs::wanted_loader_base`). Only on `u-exec` with a disc image, and only
   before anything else is uploaded.

   The Dreamcast side is not a debugger attached to a title, it is a program
   that stays resident in RAM while the title runs and answers its GD-ROM
   syscalls. Retail titles decide for themselves which RAM is free, and several
   of them treat the hole the loader sits in as exactly that. DreamShell's
   isoldr answers this per title, in the `memory` field of its presets, and this
   is the same answer applied the same way: read the disc's boot sector,
   identify the game, look up the address, and chainload a dcload relinked for
   it. Details are in the module docs; the four facts a reader needs:

   - The Dreamcast tree builds one ELF per base (`make loaders` in
     `target-src/dcload`), each self-contained — the guest vector table travels
     with it as a `.guestvbr` section. They live in **`loaders/` at this
     project's root**, with `game-presets.tsv` next to it — deliberately
     outside `target/`, so `cargo clean` cannot take them and a debug build and
     a release build read the same set. Override with `--loader-dir` /
     `DCLOAD_LOADER_DIR` (and `--game-db` / `DCLOAD_GAME_DB`); a directory
     beside the executable is still honoured, last, for a distributed copy.
     **Never keep a second set under `target/`.** A stale one chainloads an old
     loader that answers, runs, and reports its counters at addresses that have
     since moved, so every value read back is believable and wrong — that cost
     a full session on 2026-08-16. `LoaderSet::searched()` names every
     directory considered whenever something is missing.
   - Identification is exact (MD5 of IP.BIN sector 0, DreamShell's own key) with
     a title fallback, because that MD5 identifies a *dump* and coverage is
     partial — neither Sonic Adventure dump used in development is in the 1026
     rows. A title match is reported as approximate, and a tie between addresses
     breaks towards not moving.
   - **Going from a low base to 0x8cfe8000 must not be done directly.** A low
     loader keeps its packet buffers at 0x8cfe8000/0x8cfe9000, outside its
     image, so the new loader would be written through the buffers the upload
     is arriving in. It fails silently — success reported, new loader running
     and deaf. The plan hops via 0x8ce00000.
   - **Nor can a loader be uploaded over the address it is already running
     from**, which is what "refresh the loader in place" means and what a user
     naturally tries against an old CD build. It overwrites its own
     `cmd_partbin` mid-transfer: the console drops to the BIOS and the host
     sees only a DoneBinary that never arrives. `refuse_self_overwrite` in
     dispatch.rs blocks it before a single part goes out, on every path
     (`upload`, `uexec`, chainload), and names the remedy — hop to 0x8ce00000
     first. It compares PHYSICAL addresses, because a title goes to
     0x0c010000 while the loader sits at 0x8c004000 and those are the same RAM;
     the alias is the whole reason the check is not a two-line one.
   - **A base is judged by three tests, and the third one is not an address
     collision.** The constant scan asks what the title NAMES and the learned
     map asks where its reads have LANDED; both look for an overlap. A title's
     STACK is neither: it descends from 0x8c00f400 into whatever a low loader
     left below it, is named by no constant, and no read is ever served into
     it. `low_base_has_stack_headroom` is that test —
     `sp_min - _end >= LOW_BASE_MIN_MARGIN` — and Sonic Adventure at the stock
     base is the case it exists for: it passes the other two and corrupts the
     loader. The threshold sits between the two measurements in AGENTS.md 4.6
     (5240 bytes booted and played, 2444 corrupted), because a guard that
     rejects the configuration measured to work guards nothing. `sp_min` comes
     from `game-memory.tsv`; with none recorded the test passes, since assuming
     a depth would reject the base 593 presets ask for on one game's evidence.
   - **A disagreement in the database is information when one of the votes is
     unbuildable.** A title match is ambiguous when several dumps share a name
     and got different addresses; the tie-break keeps the loader still. But a
     vote below 0x8c004000 is DreamShell saying low RAM was too tight for that
     title — for a loader a quarter of this one's size — so keeping a 56 KB
     image at the stock base picks the one address the disagreement argues
     against. `low_family_contested` reads it, `base_off_the_low_family` answers
     from `ISOLDR_HIGH_ADDR` (checked like any other candidate, since Sonic
     Adventure 2's preset is that very address and its Maple DMA list rules it
     out). 8 of the database's 1026 rows reach this, Sonic Adventure among them.
   - `--no-relocate` runs whatever is on the console; `--loader-base 0x…` pins
     one. Both exist so a relocation can be ruled in or out as the cause of a
     title's behaviour in one run.

4. **Upload phase** (`src/dispatch.rs::upload_bytes`):
   - What gets uploaded is resolved first (`main.rs::resolve_payload`). A file
     is uploaded as it lies; a DISC IMAGE resolves to the boot binary the image
     itself names, read out of its ISO9660 root
     (`disc_formats::boot::extract`). Both then go through the same
     `upload_bytes`, so the ELF handling, the self-overwrite refusal and the
     byte accounting cannot drift apart between them.
   - If the input is an ELF, parse it with the `elf` crate, walk the
     sections that occupy memory at run time (`loaders::is_uploadable`:
     `SHT_PROGBITS` **and** `SHF_ALLOC` **and** a non-zero address), and upload
     each to the address in its section header. The CLI `--address` value is
     used only as a fallback entry point for non-ELF blobs.
   - For every chunk, we send `LoadBinary` (`LBIN`) once, then a stream of
     `PartBinary` (`PBIN`) packets — each one a fixed-size, zero-padded
     slice — paced with a small sleep and a longer sleep every
     `burst_packets` (10 in the syscall hot path, 15 during initial
     upload). Pacing exists to keep the DC's RX FIFO from drowning during
     runtime CDFS transfers.
   - After `DoneBinary` (`DBIN`), the DC tells us about any missing
     bytes; we re-send those chunks and repeat `DBIN` until the DC is
     satisfied.
5. **Execute phase** (`dispatch::execute`): send `Execute` (`EXEC`) with
   the entry point and a flag byte. `cdfs_redirect` is bit 1, `console`
   is bit 0. Any of `-d` / `-m` / `-c` forces `console` to true; the
   code does not let the user run with CDFS or host-FS redirection but
   no console mirror.
6. **Syscall phase** (`dispatch::receive_syscalls`): an infinite loop
   that answers `ReadSector` (sector data from a `.iso` / `.gdi` /
   `.cdi` image), `ReadToc` (the synthesized DC TOC, see `src/cd.rs`),
   and `FSCommand` (host file/dir syscalls routed through `src/fs.rs`).
   The loop exits cleanly only on the `DC00` `Exit` syscall; if the DC
   goes silent it will spin in `await_result` until the next packet
   arrives.

`upload` (no execute) does steps 1, 2 and 4 only -- no loader placement, since
without a disc there is nothing to identify. `reboot` is a single `RBOT`
command — it only works if dcload is currently in control of the DC;
it does not work against a normal game.

## Build & run

- `cargo build` — debug build, fast iteration.
- `cargo build --release` — release profile is set in `Cargo.toml` to
  `opt-level = 2`, `codegen-units = 1`, `lto = "fat"`. Release builds
  are noticeably slow because of fat LTO. Use debug for almost
  everything.
- `cargo run -- u-exec --host <DC_IP> <1ST_READ.BIN|loader.elf|disc image>` —
  upload and execute. Typical use against a real DC on the same LAN.
  **Pointing at a disc image is the short way**: `u-exec --host <IP> game.gdi`
  reads the boot binary out of the image (IP.BIN says which file it is) and
  serves that same image's sectors, so there is nothing to extract by hand and
  no second path to keep in step. `.zip` works everywhere an image does — see
  "Disc formats". Add any combination of:
  - `-d <disc.{gdi,cdi,iso,zip}>` — redirect CD-ROM reads to a host disc
    image. The format is chosen by extension (a zip by content); see "Disc
    formats" below. Only needed when the disc is NOT the thing being run.
  - `-m <host_dir>` — serve a host directory in place of the DC's
    filesystem. Paths are sandboxed; see `fs.rs::join_and_check_path`.
  - `-c` — mirror the DC's `stdout` / `stderr` over UDP into our
    own log. The CLI lets you pass `-c` on its own, but `-d` and `-m`
    silently turn it on too — there is no "CDFS without console"
    mode.
  - `--vga auto|always|never` — make the title believe a VGA box is plugged
    in. `auto` (the default) asks the console; see "Forcing VGA" below.
- `cargo run -- upload --host <DC_IP> <file>` — upload only. Useful for
  inspecting a payload without booting it. Takes a disc image too.
- `cargo run -- identify <disc image>` — what the image is, which loader base
  its preset wants, and which boot binary it holds. Touches no network.
- `cargo run -- extract <disc image> [-o out.bin]` — write the boot binary out.
  Also the only offline check that a zipped image reads back byte for byte like
  the loose one: extract from both and compare the md5 it prints.
- `--descramble auto|always|never` — a binary meant to boot from a CD-R is
  stored permuted and the disc's bootstrap unpermutes it while loading. We never
  run that bootstrap, so it has to be undone here. `auto` does it only when it
  can be proven (homebrew headers); a retail `.cdi` conversion that uploads and
  then does nothing at all wants `always`. See `disc_formats::scramble`.
- `cargo run -- reboot --host <DC_IP>` — single `RBOT` packet. Only
  honoured by dcload, not by a real game.
- `cargo run -- -h` — full CLI help. Subcommands are defined with
  `clap` derives in `src/main.rs`.

There is no `make`, no `xtask`, no installer. Everything happens through
`cargo` and the resulting binary in `target/{debug,release}/dcload-ip-rs`.

## Tests

Unit tests live in `src/presets.rs`, `src/loaders.rs`, `src/dispatch.rs` and
across `src/disc_formats/` -- the lookup rules, the chainload plan, the GAPS
probe, the VGA cable check, and everything that turns bytes on disk into
sectors. That last group is
testable precisely because it never touches the network. Everything past
`EXEC` still needs real hardware or an emulator. `cargo test` runs them; there
is no `[lib]` target and no integration-test directory.

Two tests are **skipped, not failed, when the dumps are absent**, which is the
convention for anything that needs a real disc:

- `disc_formats::gdi` needs `test/Sonic Adventure ....gdi` and its tracks.
- `disc_formats::zip::a_zipped_gdi_reads_identically_to_the_loose_one` needs
  that plus `test/sa-deflate.zip`, built with
  `zip test/sa-deflate.zip "test/Sonic Adventure"*.gdi test/track0*`.
  It is the one that matters for the archive reader: it compares 64 RANDOM
  16 KiB reads against the loose dump, because sequential agreement would pass
  even with the checkpoint table ignored. Run it with `-- --nocapture` and it
  prints the read latencies.

The `test/` directory at the repo root is **Dreamcast-side runtime
assets**: firmware (`test/DS/firmware/`), KLF modules (`test/DS/modules/`,
`test/DS/apps/*/modules/`), font files (`test/DS/fonts/`), Lua scripts
(`test/DS/lua/`, `test/DS/apps/*/lua/`), GUI bitmaps, etc. They are the
payload that gets pushed to a real Dreamcast for manual end-to-end
testing. The whole `test/` directory is listed in `.gitignore` (one
line, just `test`) so it is a per-developer sandbox and not part of the
source tree.

This name is unfortunately one keystroke away from Cargo's conventional
integration-test folder `tests/`. Do **not** rename it to `tests/` —
Cargo will treat the ELF/firmware/font files as Rust integration
tests and fail to build. If the naming conflict bothers you, the safer
rename is to something like `dc-assets/` and update the `test` entry in
`.gitignore` accordingly.

The realistic verification loop is:

1. `cargo build` (or `cargo clippy` if you want lint-only).
2. `cargo run -- u-exec --host <DC_IP> ...` against a real Dreamcast on
   the same LAN. Watch the logs; the binary is chatty with `--verbose` or
   `RUST_LOG=debug`.

There is no mock, no `localhost` test harness, no record/replay mode.
Changes that touch the protocol or syscall handlers need a real DC to
verify.

## Architecture cheat sheet

The crate is small enough that one diagram isn't really needed; the
short version is "main wires a CLI to a UDP transport and an upload/syscalls
dispatcher". The longer version, module by module:

- **`src/ui.rs`** — everything that touches the terminal. Owns the one
  `MultiProgress` for the process, installs the logger through it
  (`init_logging`), and hands out progress bars (`bytes_bar`, which
  returns a `Bar` that removes itself on drop). The point of the module
  is that a log record and a progress bar can no longer write over each
  other: records are printed from inside `MultiProgress::suspend`. If you
  create a `ProgressBar` anywhere else, it is outside that arrangement
  and will be shredded by the next log line. It also holds `LoadMonitor`,
  which aggregates a running title's disc reads into "loading" bursts, and
  `DiagPanel`, the counter panel described further down.

- **`src/diag.rs`** — dcload's own always-compiled counters, read off the
  console with `SendBinQ` while a title runs and shown in a panel (`--diag`,
  off by default). Holds the table of what to read and how to format it, the
  symbol lookup, and the sampling state machine. Unit-tested for the parts that
  are pure (grouping, deltas, the table having no duplicates).
  **The header reports the MEASURED gap between the two samples a delta is
  taken across, never the configured interval.** They are not the same: a
  sample is answered from inside dcload's `bb->loop()`, which during CD-DA is a
  fraction of a percent duty cycle, so a request made on a 2 s timer is
  regularly served most of a second late. Measured 2026-09-03: 49 audio fetches
  under a header reading "2.0s" is 24.5/s against the 18.75/s real time needs,
  an apparent 31 % over-fetch — and the real gap was 2.61 s, so the loader was
  exactly in real time. Two counters exist only to be divided by this number
  (`g_cdda_ticks`, `g_cdda_played`: 12 500 000/s and 44 100/s are what a
  correct pacing model looks like), and they are worthless against a nominal
  one.

- **`src/stackwatch.rs`** — how close the running title's stack is coming to
  the loader, read off the console while it plays. One `SendBinQ` for eight
  bytes every ten seconds (`g_gd_sp_min` / `g_gd_sp_in_image`, which dcload
  latches for free on every GD syscall), claimed through `io::PacketSink` like
  the counter panel's samples and posted only from the top of the syscall loop.
  ON IN EVERY SESSION, unlike `--diag`: it is the only thing that can see the
  one failure the placement tests are blind to, and the value is latched on the
  title's FIRST GD syscall — so the verdict arrives seconds into a boot, long
  before the freeze it predicts. What it measures is written to
  `game-memory.tsv`, so a session at a base that works teaches as much as one
  at a base that does not.

- **`src/adpcm.rs`** — 4-bit Yamaha ADPCM, the AICA's own flavour, as a
  **continuous stream**. The loader asks for it with `DC24` instead of `DC23`
  and the point is bus time on the console: measured 2026-09-01, a 7056-byte PCM
  fetch costs it ~1.2 ms out of the BBA's SRAM and ~1.0 ms into sound RAM,
  25 times a second, all inside the title's frame loop — while this host serves
  the same fetch in 0.11 ms. Both halves are byte counts, so a quarter of the
  bytes is a quarter of the cost.

  What makes it a module rather than a function is that **the encoder's state is
  the console's decoder state**. ADPCM is differential; the AICA plays our ring
  in `AICA_SM_ADPCM_LS`, the mode whose defining property is that the predictor
  survives the loop back to the ring's start. So `Stream` continues from request
  to request, never resets at a seek or a track loop, re-encodes a **repeated
  LBA from the state it had at the start of it** (the loader re-asking for a
  fetch whose answer it never saw must get identical bytes), and resets only
  when bit 31 of the request says so — which the loader sets at key-on, the one
  event that resets the AICA's own decoder. Five unit tests, of which
  `requests_concatenate_into_one_stream` is the one the whole design rests on.

  **The codec itself is `oxideav-adpcm`** (`yamaha::Chip::Aica`), and it is
  there for provenance, not for speed: it implements the Y8950 Application
  Manual's recurrence and **makes the AICA/OPNA distinction a type**. Both
  chips approximate the same `~1.1^M` step curve, but AICA/Y8950/YMZ280B is
  `{230,…,614} >> 8` and the YM2608 manual's Table 5-1 is `{57,…,153} >> 6` —
  0.8984375 against 0.890625. A stream encoded with one and decoded by the
  other does not sound obviously wrong, it *drifts*, and the only other place
  that could be noticed is a Dreamcast three minutes into a track.

  A hand-rolled encoder from KOS's `utils/wav2adpcm` shipped first and was
  **measured against the crate over 200000 samples: rms error 385.4 against
  385.2, SNR 30.3 dB either way**. (44.5 % of nibbles differ, which is only the
  two trajectories separating after the first disagreement.) So the swap costs
  a dependency and buys no fidelity — what it buys is that the constants are
  argued from the manual rather than copied, and that
  `the_crate_still_decodes_like_the_aica` walks the whole step range against
  the recurrence written out by hand. **That test is the spec**: if the
  dependency ever has to go, the codec is ten lines and the test still says
  whether they are right.

  **The dependency is not free**: `oxideav-adpcm` pulls `oxideav-core`, which
  pulls `serde_json`, `bytemuck` and `thiserror` unconditionally — 11 crates
  for a 60-line codec, roughly doubling this binary's tree. Worth knowing
  before the next one is added on the same reasoning.

- **`src/ppf.rs`** — the PPF patch format (v1.0, v2.0, v3.0), parsed and
  applied. A PPF is a list of "at file offset N, these bytes instead"; what
  makes it a module rather than a loop is the part that says WHICH file it is
  for. A PPF3.0 carries 1024 bytes of the original at a fixed offset, so it can
  identify the exact dump by content, and a mismatch there is fatal — a patch
  aimed at another dump writes plausible bytes into the middle of live SH4 code
  and produces a title that boots and then behaves strangely, which is the
  hardest failure in this project to attribute to anything.

- **`src/patchdb.rs`** — the shipped patch library: `patches/patches.tsv` and
  the `.ppf` files beside it, found by the same search as `game-presets.tsv`.
  Unlike the GAPS guard and the cable check this one IS a mapping list, and it
  has to be: what these patches fix is different in every title, so there is no
  content signature to look for. The list is a claim and the patch checks it.

- **`src/memmap.rs`** — what earlier sessions measured about a title, keyed on
  the same boot-sector MD5 the presets use: a 256-bit bitmap of the 64 KB blocks
  its disc reads landed in (merged by OR) and `sp_min`, the lowest stack pointer
  it was seen entering a GD syscall with (merged by MINIMUM). Written by a
  ticker thread rather than by the read path, because a session normally ends in
  a way no handler is told about and no disc read should pay for a file write.
  Meant to be committed and shared: a row is only ever incomplete, never wrong.

- **`src/presets.rs`** — the per-game settings table carried over from
  DreamShell's isoldr presets, and the disc identity (IP.BIN fields plus the
  boot-sector MD5) used to look a game up in it. Two-tier matching, and the
  vocabulary for saying which tier answered. Unit-tested.

- **`src/loaders.rs`** — everything about *where* the Dreamcast-side loader
  lives: parsing the base out of the VERS reply, finding the ELF for a base,
  the memory a running loader is using (`live_footprint`, which is a LIST of
  ranges and the reason a direct chainload to 0x8cfe8000 is refused), and the
  hop plan. Unit-tested.

  `layout()` is the one copy on this side of the layout table in
  target-src/dcload/Makefile: the four addresses a loader build is pinned to
  (image, stack, `.hiram`, Maple DMA), and the two families they come in.
  `live_footprint` and `relocate` both read it, so they cannot come to disagree
  about where a loader's buffers are.

  **`relocate()` applies four deltas, not one**, which is what lets one
  `dcload-relocatable.elf` answer for a LOW base as well as a HIGH one — the
  stock base included, which used to need its own pre-linked ELF. Each
  `R_SH_DIR32` is classified by the VALUE of the symbol it names; classifying by
  the symbol's *section* does not work (`PROVIDE (_dcload_base = ORIGIN(ram))`
  is filed in `.hiram` by ld) and neither does the word's value (`commands.c`
  reaches its base through P2). `.guestvbr` carries no relocations and is
  base-dependent — six words naming the jump table at `base+0x00..+0x20`, from
  `exception.S`'s `-D` literals — so it is patched by content and re-scanned;
  before 2026-08-28 it was not patched at all, and every relocated loader handed
  its title a vector table pointing at the base the image was linked for.
  `relocating_reproduces_every_native_link_byte_for_byte` checks the whole thing
  against whatever `make loaders` deployed, and skips when the set is not there.

- **`src/main.rs`** — entry point. Defines the `Args`/`Commands` clap
  structs, sets up logging (`ui::init_logging`, `-v`/`-vv` for
  debug/trace, otherwise honors `RUST_LOG`), chooses legacy vs. modern
  mode from `CHUNK_SIZE`, opens the `DcIoUDP` socket, sends the initial
  `Version`, and dispatches to the right `dispatch::*` function for the
  chosen subcommand. The constants at the top — `PROTOCOL_VERSION_*`
  and `CHUNK_SIZE` — are the only knobs that switch protocol behaviour.

- **`src/dispatch.rs`** — does most of the work. `upload` reads the file,
  parses ELF sections, drives the `LBIN` / `PBIN` / `DBIN` handshake,
  and handles the "DC asked for missing bytes" retry loop.
  `receive_syscalls` is the long-running event loop after `EXEC`: it
  pumps the `polling` socket, parses incoming `DCLoadClientCmds` packets,
  and dispatches each one (`ReadSector` → disc reader, `ReadToc` →
  `cd::build_dc_toc`, `FSCommand` → `fs::handle_fs_syscall`,
  `Exit` → clean return). It also contains the lower-level `send_data`
  (host → DC) and `receive_data` (DC → host) helpers, plus
  `await_result` / `call_command` for retry-with-timeout plumbing.

- **`src/cmds.rs`** — wire format. The `DCLoadCmd` struct has a
  4-byte ASCII command tag plus two big-endian `u32` fields
  (`address`, `size`); some variants carry a fixed-size
  `[u8; CHUNK_SIZE]` payload. `From<DCLoadCmd> for Vec<u8>` does the
  encoding; `TryFrom<Vec<u8>> for DCReturnCmd` does the decoding. The
  client (DC-originated) commands are a separate `DCLoadClientCmds`
  enum, all starting with a 4-byte tag like `DC00` (Exit), `DC01..DC22`
  (FS syscalls), and a few that map to `ReadSector` / `ReadToc`. The
  big-endian decision is the wire format; do **not** convert to
  little-endian — the DC expects network byte order.

- **`src/io.rs`** — networking. `ExternalDcIo` is a small trait
  (`poll`, `handle_data`, `send_command`, `set_sink`) with a single
  implementation `DcIoUDP` that wraps a non-blocking `UdpSocket` registered
  with the `polling` crate. There is no other transport, no loopback, no
  test-only implementation — anything you want to test has to go
  through a real UDP socket or a DC.

  **`handle_data` drains the socket, one wakeup at a time.** The poller is
  one-shot, so it used to take exactly one datagram per wakeup however many
  were queued — under a runtime CDFS load that is a backlog that only grows,
  and whatever a caller is waiting for surfaces some number of wakeups after it
  actually arrived. Tested, and the test fails when the drain is removed.

  **`set_sink` installs a `PacketSink`**, which claims packets before any caller
  sees them. It exists because a reply to a command issued out of band arrives
  wherever the host happens to be polling — inside `send_data`, most of the
  time, which discards what it did not ask for. A sink must claim only what it
  asked for; eating somebody else's reply is a transfer that never completes.

- **`src/fs.rs`** — host-side filesystem. The full set of KOS-style
  FS commands is implemented in `handle_fs_syscall`, with one function
  per command. State lives in `FSSyscallState`: a `base_path`
  (the `-m` argument, or `.` if not set), an emulated `cwd`, and two
  fixed-size `Vec<Option<...>>` tables for open files and open
  directories. Two constants matter:
  - `FILE_OFFSET = 10` — first valid host fd. FDs 0/1/2 are reserved
    for stdout/stderr/stdin; `fd < FILE_OFFSET` is special-cased in
    `write` to log to the host.
  - `DIR_OFFSET = 1337` — first valid dir handle. KOS apparently
    struggles with `dirent` values ≤ 100, so the project just picks a
    safe high offset.
  Path joining goes through `join_and_check_path`, which canonicalises
  the base and rejects any path that escapes it. `link` is the only
  function with `#[cfg(target_family = "...")]` branches: it uses
  `std::os::windows::fs::symlink_file` / `symlink_dir` on Windows and
  `std::os::unix::fs::symlink` on Unix. A lot of FS failures return a
  `ReturnValue` whose `address` is `u32::MAX`; that is the wire-level
  "error" sentinel for the DC, **not** a `Result::Err`.

- **`src/cd.rs`** — synthesises a 102-entry Dreamcast CD-ROM TOC at
  runtime, in little-endian (the DC reads it native-endian; everything
  else in the protocol is big-endian). `build_dc_toc(start, n)` returns
  a 408-byte buffer; consult this if you need to change how virtual
  discs are advertised to the DC.

- **`src/disc_formats/`** — the disc readers, and everything under them.

  `types.rs` holds the `DiscFormat` trait (`read_sector`, `start_sector`,
  `boot_sector`, `num_sectors`, `fs_lba`). `iso.rs`, `gdi.rs` and `cdi.rs` are
  the three formats. `dispatch::open_disc` chooses: `.gdi` → `Gdi`, `.cdi` →
  `Cdi`, a zip **by content** → the image inside it, anything else → `Iso`.
  `StubDisc` is the placeholder used when `-d` wasn't passed — its
  `read_sector` returns an error.

  **The readers do not open files.** `source.rs` has `ImageSource` (`read_at`,
  `len`) and that is all a reader needs; `FileSource`, `SubSource`,
  `MemorySource` and the archive readers implement it. `Container` is the
  second half and exists for one format: a `.gdi` is a text file that NAMES its
  tracks, so opening one means opening its siblings, and "sibling" is a
  directory for a loose dump (`DirContainer`) and a name prefix inside an
  archive (`ZipContainer`). Everything else opens one thing and is done.

  `zip.rs` reads an image **out of a `.zip` in place** — nothing is unpacked.
  A STORED member (`zip -0`) is a seek and costs nothing at all. A DEFLATED one
  goes through `deflate.rs`, which indexes it once and then reads it at random:
  deflate has no restart points but it does have block boundaries, and at one
  the decoder's whole state is (which bit comes next, the last 32 KiB of
  output) — `miniz_oxide`'s `block-boundary` feature exposes both. Measured on
  the 1.10 GiB Sonic Adventure track: 4.7 s to index, then 0.28 ms for a
  sequential 16 KiB read, 0.34 ms with three files interleaved, and 3.5 ms for
  a genuinely random one. **The index pass is also the only
  correctness proof there is**: it decodes every byte anyway, so it checks the
  member's CRC-32 before a single sector is served. Encrypted members, split
  archives and any other compression method are refused BY NAME.

  `iso9660.rs` is just enough of the filesystem to find a file in the root —
  no paths, no Joliet, no recursion — because a title's boot binary is always
  a root file that IP.BIN names at +0x60. `boot.rs` puts it together:
  `extract()` returns the binary a `uexec <image>` uploads. `scramble.rs` is
  Sega's CD-R permutation and, more importantly, the honest limits of detecting
  it.

  **The boot track of a GDI is the FIRST data track of the high-density area,
  which is neither the first nor reliably the last track on the disc.**
  `start_sector()` is the lowest data track — the low-density stub, and the
  sector DreamShell hashes to name a preset, so it must not move.
  `boot_sector()` used to be its mirror, the highest data track, and that is
  right only for the ordinary three-track dump. A title whose CDDA lives in the
  high-density area is mastered `data / audio / … / data`: measured on the Buzz
  Lightyear of Star Command PAL dump, `0 data, 6986 audio, 45000 data, 257827
  audio, 263852 data`, where IP.BIN and the ISO9660 PVD are on track 3 and
  track 5 sector 0 is mid-file payload. The rule is now "the lowest data track
  at or above LBA 45000" — 45000 is where the high-density area begins on every
  GD-ROM, and a `.gdi` records its track starts in that same origin — falling
  back to the highest data track when no track reaches it. `num_sectors()` still
  asks for the last data track directly, because the lead-out is behind *that*
  one. The failure this fixes was total and looked like a bad dump: "neither LBA
  264002 nor an IP.BIN file in the root directory there carries a Dreamcast
  header, so the disc does not say which file it boots", about a disc that says
  so perfectly clearly 219000 sectors earlier.

  **`Cdi` used to be a stub and it mattered.** It sniffed the first sector,
  picked a sector size, and treated the whole file as one flat run from LBA
  150 — the `cdi2iso.c` heuristic, which is where it came from, so that file
  is not a reference. All three real images available start with an *audio*
  track, so the Dreamcast's first sector request was answered with audio
  samples and no error was reported. Picking the boot track is the subtle
  part: not the first, not the last, and **not** "the one whose first sector
  says SEGA SEGAKATANA" — that picks a 302-sector stub session on the Sonic
  Adventure conversion. The test that works is an ISO9660 PVD at track sector
  16 whose root directory extent lies inside that same track. Module docs have
  the arithmetic.

  **Every open failure is reported now.** `open_disc` returns a `Result` and
  the cases — path does not exist, archive holds no image or two of them,
  format not understood, opens but holds no Dreamcast header — are
  distinguished. They used to collapse into one `None` that `identify_disc`
  printed as "no readable IP.BIN in <path>", and a `.gdi`/`.cdi` that failed to
  open fell through to `StubDisc` with nothing logged, so a mistyped `-d` gave
  a whole session with CDFS silently dead.

  `types::find_ip_bin` is where identification reads the header: the boot
  sector first, then `IP.BIN` as a FILE in the ISO9660 root, because one real
  image starts its data track with sixteen blank sectors and carries IP.BIN
  that way.

- **`src/types.rs`** — wire-format structs. `DCLoadDirEnt` and
  `DCLoadStat` are `#[repr(C)]` mirrors of the DC's `struct dirent`
  and `struct stat`; they serialize little-endian because that's what
  the DC reads. `ExceptionStruct` is the 272-byte SH-4 exception
  frame; if a download comes back prefixed with `b"EXPT"`,
  `fs::download_data` `transmute`s the first 272 bytes into it and
  logs the register dump, then dumps the raw bytes to
  `dc_exception_dump-<unix>.bin` in the cwd for offline analysis.
  `NotImplemented` is a small `Display` + `Error` type used when an
  unknown client command tag arrives.

## Forcing VGA

`--vga` makes a title believe a VGA box is plugged in. Two changes, both found
in the image by content -- no per-game table -- and both applied before the
title runs:

- **The cable check in the title's own code** (`dispatch::vga_cable_patches`).
  A Katana title asks the hardware which cable it is on exactly once, by
  reading the SH4's port data register `0xff800030` and taking bits 8 and 9
  (0 = VGA, 2 = RGB, 3 = composite). Everything downstream follows from those
  two bits, so forcing that read to 0 IS the patch, and it is one halfword.
- **The IP.BIN peripheral field** (`dispatch::declare_vga_in_ip_bin`), bit 4 of
  the hex string at +0x38. A different reader, which is why it is not
  redundant: IP.BIN's own bootstrap consults it and `--boot-ipbin` runs that
  bootstrap, and the header stays in RAM at 0x8c008000 where the title can read
  it back -- this host puts it there itself, exactly as isoldr does, precisely
  because nothing else on our path ever populates that region.

Measured on four PAL dumps. Each has EXACTLY ONE aligned occurrence of
0xff800030, exactly one instruction that loads it, and the same routine around
it, byte for byte:

| title | cable check | IP.BIN peripherals |
| --- | --- | --- |
| Sonic Adventure | 0x8c10d866 | `0601A10` -- declares VGA |
| Sonic Adventure 2 | 0x8c137276 | `0799A10` -- declares VGA |
| Crazy Taxi | 0x8c162dee | `0799A10` -- declares VGA |
| Snow Surfers | 0x8c0e9026 | `0799A00` -- **does not** |

```text
  d3 03   mov.l  @(3,PC),r3   ; 0xff800030
  92 03   mov.w  @(3,PC),r2   ; 0x0300
  64 31   mov.w  @r3,r4       <- becomes `mov #0,r4` (e4 00)
  60 4d   extu.w r4,r0
  00 0b   rts
  20 29   and    r2,r0
```

**The read is what is patched, not the extraction after it.** The caller shifts
and masks the result in its own way -- `shlr8` then `and #3` in all four, and a
title is just as free to test the raw 0x300 -- so forcing the value that comes
off the port answers every one of those shapes while having to recognise none
of them. The scan is anchored the same way the GAPS probe is: the literal
alone proves nothing, an `mov.l @(disp,PC),Rn` must load it, and the read must
use the register it went into.

**`auto` asks the console, and that is the whole point of the option.** Nothing
on this side of the wire can see which cable is plugged in, so dcload reads it
off PDTRA and reports it in its VERS reply, after the base
(`loaders::parse_version_payload`, `Cable`). The host then patches only when
there really is a VGA box on the other end — forcing VGA on a television is a
black screen. `--vga always` covers the case the console cannot report: an
adapter that does not ground the detect pins (some VGA cables, some HDMI
boxes), where the title is told composite while the display wants 480p.
`--vga never` disables it.

**Unknown is not "not VGA", and it is not "VGA" either.** A loader too old to
report the cable, or a VERS that does not come back, leaves the title alone and
says so in the log. That asymmetry is deliberate: the code for VGA is 0, so
every loose decode — trailing zero padding, a short reply, a missing field —
lands on the one answer that would patch a title on a television. There is a
test for the padding case.

**The question is asked when the decision is made, not once at start-up.** A
chainload replaces the loader, so the one that answered first is not
necessarily the one that will run the title: the loader that came off the CD
may predate the field while the one just uploaded reports it
(`dispatch::query_cable`). One round trip on an idle console.

`identify` prints what `--vga` can do to an image, with no console attached:

```
vga      : IP.BIN does NOT declare VGA box support; 1 cable check(s) --vga would force to VGA
```

**What it cannot do** is give a title a 480p path it was never built with: one
that declares no VGA support may set an interlaced mode by hand, and that is a
per-title patch no scan finds. When the scan comes up empty `--vga` says so
loudly rather than leaving it to be discovered on the console -- afterwards, a
title that ignored the patch and a title that was never patched look exactly
the same.

Like the GAPS guard, the patch **survives a reload**: it changes a word in the
title's own image, and a title is free to read that image back off its disc, so
`receive_syscalls` re-applies any patched word a disc read covers before the
title can run the bytes just delivered.

## CD-DA: what the music costs the title

Every disc read freezes the running title — dcload sits in `bb->loop()` until
the transfer completes — and audio is 25 of those a second, forever, while a
data read is bursty. So the audio path is the one place where the transfer's
reliability machinery is worth *less* than its latency.

Measured 2026-08-31 on Snow Surfers, timed by the host from request receipt to
`ReturnValue`:

| | |
| --- | --- |
| fetches | 24.9/s (7056 B = 3 raw sectors = 40 ms of audio) |
| title frozen | **3.01 ms each**, disc 0.04 + wire 2.98, max 11.08 |
| share of wall time | **7.5 %** |
| payload at 100 Mbit | 0.56 ms — so **2.4 ms of the 3.0 was two round trips** |

The handshake, not the data, is the cost. `send_audio()` therefore drops both
round trips: every failure it stops detecting is worth a click (a lost part
leaves ~1.4 ms of the previous ring revolution; a lost LoadBinary makes dcload
refuse all the parts and replay ~40 ms of stale ring), while the round trips
were worth 6 % of the machine. The `ReturnValue` is NOT dropped — it is what
releases `bb->loop()`, and losing it costs seconds. One fetch in 256 still
probes with DoneBinary, so a link that starts dropping half the audio is
reported rather than left to be blamed on the ring or the AICA.

**WHAT THIS NUMBER IS, EXACTLY.** It is the host's own half: request received
-> disc read -> packets out -> ReturnValue sent. It is NOT the whole freeze,
which also carries the two flight times and whatever dcload processes out of its
RX ring before it reaches the ReturnValue. That distinction did not matter while
the path had blocking round trips -- the host sat idle waiting for the DC, so
the two nearly coincided -- and it matters a great deal now that it does not.
The 2.4 ms that went away was genuine mutual waiting and is genuinely gone; the
0.3 % that remains is a floor on the freeze, not a measurement of it.

**This could not be measured on the console.** dcload only looks at the wire
from inside `bb->loop()`, and after loading the only thing that enters it is the
audio fetch itself — a few percent duty cycle — so `--diag` samples a console
that is not listening and times out. The host is the other end of the freeze;
it times it with a clock the Dreamcast never touches. `GD_SERVICE_EVERY_SYSCALL`
would open a window 60 times a second, but it does so by adding 256 poll
iterations to every GD syscall, i.e. by changing the thing being measured — and
it is the flag that killed Sonic Adventure.

**And the fix shrank the loader's listening window by the same factor it saved.**
dcload hears the host only from inside `bb->loop()`, which is now ~0.13 ms out
of every 40 ms: a **0.3 % duty cycle**, against 7.5 % before. Anything else the
host wants to ask -- `--diag`, `stackwatch`, a probe -- now waits many fetch
windows to be heard (measured: a panel sample's second request took 334 ms
instead of 2 ms, repeatedly), and is then served *inside* an audio fetch. So the
counter panel became a disproportionately heavy guest as a direct consequence of
the path getting cheap, and an A/B of the game with and without `--diag` is now
worth doing before blaming anything else.

Whatever stutter survives this is **not** the network: it is the 176 KB/s of
32-bit CPU stores into sound RAM (`cdda_push_frames`), which happen after the
`ReturnValue` and are invisible from here — and the 176 KB/s read *out* of the
BBA's SRAM before them, which is the same size and just as invisible. **That is
what `src/adpcm.rs` and `DC24` are for**: the AICA decodes 4-bit Yamaha in
hardware, so a quarter of the bytes is a quarter of both halves and the fetch
rate falls from 25/s to 19. The cost is that it is lossy and, more importantly,
**stateful** — with PCM a lost sample is a click that heals, with ADPCM it
desynchronises a predictor that does not. The loader chooses (`CDDA_ADPCM`, a
rebuild); this host serves whichever command arrives, and `DC23` is unchanged.

## Shipped patches (PPF)

`--vga` can force a cable check and set a flag because both are one known
instruction and one known field. It **cannot** give a title a video path it was
never built with: the PAL release of Snow Surfers offers neither VGA nor a
50/60 Hz screen, and adding one is a different piece of work in every title.
Somebody did that work by hand in 2015 and shipped the result as four bytes in a
PPF. That is what the patch library is for — **patches nobody can derive, only
carry**.

So this is the one place in this host with a per-game table. It lives in
`patches/`, beside the `.ppf` files, and travels with the loaders and the two
`.tsv` databases by the same search (`loaders::patch_dir_candidates`): a
deployment has all of it or none of it, for the reason §14.19 of dcload-ip's
own notes exists — a set found in `target/` is one `cargo clean` takes and one
that differs between debug and release, and a patch applied from a stale
directory is worse than a missing one, because what it produces is a title that
runs.

**A mapping list is a claim; the patch itself usually checks it.** Every row is
verified against the image before a byte is written:

| | what it proves |
| --- | --- |
| the PPF3.0 blockcheck | 1024 bytes of the original file — the exact dump, by content, with no database involved |
| `bin_md5` | the boot binary is the one the row means |
| `disc_md5` | the boot sector is the dump the row means (the identity the rest of this host uses) |

A patch that fails the blockcheck is **refused, not forced** — including one
named by hand with `--ppf`. Its offsets mean something else in this image, so
applying it would write correct bytes into the wrong instructions. A PPF1.0, or
a PPF3.0 built with the blockcheck off, can prove nothing; those are what the
`bin_md5` column exists for, and applying one is an act of faith by
construction.

**Patched on the host, before the upload.** The bytes go into the payload
buffer, so what is uploaded is what runs, the read-back verification checks the
patched bytes like everything else, and no round trip is spent. Poking the words
in afterwards (as `--patch` does) would cost a round trip each and, worse, put
them outside every check on the transfer — the read-back comparison would be
against an image the host itself no longer agreed with. Applying it first also
means the scans that follow — `literals_in_loader_footprint`, the GAPS probe,
the cable check — all look at the code that will actually execute.

**And guarded afterwards**, by the same mechanism as `--vga` and the GAPS
probe: a title is free to read its own binary back off its disc, and one that
does would otherwise undo the patch several seconds into its own start-up,
silently. The changed bytes are widened to the aligned words that hold them
(four bytes in one word is one write, not four) and handed to
`receive_syscalls`, which puts them back before the title can run what was just
delivered.

`apply` in the manifest is `auto` or `manual`. `manual` is not a formality: a
patch can be perfectly correct and still not something to apply to somebody's
session unasked — the Snow Surfers one forces 60 Hz, which is a change to what
the title *does*, not only to what it supports. Shipping such a patch and
letting `--ppf` reach it beats either applying it silently or not carrying it.

`--no-ppf` turns the list off and still reports what it held back: an off-switch
that also silences "there is a patch for this game" turns an A/B test into a
fact nobody is told twice. `--ppf FILE` is unaffected by it — an off-switch for
the mapping list has no business discarding a file named by hand.

A `.ppf` dropped into `patches/` with no row is **offered, never applied**, and
only when its own blockcheck verifies against this image. Fitting is not the
same as being wanted, and the manifest is where "wanted" is recorded. An
unverifiable patch fits every image equally, so offering those would offer the
whole directory.

`dcload-ip-rs identify <image>` prints the whole answer with no console
attached, which is where it is worth the most: a patch that does not fit is a
fact about two files, and finding that out offline costs one command.

Measured 2026-08-31 on `Snow Surfers v1.001 (1999)(Sega)(PAL)[!]`
(boot md5 `1aae36b0…`, bin md5 `ca89367a…`) against `jc-snows-60hz-vga.ppf`:
PPF3.0, blockcheck present and matching, four single-byte records at
`0x4d1e6`/`0x4d1fa`/`0x4d30c`/`0x4d30e`, three guard words (two of the bytes
share one), and the result equals the author's own `1ST_READ_PATCHED.BIN` byte
for byte. That last comparison is
`ppf::tests::reproduces_the_shipped_patched_binary`, `#[ignore]`d because it
needs a retail dump this repository does not carry; the command that runs it is
on the test.

## Protocol modes

`CHUNK_SIZE` in `src/main.rs` is a single `usize` that toggles two things
at once: the wire protocol version, and the local UDP bind. There is no
auto-negotiation — the same value is used for both client and host:

- `1440` (current default) → modern protocol, version `v[2, 0, 3]`.
  `remote_port` is whatever the user passed (default `53535`); the
  local socket is bound to `0.0.0.0:0` (kernel-assigned ephemeral
  port).
- `≤ 1024` → legacy protocol, version `v[0, 0, 0]`. **Both** `remote_port`
  and the local bind are forced to `31313`, regardless of `--port`.
  The local bind in particular is what the original dcload-ip host
  tools expect.

If you are debugging a connectivity issue, check the mode first —
clients of the two protocols will not talk to each other. The branch
is in `main.rs` and reads `if CHUNK_SIZE <= 1024`; the `local_port`
branch is the easy one to miss because it silently overrides `--port`.

## Debugging

`.vscode/launch.json` ships six prebuilt LLDB launch configs, all
hardcoded to a Dreamcast at `192.168.1.64` and to local Windows
game paths under `C:\Users\arnod\Downloads\` and
`C:\Users\arnod\Documents\Dreamcast\`. They are useful as templates —
copy one, change the IP, change the binary path, change the `-d` /
`-m` arguments. Do not commit changes to these files blindly.

All configs set `RUST_BACKTRACE=1` and `RUST_LOG=debug`. Two of them
also set `DCLOAD_IP_RS_TRACE_STALL=1` (a value the binary honours;
search for that string in the source if you need to know what it
does in this version — the name implies it traces slow receive loops).

The binary is otherwise a normal command-line tool: `RUST_LOG=trace`
plus `-vv` is the deepest verbosity, and `dispatch::send_data` /
`dispatch::receive_syscalls` are the most useful `tracing!` targets.

**The display and the log share the terminal on purpose** — see
`src/ui.rs`. Everything a reader needs to know about it:

- One bar per upload, sized in bytes over the WHOLE file, so the rate and
  the ETA are stable. It advances on bytes the DC has ACKNOWLEDGED (the
  address `DoneBinary` reports), never on bytes merely sent, and it never
  moves backwards even though `DoneBinary` does.
- Log records are printed from inside `MultiProgress::suspend`, so they
  land above the bar instead of through it. That only works for bars
  created via `ui::bytes_bar`.
- Nothing draws when stderr is not a terminal: `dcload-ip-rs … 2> log`
  gets plain text with no escape sequences.
- `DoneBinary` is logged at TRACE, not DEBUG. It is sent once per
  eight-packet window, so at debug level it alone was hundreds of
  identical lines per second. Everything else is unchanged.
- Commands log through `Display` (`LBIN 0x0c010000 +368640`), not
  `{:?}`. `{:?}` printed addresses in decimal and would have dumped the
  whole 1440-byte payload of a `PartBinary`.
- Transfers under 10 KB get no bar at all (`ui::BAR_MIN_BYTES`).

**The counter panel (`--diag`)** is a debug aid and off by default. What is
worth knowing before touching it:

- **`d` is the master switch, and it works in both directions at any moment.**
  `--diag` only chooses the state a session starts in; `start_diag` runs
  regardless, because none of it can be done later — `verify_image` is a
  blocking round trip and the console is idle only in the seconds before the
  title starts. Its failures drop to `debug` when nobody asked (`note()`).
  **Off means the console is not asked anything**, not that the box is folded
  away: every sample is a `SendBinQ` dcload answers from inside `bb->loop()`, so
  a hidden-but-sampling panel goes on perturbing the exact window someone hides
  it in order to measure. That is what `d` used to do.
- **Exactly one of the panel and `stackwatch` may be on the wire**, because the
  panel's range CONTAINS `g_gd_sp_min` and both sinks claim by address. They
  follow `ui::sampling_wanted()` in opposite directions, each at its own tick,
  and **an inactive sink claims nothing** — that one line is the whole of the
  exclusion, and it has a test. A session that never presses `d` keeps the stack
  watch it has always had.
- **`measure_rtt()` gives the number every other latency is read against.**
  Five four-byte round trips on the idle console, minimum reported, logged once
  before the upload. It exists because dcload's own TMU2 timing of a CD-DA fetch
  (3.31 ms) and this host's timing of its half of the same fetch (0.13 ms) left
  3.2 ms that nothing could attribute. **`ping` cannot substitute**: dcload
  answers ICMP correctly, but only from inside `bb->loop()`, so once a title
  runs the reply waits for the next fetch — up to 40 ms of loader scheduling
  reported as if it were the link.
- **`w` writes a snapshot, and the panel is not meant to be copied from.** It
  is redrawn on every sample and again before every log record, and a terminal
  drops a selection the moment the cells under it change -- so selecting it is a
  race against the next repaint, unwinnable at any useful sampling rate. `w`
  prints the set as plain text through `suspend`, i.e. above the live region
  where nothing will redraw it, and appends it to `dcload-diag.txt`. **Zeros
  included**: the panel hides them, so in a paste "absent" and "zero" are
  indistinguishable -- which is the difference between a feature compiled out
  and a hazard that is not happening, and it had to be guessed at twice.
- **Where it draws is not a style choice.** The requirement was that selecting
  the log copies the log and not the panel, and a terminal selection returns
  whatever is in the cell grid: a full-height column down the right-hand side
  shares every physical line with a log line and goes into the scrollback with
  it. No escape sequence makes a region unselectable, and left/right margins
  (DECSLRM) make it worse — terminals that support them save only full-width
  lines to scrollback. So the panel is a right-aligned block inside indicatif's
  live region, which `suspend` erases before every log record: it never enters
  the scrollback at all. Measured: 54 log records interleaved with panel
  repaints, none of them carrying a box glyph.
- **The panel is a grid, not a slot.** One column of at most 24 rows showed a
  third of the set beside 140 empty columns. `compose` fills every column the
  terminal's width allows — never more than there is content for, and never
  more than fits, since a box wider than the screen wraps every line and shreds
  the display it is drawn into. The height is then the tallest column's, not
  the cap. One column reduces to exactly the old geometry, and there is a test
  for each.
- **It pages, it does not scroll, and that is forced.** In a column-major grid
  a cell's column is `(slot - offset) / body`: move the offset by less than a
  whole column and every entry changes column, move it by exactly one and every
  entry moves one column left. **Reading down a column and nothing jumping
  between columns cannot both hold while a flat list slides through a grid** —
  the first arrangement was column-major with the keys stepping one entry, which
  walks every counter across the panel and reads as numbers duplicating
  themselves from one column into the next; the second was row-major with the
  keys stepping a whole grid row, which pins each counter to a column at the
  price of reading every group across. The way out is that the content is never
  slid, it is replaced: a page is a screenful, every movement key moves a page,
  and the fill inside a page is column-major again. `page 1/1` is not printed —
  one page is not a control — which is the state the panel is normally in while
  a title runs.
- **Columns are filled like a newspaper, and every one of them is titled.** A
  section flows down the current column and starts a fresh one when what is left
  will not hold it, *unless* a whole column would not hold it either, in which
  case moving it gains nothing — with a widow rule (`MIN_KEEP = 3`) so a heading
  never lands alone at the foot of a column. A section that does spill is
  titled again at the top of each column it continues into (`Slot::Cont`,
  dimmed with an ellipsis). Both together make "a column starts with a heading
  or a continuation" **structural**, and there is a test for it: with `show all`
  the GD group is 79 of the 135 rows and fills three columns on its own, so a
  page of bare `CMD_…` names is otherwise exactly what a reader gets. The whole
  set is two pages of four columns on a 130-column terminal, which is also a
  test.
- **The image is verified before a single number is decoded** (`verify_image`).
  Matching the loader's base is not enough: two builds of the same base put the
  same counter at different addresses, and the values then come back believable
  and wrong. 256 bytes of the first loadable segment are compared against the
  very ELF this host uploaded — including one `loaders::relocate` moved in
  memory, for which there is no file on disk to aim `scripts/dc-counters.py` at.
- **It never blocks the syscall loop.** One `SendBinQ` is posted from the top of
  an iteration; nothing waits for the answer.
- **The answer is claimed in the IO layer, and there is nowhere else it could
  be.** `diag::SampleSink` implements `io::PacketSink` and is registered on the
  connection, so `DcIoUDP::handle_data` — the one funnel every poll site shares
  — takes our replies out before anybody sees them. Filtering in the syscall
  loop instead, which is what this did first, claims **nothing at all**:
  dcload answers a `SendBinQ` only from inside `bb->loop()`, and it is only
  inside `bb->loop()` while it waits for a host transfer to land
  (`cdfs_syscalls.c`: *"bb->loop() is reached from the READ PATH ONLY"*), so the
  reply arrives, every time, in the middle of `send_data`'s own polling — which
  discards what it did not ask for. Measured on a title streaming CD-DA: 43
  samples posted, 43 timed out, the panel permanently empty.
- **What the sink claims is decided by the ADDRESS, for both kinds of packet,
  and getting that wrong breaks the disc read the title is blocked on.** The
  `SendBinary` half was always right — eating somebody else's is a transfer that
  never completes. The `DoneBinary` half was a heuristic ("some of our data has
  landed"), which is true for essentially the whole life of a sample, and it
  failed in **both** directions at once. Measured 2026-08-30 on Sonic Adventure:
  the game stopped for about ten seconds every two seconds, once per sample.
  A sector transfer's `DoneBinary` was swallowed, so `request_donebin` timed out
  (`No DoneBinary response received`), the host abandoned the read and the
  loader sat out its own 6 s timeout before re-requesting; and our terminator
  leaked the other way once a sample had completed on its last `SendBinary`
  (`pending` is `None` by then, so the old rule refused it) — and `cmd_sendbinq`
  used to close with `address = 0, size = 0`, which is byte for byte what a
  **complete** LoadBinary window answers. The host read that as "nothing missing
  anywhere: done" and credited a sector read that still had holes in it.
  dcload now names the range it served in that terminator (loader's AGENTS.md
  §8), so the rule here is one line: a packet is ours if its address is inside
  the range we asked about. The two cannot collide — a transfer's `DoneBinary`
  names a game buffer or nothing, ours names loader RAM, and the footprint rule
  is precisely that a title's buffers are not where the loader is. **The
  terminator is claimed whether or not a sample is still open**, because that is
  the case that leaked. This needs a loader built from the current tree
  (`loaders-diag/`); an older one closes with 0/0 and the leak comes back, and
  the image check cannot see it — it compares each loader against its own ELF.
- **A title that has stopped reading answers nothing**, because dcload is then
  not looking at the wire at all. That is the normal state of a freeze, which is
  also when the counters would say the most; the panel says so after three
  missed samples rather than showing an empty box. **There is no good answer to
  this yet.** The DC-side flag that exists for it,
  `GD_SERVICE_EVERY_SYSCALL=1`, kills Sonic Adventure — measured, isolated, and
  written up at the flag in `cdfs_syscalls.c` and in the loader's AGENTS.md
  §4.5. So the counters are readable while a title still reads its disc, and go
  quiet exactly when it stops; treat the last sample before the silence as the
  measurement.
- **The read is asked for ONE PACKET AT A TIME, and every ask is
  retransmitted.** Measured on a console running Snow Surfers: a 1456-byte
  `SendBinQ` — three frames back to back, emitted from inside a nested
  `bb->loop()` — was answered **zero times out of three**, while
  `verify_image`'s 256-byte read of the same loader, one `SendBinary` plus one
  `DoneBinary`, succeeded moments earlier and the title's own `LoadBinary`
  echoes kept coming from that same loop. So the in-game read is now the shape
  of the read that is known to work, and it is re-sent every 300 ms until it
  lands: one datagram with no acknowledgement, on a link where the RX ring
  overflowing is documented as normal back-pressure, was the one request in
  this host that never retried.
- **On the first miss the probe runs a CONTROL read** of the exact range
  `verify_image` already read back, and says which side is at fault: answered
  means the counter range is the problem, unanswered means the console does not
  answer `SendBinQ` while that title runs, whatever the address. It runs once.
- **A missed sample is two different faults and the panel cannot tell them
  apart**, so `-vv` says which: `diag: sample timed out -- N/M bytes landed`.
  Zero bytes means dcload never answered (it looks at the wire only from inside
  `bb->loop()`); some bytes means the run was spliced, which is a transport
  problem. `SAMPLE_TIMEOUT` is 5 s and generous on purpose — it bounds how long
  a reply may sit behind other traffic before this host reaches it, not the
  console's turnaround, and at 1.5 s it abandoned replies that then arrived.
- **The interval is the whole cost.** 2 s by default, `+`/`-` in the panel,
  floored at 250 ms. Measured against the same session with no panel: nothing
  measurable at 2 s, 0.5 % of one core at the floor.
- Raw mode belongs to `console::Term::read_key`, which raises SIGINT itself
  rather than handing us `Key::CtrlC` — so the Ctrl-C report still happens. Do
  not swap in `read_key_raw`. `ui::restore_terminal` covers the endings that do
  not go through it.

**In-game loading has its own bar** (`ui::LoadMonitor`), and its shape is
dictated by the protocol:

- **The unit is the burst, not the request.** dcload fetches at most
  `GD_EMU_ASYNC` = 8 sectors (16 KiB) per `ReadSector`, so a level load is
  a hundred small requests back to back. The monitor accumulates
  consecutive reads and shows one bar for the burst.
- **There is no percentage or ETA, on purpose.** The GD command knows how
  many sectors it wants (`_GDS.param[1]` on the DC), but the wire carries
  only the chunk being fetched. The host cannot know the total, so the
  bar shows bytes read, elapsed time and the burst's average rate — no
  invented progress. Making it a real percentage would mean sending the
  command's total sector count from the DC, which is a protocol change.
- **The bar is only updated after the ReturnValue goes out.** Until then
  the title is parked in `bb->loop()` waiting for its data; anything done
  before that — a redraw included — is time the game spends frozen.
- Thresholds, both overridable: `DCLOAD_LOAD_BAR_KB` (default 256, the
  burst size that earns a bar; **0 disables the feature entirely**) and
  `DCLOAD_LOAD_IDLE_MS` (default 250, the silence that ends a burst).
- `receive_syscalls` now polls with a timeout **only while a burst is
  open** (`LoadMonitor::poll_timeout`), so the bar can be taken down when
  the loading stops. With no burst in flight — the normal state of a
  running title, and always when the feature is disabled — it blocks
  forever exactly as it did before. A `TimedOut` from that poll is not an
  error and must not be logged as one.

If you have no Dreamcast and no emulator that speaks the dcload
protocol, the only thing you can do is `cargo build` and read the
code. There is no way to run the host side against a simulated DC
without writing one.

## Gotchas

- **A region the relocator classifies by a fixed page goes stale when a buffer
  grows, and it fails CLOSED.** `relocate` sorts every relocation into one of
  the loader's four regions by the value of the symbol it names, and refuses
  what it cannot place rather than guessing -- which is right. But `.hiram` was
  classified by one 4 KB page while the layout reserves `HIRAM_RESERVED`
  (12 KB), and CD-DA's 7 KB staging buffer took the section to ~10 KB. From
  that commit on, `__hiram_end` (0x2790 past the start, named by `crt0`'s
  zeroing loop) belonged to no region and **the relocatable loader would not
  relocate to any base at all**. Found by
  `relocating_reproduces_every_native_link_byte_for_byte` -- run it against a
  freshly built set, `DCLOAD_LOADER_DIR=…/target-src/dcload/loaders cargo test
  relocating_reproduces`, because the set in `loaders/` is whatever was
  deployed and can be older than the tree. Nothing on a console would have
  found it: the failure is a message before the upload.

- **An LBA inside a disc's filesystem is NOT an LBA `read_sector` takes.**
  `DiscFormat::fs_lba` converts, and the difference is 150 on a `.gdi` and a
  `.iso` and zero on a `.cdi`: a GDI records track starts without the
  150-sector lead-in and the reader adds it back, but the ISO9660 structures on
  a GD-ROM are mastered in that same lead-in-less numbering. Measured on the
  Sonic Adventure PAL GDI: root directory extent recorded as LBA 45020, read at
  45170; `1ST_READ.BIN` recorded at 545711, read at 545861. **Getting it wrong
  is silent** — the directory walk simply finds nothing, which reads exactly
  like "this disc has no files on it". Anything that takes an LBA out of a
  PVD or a directory record goes through `fs_lba` first, once, in
  `iso9660.rs`, so nothing downstream has to remember.

- **A stock debug build makes the disc look like a slow network.**
  Measured on the 1.10 GiB Sonic Adventure 2 track read over SMB, same file,
  same share, same run: release indexes it in 4.6 s (inflate 3.73 s, crc
  0.49 s), an unoptimised debug build in 40.5 s (inflate 33.58 s, crc 6.30 s).
  The reader threads waited 0.07 s in BOTH -- the wire was idle, being fed by a
  consumer running at 29 MiB/s, and the network graph showing ~230 Mbps was the
  symptom, not the cause. `Cargo.toml` therefore builds `miniz_oxide` at
  opt-level 3 and this crate at 1 even in dev, which brings the debug build to
  5.7 s and keeps backtraces. Before blaming storage for a slow index pass,
  read the `waited ... / inflate ... / crc ...` line the pass prints at debug
  level: it says which of the three it was. `examples/readbench.rs` measures the
  storage itself (`--direct` bypasses the client cache) if you still suspect it.

- **A disc read is one read per REQUEST, not one per sector.**
  `Gdi` and `Cdi` resolve the track once, work out how much of the request that
  track answers, and issue a single positioned read for the whole run when the
  track stores plain 2048-byte sectors. Only a raw track (2336/2352/2448, where
  the user bytes are surrounded by sync, subheader and ECC) still goes sector by
  sector. This matters because the title is FROZEN for the whole syscall, and a
  128-sector read used to be 128 lookups and 128 reads. Two things must stay
  true if you touch it: a request that spans two tracks falls back to the
  per-sector path (a `.gdi` with a data track either side of the audio is
  normal), and `FileSource` reads by POSITION (`pread`/`ReadFile`-with-offset),
  so there is no shared cursor to seek and no `RefCell` in the read path.

- **A name out of a dump is not a path, and not a member name either.**
  Three separate untrusted-string rules, each where the string is produced:
  `source::plain_track_name` (a `.gdi` names its tracks as bare filenames --
  an absolute one would make `Path::join` throw the dump directory away and
  serve `C:\Windows\...` to the title as sectors), `iso9660::boot_file_name`
  (IP.BIN's sixteen bytes are returned only if they spell an ISO9660 filename),
  and `main::safe_output_name` (what `extract` will write to when `-o` is
  absent). `ZipArchive::find` is EXACT plus case, because it resolves the
  `archive.zip#member` the user typed; the basename tolerance a `.gdi`'s track
  names need lives in `find_track`, so a mistyped member is an error rather
  than a quietly different file.

- **A scrambled boot binary uploads perfectly and executes noise.**
  A binary meant to boot from a CD-R is stored with its 32-byte slices
  permuted; the disc's own IP.BIN bootstrap unpermutes it while loading, and
  this host never runs that bootstrap — it enters the binary directly, as
  isoldr does. A `.gdi` off a GD-ROM is never scrambled; a `.cdi` self-boot
  conversion usually is. Detection is ONE-SIDED on purpose
  (`disc_formats::scramble`): the permutation preserves every byte statistic,
  so the only thing that can be answered with certainty is "does unscrambling
  it produce a header we recognise", which works for homebrew and not for
  retail. `--descramble always` is the escape hatch, and the symptom that calls
  for it is a title that uploads, verifies, and then does absolutely nothing.
  isoldr has the same gap and answers it the same way.

- **The first read of a DEFLATED zip member costs a full inflate.**
  4.7 s for the 1.10 GiB Sonic Adventure track, with a progress bar. It happens
  before the title starts, the index is cached for the life of the process (the
  image itself is opened once and the reader handed to identify, the boot
  binary, IP.BIN and the syscall loop — see `main`), and it is what verifies the
  member's
  CRC-32. If you are iterating and the wait annoys you, **`zip -0` makes it
  vanish**: a stored member is read in place with no index, no RAM and no
  start-up cost, and the archive still keeps the CRC and the filenames
  together. The checkpoint table costs up to 64 MiB of RAM PER INDEXED MEMBER
  (nothing is evicted, and in practice only the track being read is indexed);
  that is a LATENCY knob, not a memory one, and `DCLOAD_ZIP_INDEX_BUDGET` (MiB)
  moves it.

- **That pass was 13 s and the reason was not the one anybody guessed.**
  Reading the compressed bytes was 58 % of it and inflating them 37 %. Two
  measurements settled it: this mount serves 211 MB/s to one reader and
  467 MB/s to four, and the textbook byte-at-a-time CRC-32 was costing ~3 s on
  its own. So the bytes are now read ahead on four threads (the decoder waits
  0.04 s in total) and the CRC folds sixteen bytes at a time. **Do not
  micro-optimise the decoder loop before re-reading the split** — the index
  pass prints `waited … / inflate … / crc …` at debug level for exactly this
  reason, and a bigger output ring was tried against it and moved nothing.

- **A deflate cursor cannot go backwards, so the number of them is a cliff.**
  `CURSORS` in `deflate.rs` is how many places in the stream stay open. With
  three files read round-robin, one or two cursors give 3.6 ms per 16 KiB and
  four give 0.35 ms — there is no middle. It is set to eight because a spare
  costs 288 KiB and being one short costs a factor of ten. If a title ever
  looks like it is seeking constantly on a zipped image, that is the first
  number to raise.

- **The `test/` directory is intentionally not a Cargo test target.**
  It is git-ignored, contains Dreamcast payload data, and is one rename
  away from being picked up as a Cargo integration-test folder. Don't
  rename it to `tests/` without first moving the contents somewhere
  else and updating `.gitignore`. If you do rename it, expect a baffling
  `cargo test` failure that points at `*.klf` / `*.vmd` / `*.bmp` as if
  they were Rust sources.

- **`cdi2iso.c` at the repo root is untracked third-party GPLv2 code**
  (Salvatore Santagati, 2004). It is *not* compiled by `cargo`; nothing
  in `Cargo.toml` references it. It is a small standalone helper for
  converting `.cdi` disc images to `.iso` and exists in the tree as
  reference material. Keep it for reference, or delete it per project
  policy, but do not add it to the build (`build.rs`, `[[bin]]`,
  `[features]`, etc.) without first checking the GPLv2 implications.

- **ELF upload honours section addresses, and only allocated ones.**
  `loaders::is_uploadable` gates on SHF_ALLOC and a non-zero `sh_addr`, not on
  `SHT_PROGBITS` alone. The old filter logged "skipping" and then pushed the
  section anyway, so `.symtab`, `.strtab`, `.shstrtab` and `.comment` -- all at
  address 0 -- were uploaded to the bottom of the Dreamcast's address map on
  every ELF. It went unnoticed because the usual input is a raw `1ST_READ.BIN`,
  which takes the non-ELF path.
 The CLI `--address` default
  is `0x0c010000` (a typical Dreamcast load address), but if the input
  is an ELF, `dispatch::upload` overrides it with `e_entry` from the
  ELF header. Pass `--address` only when uploading a raw `.bin` blob.

- **Network is UDP and the binary is opinionated about pacing.**
  `dispatch::send_data` inserts a `1 ns` sleep between every PBIN
  packet and a longer sleep every `burst_packets` packets. This
  matters for runtime CDFS transfers (where the DC is asking for
  many chunks back-to-back) and is why the burst sizes differ
  between the upload-progress path (15 packets / 2 ms) and the
  syscall-response path (10 packets / 1.8 µs). If you ever change
  `CHUNK_SIZE` — which also changes the `PartBinary` payload size,
  not just the protocol version — expect to re-tune the pacing.

- **`-d` and `-m` silently turn on `-c`.** The CLI exposes `-c` as a
  separate flag, but the code (`main.rs`, `UExec` arm) sets
  `console = true` whenever `disc.is_some() || mount.is_some()`.
  There is no warning. If you want CDFS or host-FS redirection
  without console mirroring, you can't get it from the CLI today.

- **Many syscalls return errors as `u32::MAX`, not `Err`.** The DC's
  syscall ABI encodes errors directly in the return value's
  `address` / `size` fields. If you are changing `fs.rs` and the
  DC is misbehaving, double-check the return shape before assuming
  a panic or a real `Err`.

- **Editor folders `.continue/` and `.zed/` are local config.** They
  contain MCP server / debug configuration tied to the original
  dev machine. `.vscode/launch.json` references personal IPs
  (`192.168.1.64`) and personal Windows paths. None of these should
  be committed as-is.

- **Big-endian everywhere on the wire, except where it isn't.**
  `DCLoadCmd` headers, `PartBinary` / `SendBinary` payloads, and
  all syscall parameters are big-endian. The TOC (`src/cd.rs`) and
  the `DCLoadStat` / `DCLoadDirEnt` wire structs are little-endian
  because the DC reads them native. If you add a new command or
  field, match the convention of the nearest existing code rather
  than guessing.

- **No CI, no formatter config, no linter config.** No `.github/`,
  no `rustfmt.toml`, no `clippy.toml`. `cargo fmt` and `cargo clippy`
  will run but follow only the default rules. There is no canonical
  style enforced in CI.
