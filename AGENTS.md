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
`miniz_oxide`, `pretty_env_logger`. (`console` is indicatif's own terminal
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
   continue if the DC doesn't answer.
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
probe, and everything that turns bytes on disk into sectors. That last group is
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
  which aggregates a running title's disc reads into "loading" bursts.

- **`src/presets.rs`** — the per-game settings table carried over from
  DreamShell's isoldr presets, and the disc identity (IP.BIN fields plus the
  boot-sector MD5) used to look a game up in it. Two-tier matching, and the
  vocabulary for saying which tier answered. Unit-tested.

- **`src/loaders.rs`** — everything about *where* the Dreamcast-side loader
  lives: parsing the base out of the VERS reply, finding the ELF for a base,
  the memory a running loader is using (`live_footprint`, which is a LIST of
  ranges and the reason a direct chainload to 0x8cfe8000 is refused), and the
  hop plan. Unit-tested.

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
  (`poll`, `handle_data`, `send_command`) with a single implementation
  `DcIoUDP` that wraps a non-blocking `UdpSocket` registered with the
  `polling` crate. There is no other transport, no loopback, no
  test-only implementation — anything you want to test has to go
  through a real UDP socket or a DC.

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
