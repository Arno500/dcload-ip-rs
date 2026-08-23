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
versions of `clap`, `elf`, `polling`, `indicatif`, `console`,
`pretty_env_logger`. (`console` is indicatif's own terminal backend; it is
declared directly so `src/ui.rs` can ask how wide the terminal is.)

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

4. **Upload phase** (`src/dispatch.rs::upload`):
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
- `cargo run -- u-exec --host <DC_IP> <1ST_READ.BIN|loader.elf>` — upload
  and execute. Typical use against a real DC on the same LAN. Add any
  combination of:
  - `-d <disc.{gdi,cdi,iso}>` — redirect CD-ROM reads to a host disc
    image. The format is chosen by extension; see "Disc formats" below.
  - `-m <host_dir>` — serve a host directory in place of the DC's
    filesystem. Paths are sandboxed; see `fs.rs::join_and_check_path`.
  - `-c` — mirror the DC's `stdout` / `stderr` over UDP into our
    own log. The CLI lets you pass `-c` on its own, but `-d` and `-m`
    silently turn it on too — there is no "CDFS without console"
    mode.
- `cargo run -- upload --host <DC_IP> <file>` — upload only. Useful for
  inspecting a payload without booting it.
- `cargo run -- reboot --host <DC_IP>` — single `RBOT` packet. Only
  honoured by dcload, not by a real game.
- `cargo run -- -h` — full CLI help. Subcommands are defined with
  `clap` derives in `src/main.rs`.

There is no `make`, no `xtask`, no installer. Everything happens through
`cargo` and the resulting binary in `target/{debug,release}/dcload-ip-rs`.

## Tests

There are unit tests in `src/presets.rs` and `src/loaders.rs` only -- the
lookup rules and the chainload plan, which are pure functions over data and so
are the only part of this crate that can be tested without a Dreamcast.
Everything else still needs real hardware or an emulator. `cargo test` runs
them; there is no `[lib]` target and no integration-test directory.

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

- **`src/disc_formats/`** — three format readers and a trait
  (`DiscFormat` in `types.rs`). `Iso` wraps a single `File` and does
  range seeks for `read_sector`; `Gdi` walks the `.gdi` track list and
  jumps between track files at the right offsets; `Cdi` parses the
  DiscJuggler descriptor block at the END of the file and maps LBAs
  through the resulting track table. `open_disc` (in `dispatch.rs`)
  chooses by extension on the `-d` path: `.gdi` → `Gdi::new`, `.cdi` →
  `Cdi::new`, anything else → `Iso::new`. `StubDisc` is the placeholder
  used when `-d` wasn't passed — its `read_sector` returns an error.

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
  the three cases — path does not exist, format not understood, opens but
  holds no Dreamcast header — are distinguished. They used to collapse into
  one `None` that `identify_disc` printed as "no readable IP.BIN in <path>",
  and a `.gdi`/`.cdi` that failed to open fell through to `StubDisc` with
  nothing logged, so a mistyped `-d` gave a whole session with CDFS silently
  dead.

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
