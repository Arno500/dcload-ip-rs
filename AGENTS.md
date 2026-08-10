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
versions of `clap`, `elf`, `polling`, `indicatif`, `pretty_env_logger`.

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
3. **Upload phase** (`src/dispatch.rs::upload`):
   - If the input is an ELF, parse it with the `elf` crate, walk
     `SHT_PROGBITS` sections, and upload each section to the address
     recorded in its section header. The CLI `--address` value is used
     only as a fallback entry point for non-ELF blobs.
   - For every chunk, we send `LoadBinary` (`LBIN`) once, then a stream of
     `PartBinary` (`PBIN`) packets — each one a fixed-size, zero-padded
     slice — paced with a small sleep and a longer sleep every
     `burst_packets` (10 in the syscall hot path, 15 during initial
     upload). Pacing exists to keep the DC's RX FIFO from drowning during
     runtime CDFS transfers.
   - After `DoneBinary` (`DBIN`), the DC tells us about any missing
     bytes; we re-send those chunks and repeat `DBIN` until the DC is
     satisfied.
4. **Execute phase** (`dispatch::execute`): send `Execute` (`EXEC`) with
   the entry point and a flag byte. `cdfs_redirect` is bit 1, `console`
   is bit 0. Any of `-d` / `-m` / `-c` forces `console` to true; the
   code does not let the user run with CDFS or host-FS redirection but
   no console mirror.
5. **Syscall phase** (`dispatch::receive_syscalls`): an infinite loop
   that answers `ReadSector` (sector data from a `.iso` / `.gdi` /
   `.cdi` image), `ReadToc` (the synthesized DC TOC, see `src/cd.rs`),
   and `FSCommand` (host file/dir syscalls routed through `src/fs.rs`).
   The loop exits cleanly only on the `DC00` `Exit` syscall; if the DC
   goes silent it will spin in `await_result` until the next packet
   arrives.

`upload` (no execute) does steps 1-3 only. `reboot` is a single `RBOT`
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

There are **no Rust unit or integration tests** — `grep "#\[test\]" src/`
returns nothing and the crate has no `[lib]` target where tests could
hide. `cargo test` will build the test harness and find zero tests; that
is not a bug, that is the project.

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

- **`src/main.rs`** — entry point. Defines the `Args`/`Commands` clap
  structs, sets up logging (`pretty_env_logger`, `-v`/`-vv` for
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
  jumps between track files at the right offsets; `Cdi` parses
  DiscJuggler images. The dispatch in `receive_syscalls` chooses by
  extension on the `-d` path: `.gdi` → `Gdi::new`, `.cdi` → `Cdi::new`,
  anything else → `Iso::new` (which then warns and disables CDFS if
  it can't find a PVD). `StubDisc` is the placeholder used when `-d`
  wasn't passed — its `read_sector` returns an error.

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
The progress bars (`indicatif`) and the pretty_env_logger output
co-exist; the bar suppresses itself under 10 KB to keep the logs
readable.

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

- **ELF upload honours section addresses.** The CLI `--address` default
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
