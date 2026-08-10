# `.zed/debug.json` notes

Sidecar for the Zed debug configurations. `.zed/debug.json` itself is plain
JSON (JSON has no comment syntax), so the `// ...` alternates that used to
live in `.vscode/launch.json` are collected here. When you want to switch
a config to one of these variants, edit the `args` array of the relevant
entry in `debug.json` directly.

All paths assume a Windows host with `arnod` as the user. Adjust as
needed.

---

## `Launch Sonic Adventure`

The `//` lines from the original VSCode config (not currently active):

- `--address 0xac010000`
- `--address 0x8c010000`
- Crazy Taxi payload path:
  `C:\Users\arnod\Downloads\Crazy Taxi v1.000 (2000)(Sega)(PAL)[!]\1ST_READ.BIN`
- Crazy Taxi disc path:
  `C:\Users\arnod\Downloads\Crazy Taxi v1.000 (2000)(Sega)(PAL)[!]\Crazy Taxi v1.000 (2000)(Sega)(PAL)[!].gdi`
- Unscrambled SA bin:
  `C:\Users\arnod\Downloads\Sonic Adventure v1.003 (1999)(Sega)(PAL)(M5)[!]\1ST_READ_UNSCRAMBLED.BIN`
- ELF fallback:
  `C:\Users\arnod\Documents\Dreamcast\loader.elf`
- `-m test` flag (host-FS mount, see "Run Dreamshell" for the `-m` flag shape)

## `Launch Sonic Adventure International`

The `//` lines:

- `--address 0xac010000`
- `--address 0x8c010000`

## `Launch Sonic Adventure CDI`

The `//` lines:

- `--address 0xac010000`
- `--address 0x8c010000`

## `Launch Crazy Taxi`

The `//` lines:

- `--address 0xac010000`
- `--address 0x8c010000`

## `Run updated dc-load-ip`

The `//` lines:

- `--address 0x8ce00000`
- `-m test` flag

## `Run Dreamshell`

The `//` lines:

- `--address 0xac010000`
- Crazy Taxi disc:
  `C:\Users\arnod\Downloads\Crazy Taxi v1.000 (2000)(Sega)(PAL)[!]\Crazy Taxi v1.000 (2000)(Sega)(PAL)[!].gdi`
- SA PAL disc:
  `C:\Users\arnod\Downloads\Sonic Adventure v1.003 (1999)(Sega)(PAL)(M5)[!]\Sonic Adventure v1.003 (1999)(Sega)(PAL)(M5)[!].gdi`

---

## About `--address`

`--address` is the CLI fallback entry point for raw `.bin` uploads. The
code overrides it with `e_entry` from the ELF header when the input is an
ELF, so for `loader.elf` and `DS.elf` it has no effect — that's why the
dreamshell/loader configs only carry a single commented-out value each.

## About `DCLOAD_IP_RS_TRACE_STALL`

The first three configs (`Launch Sonic Adventure`,
`Launch Sonic Adventure International`, `Launch Sonic Adventure CDI`) set
`DCLOAD_IP_RS_TRACE_STALL=1`. The other three do not. If you want to
diagnose a stall on a non-SA target, add the env var to that config's
`env` block.

## About the field renames (VSCode → Zed)

- `name` → `label`
- `type: "lldb"` → `adapter: "CodeLLDB"`
- `${workspaceFolder}` → `$ZED_WORKTREE_ROOT`
- `cargo: { args, filter }` → `build: { command: "cargo", args: ["build"] }`
  (Zed auto-locates the single binary; `--bin`/`--package` filters are
  redundant since `Cargo.toml` defines exactly one `[[bin]]` and no
  library)
- `program` is set explicitly to `$ZED_WORKTREE_ROOT/target/debug/dcload-ip-rs`
  on every config — Zed's schema requires it even though the docs say it's
  optional when using `cargo build`
- root-level `setupCommands: ["set target-async off"]` → per-config
  `initCommands: ["settings set target.run-async false"]` (modern alias of
  the same setting; Zed has no global setupCommands)
- `stdio: ""` and `terminal: "integrated"` → omitted (Zed defaults route
  stdio to the debug console and use the built-in terminal panel)
