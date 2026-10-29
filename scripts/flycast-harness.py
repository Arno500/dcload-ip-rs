#!/usr/bin/env python3
"""Run disc images under flycast through dcload-ip-rs, unattended, and judge
each one: did it boot, does it still draw, does it still read its disc.

    py scripts\\flycast-harness.py "V:\\...\\Jet Set Radio (PAL).zip"
    py scripts\\flycast-harness.py --dir "V:\\...\\Collection" --match Sonic --duration 180
    py scripts\\flycast-harness.py --list scripts\\flycast-games.txt
    py scripts\\flycast-harness.py game.gdi --input 40000:start,45000:start,50000:a:250 -- --vga never

Everything after `--` goes to `u-exec` (after the image). Run it with the
Windows Python, not from WSL: the emulator, the host tool and the GDB stub are
all Windows-side, and every WSL->Windows hop in the loader repo's scripts cost
time (mirrored networking black-holes SYNs to closed ports) or hung
(`powershell.exe Start-Process`, sa-repeat.sh).

ONE RUN
  1. kill any flycast.exe / dcload-ip-rs.exe (two flycasts share one BBA MAC
     and both answer the host);
  2. re-assert `LogToFile` and `Debug.GDBEnabled` in emu.cfg (flycast drops
     them when it rewrites the file), clear flycast.log;
  3. start flycast on the dcload CDI, wait for the GDB stub (:3263) and detach
     from it: a GDB-server build starts halted;
  4. wait for the guest's first frame on the bridge ("using capture device"),
     warm the host's neighbour entry for the console (Windows drops datagrams
     while it resolves the MAC);
  5. `dcload-ip-rs identify`, then `u-exec` with `-i`, logging to host.log;
  6. after "executing at", watch for --duration seconds: the framebuffer over
     the GDB stub (one short attach per probe: an attached debugger halts the
     guest), disc reads (TRACE lines of `dispatch::sectors`), the host's
     warnings and exit, and flycast.log's resets; press keys from --input
     (TIME:KEY[*COUNT][:HOLD], milliseconds after EXEC, HOLD how long it is held);
  7. write result.json, screenshots and the logs to the run's directory.

VERDICTS, first match wins
  HARNESS    flycast, its stub or the console's first frame never came up
  NO_LOADER  the host never got past the handshake
  NO_EXEC    the host exited, or the deadline passed, before EXEC
  BIOS_MENU  `SYS_MISC 1` then `REIOS: Booting up` after EXEC (syBtExit)
  CRASH      `REIOS: Booting up` alone after EXEC (the SH4 ran address 0), or
             flycast died
  EXITED     the title made the Exit syscall (homebrew ending normally: rc 0)
  SILENT     the host ended the session after EXEC (keepalive: the console
             stopped answering) or failed
  LOADER_HIT the loader's code in RAM no longer matches its relocated ELF: the
             title wrote over it (with the CPU's PC, named if in the loader)
  BLACK      the screen never lit after the grace period
  FROZEN     neither the picture nor the disc reads changed for --freeze-after
  RUNNING    none of the above: a pass

The learned memory map (game-memory.tsv) is COPIED into each run and passed
with --memory-db, so a batch of experiments does not teach the real map what an
emulator run saw; --learn writes to the real one. RetroAchievements and the
VM2 scan are off (--ra to keep RA: it reports to retroachievements.org), and so
is the host's keepalive, which ended a live flycast session at a title screen
(--host-global "--keepalive 10" to keep it).
"""
import argparse
import ctypes
import datetime as dt
import json
import os
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import time
import zlib
from ctypes import wintypes
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_FLYCAST_DIR = Path(r"C:\Users\arnod\Code\flycast\build\RelWithDebInfo")
# Both built by scripts/flycast-build-loader.sh with a STATIC address: DHCP does
# not complete through flycast's BBA bridge on this machine, and a CDI built for
# DHCP sits on its DHCP screen forever.
DEFAULT_CDI = Path(r"C:\Users\arnod\Documents\Dreamcast\dc-load\dcload-flycast.cdi")
DEFAULT_LOADER_DIR = REPO / "loaders-flycast"
DEFAULT_DC_IP = "192.168.1.130"
IMAGE_SUFFIXES = {".gdi", ".cdi", ".zip", ".iso", ".chd"}

GDB_PORT = 3263
DCLOAD_PORT = 53535

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
LEVEL = re.compile(r"\b(ERROR|WARN|INFO|DEBUG|TRACE)\b")


def log(msg):
    print(f"[{dt.datetime.now():%H:%M:%S}] {msg}", flush=True)


def slug(text, limit=60):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")
    return s[:limit] or "image"


# --- processes ---------------------------------------------------------------

def running(image_name):
    out = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {image_name}", "/NH", "/FO", "CSV"],
                         capture_output=True, text=True, timeout=30).stdout
    return [int(row.split('","')[1]) for row in out.splitlines() if row.startswith('"')]


def kill_all():
    """Kill and VERIFY: a survivor holding :3263 plus a fresh instance means two
    emulated consoles on one MAC, and a run nobody can reproduce."""
    for name in ("dcload-ip-rs.exe", "flycast.exe"):
        for _ in range(10):
            if not running(name):
                break
            subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True, timeout=30)
            time.sleep(0.3)
        if running(name):
            raise HarnessError(f"{name} survived taskkill; refusing to start another")


def close_flycast(timeout=8.0):
    """Ask every flycast window to close before anything kills it. flycast
    writes a VMU block with an unflushed `fwrite` and flushes only at `fclose`,
    so `taskkill /F` drops the last writes of a run: the card left behind had
    a directory naming blocks its FAT gave to the next title's file (2026-10-29,
    Crazy Taxi's file over Super Mario 64's, "Échec du chargement" at boot,
    Sonic Adventure hanging on "create file 1")."""
    pids = running("flycast.exe")
    for pid in pids:
        hwnd = flycast_window(pid)
        if hwnd:
            ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
    deadline = time.monotonic() + timeout
    while pids and running("flycast.exe") and time.monotonic() < deadline:
        time.sleep(0.25)


def cdi_product(cdi):
    """The product number of the dcload CDI's IP.BIN: flycast names the per-game
    A1 card after it (`<product>_vmu_save_A1.bin`)."""
    with open(cdi, "rb") as fh:
        data = fh.read(8 << 20)
    at = data.find(b"SEGA SEGAKATANA ")
    if at < 0:
        return None
    return data[at + 0x40:at + 0x4a].decode("ascii", "replace").strip() or None


def fresh_card(flycast_dir, cdi, out_dir):
    """Give the run a blank A1 card: the one left by earlier runs goes into the
    run's directory (vmu-A1-before.bin) and flycast formats a new one, so a
    title meets the same card every run and a save one run broke cannot fail
    the next. Returns the card's path, copied out as vmu-A1-after.bin later."""
    product = cdi_product(cdi)
    if not product:
        log(f"WARNING: no IP.BIN product in {cdi}; the A1 card is left as it is")
        return None
    name = re.sub(r'[ /\\:*?|<>"]', "_", product) + "_vmu_save_A1.bin"
    card = flycast_dir / "data" / name
    if card.exists():
        shutil.move(str(card), str(out_dir / "vmu-A1-before.bin"))
    return card


class HarnessError(Exception):
    pass


# --- flycast configuration and log -------------------------------------------

def assert_emu_cfg(flycast_dir):
    """flycast rewrites emu.cfg on a clean exit and drops `LogToFile` (read but
    not a registered option) and has been seen to put `Debug.GDBEnabled` back
    to `no`. Either one silently removes an instrument this harness reads."""
    cfg = flycast_dir / "emu.cfg"
    text = cfg.read_text(encoding="utf-8", errors="replace")
    orig = text
    if not re.search(r"^LogToFile = yes$", text, re.M):
        if re.search(r"^LogToFile = .*$", text, re.M):
            text = re.sub(r"^LogToFile = .*$", "LogToFile = yes", text, flags=re.M)
        else:
            text = re.sub(r"^\[log\]$", "[log]\nLogToFile = yes", text, count=1, flags=re.M)
    if not re.search(r"^Debug\.GDBEnabled = yes$", text, re.M):
        if re.search(r"^Debug\.GDBEnabled = .*$", text, re.M):
            text = re.sub(r"^Debug\.GDBEnabled = .*$", "Debug.GDBEnabled = yes", text, flags=re.M)
        else:
            text = re.sub(r"^\[config\]$", "[config]\nDebug.GDBEnabled = yes", text, count=1,
                          flags=re.M)
    if text != orig:
        cfg.write_text(text, encoding="utf-8")
        log("emu.cfg: re-asserted LogToFile / Debug.GDBEnabled")


class Tail:
    """Lines appended to a file since the last call; tolerates the file not
    existing yet and a partial last line."""

    def __init__(self, path):
        self.path = Path(path)
        self.pos = 0
        self.partial = ""

    def lines(self):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.pos)
                data = fh.read()
        except OSError:
            return []
        self.pos += len(data)
        text = self.partial + data.decode("utf-8", errors="replace")
        parts = text.split("\n")
        self.partial = parts.pop()
        return [ANSI.sub("", p.rstrip("\r")) for p in parts]


# --- network -----------------------------------------------------------------

def port_open(port, timeout=0.25):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=timeout).close()
        return True
    except OSError:
        return False


def neighbour_state(ip):
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-NetNeighbor -IPAddress {ip} -ErrorAction SilentlyContinue"
             " | Select-Object -First 1).State"],
            capture_output=True, text=True, timeout=15).stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    return out.splitlines()[0] if out else ""


def warm_neighbour(ip, attempts=10):
    """The host tool's first datagrams are dropped while Windows resolves the
    console's MAC, and an entry left Unreachable black-holes them for longer.
    A 12-byte datagram to dcload's port is ignored by the loader and exercises
    exactly the path the tool needs (ICMP made things worse: see the loader
    repo's docs/flycast-debug-loop.md)."""
    state = neighbour_state(ip)
    for _ in range(attempts):
        if state in ("Reachable", "Stale", "Permanent"):
            return state
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for _ in range(4):
                s.sendto(bytes(12), (ip, DCLOAD_PORT))
                time.sleep(0.2)
        state = neighbour_state(ip)
    return state


# --- GDB stub: resume and framebuffer ----------------------------------------
#
# The reader follows the loader repo's scripts/dc-screen.py (measured there:
# the stub over-fetches about 4x past 1 KB, and the surplus is real memory).

VRAM64 = 0xA5000000
FB_R_CTRL = 0xA05F8044
FB_R_SOF1 = 0xA05F8050
FB_R_SIZE = 0xA05F805C
BYTES_PER_PIXEL = {0: 2, 1: 2, 2: 3, 3: 4}


class Rsp:
    def __init__(self, timeout=3.0):
        self.sock = socket.create_connection(("127.0.0.1", GDB_PORT), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def send(self, payload):
        b = payload.encode()
        self.sock.sendall(b"$" + b + b"#%02x" % (sum(b) & 0xFF))

    def recv(self):
        while True:
            while self.buf[:1] in (b"+", b"-"):
                self.buf = self.buf[1:]
            start = self.buf.find(b"$")
            if start >= 0:
                end = self.buf.find(b"#", start)
                if end >= 0 and len(self.buf) >= end + 3:
                    pkt = self.buf[start + 1:end]
                    self.buf = self.buf[end + 3:]
                    self.sock.sendall(b"+")
                    return pkt
            more = self.sock.recv(1 << 20)
            if not more:
                return b""
            self.buf += more

    def cmd(self, payload):
        self.send(payload)
        return self.recv()

    def read(self, addr, want):
        out = bytearray()
        while len(out) < want:
            reply = self.cmd(f"m{addr + len(out):x},{min(4096, want - len(out))}")
            if not reply or reply[:1] == b"E":
                break
            try:
                out += bytes.fromhex(reply.decode())
            except ValueError:
                break
        return bytes(out[:want])

    def read32(self, addr):
        b = self.read(addr, 4)
        return int.from_bytes(b, "little") if len(b) == 4 else None

    def detach(self):
        """Always: a connected debugger keeps the guest halted."""
        try:
            self.cmd("D")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def resume_flycast():
    try:
        r = Rsp(timeout=1.0)
    except OSError:
        return False
    r.detach()
    return True


_TABLES = {}


def _table16(fmt):
    t = _TABLES.get(fmt)
    if t is None:
        t = []
        for v in range(65536):
            if fmt == 1:
                t.append(bytes((((v >> 11) & 31) << 3, ((v >> 5) & 63) << 2, (v & 31) << 3)))
            else:
                t.append(bytes((((v >> 10) & 31) << 3, ((v >> 5) & 31) << 3, (v & 31) << 3)))
        _TABLES[fmt] = t
    return t


def _row_rgb(line, fmt, width, step):
    if fmt in (2, 3):
        bpp = BYTES_PER_PIXEL[fmt]
        src = line[:width * bpp]
        out = bytearray(3 * width)
        out[0::3] = src[2::bpp]
        out[1::3] = src[1::bpp]
        out[2::3] = src[0::bpp]
    else:
        table = _table16(fmt)
        out = bytearray().join(table[v] for v in struct.unpack_from(f"<{width}H", line))
    if step == 1:
        return bytes(out)
    thin = bytearray(3 * ((width + step - 1) // step))
    thin[0::3] = out[0::3][::step]
    thin[1::3] = out[1::3][::step]
    thin[2::3] = out[2::3][::step]
    return bytes(thin)


def grab(step):
    """(rows, enabled) of the scanned-out framebuffer, every `step`th pixel, or
    None when the stub cannot be reached or read."""
    try:
        r = Rsp()
    except OSError:
        return None
    try:
        ctrl, sof1, size = r.read32(FB_R_CTRL), r.read32(FB_R_SOF1), r.read32(FB_R_SIZE)
        if None in (ctrl, sof1, size):
            return None
        fmt = (ctrl >> 2) & 3
        bpp = BYTES_PER_PIXEL[fmt]
        width = (((size & 0x3FF) + 1) * 4) // bpp
        height = ((size >> 10) & 0x3FF) + 1
        modulus = (size >> 20) & 0x3FF
        stride = width * bpp
        pitch = stride + (modulus - 1) * 4
        rows = []
        for y in range(0, height, step):
            line = r.read(VRAM64 + sof1 + y * pitch, stride)
            if len(line) < stride:
                break
            rows.append(_row_rgb(line, fmt, width, step))
        return (rows, bool(ctrl & 1)) if rows else None
    except OSError:
        return None
    finally:
        r.detach()


def png(rows):
    width = len(rows[0]) // 3
    raw = b"".join(b"\x00" + row for row in rows)

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, len(rows), 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def lit_percent(rows):
    """Share of pixels with any channel above 24: a dark scene still lights some."""
    lit = total = 0
    for row in rows:
        for i in range(0, len(row), 3):
            total += 1
            if row[i] > 24 or row[i + 1] > 24 or row[i + 2] > 24:
                lit += 1
    return 100.0 * lit / max(1, total)


# --- the loader in RAM: is it still the loader? where is the CPU? -------------
#
# A title that writes over the loader is the failure this project fights most,
# and it does not always look like one: Crazy Taxi PAL with the loader at
# 0x8cfe0000 (2026-10-29) stored 148 bytes into its .text, one run inside
# `_irq_tick`, and the SH4 then executed 0x0000. Under flycast that halts the
# emulator for good -- its GDB server turns an illegal instruction into a
# debugger stop once any client has ever connected (`attached` is only cleared
# when the server thread ends), and the harness connects at least once, to
# resume a GDB-server build -- so the picture freezes and the disc goes quiet
# with nothing in either log. Comparing the loader's code with its relocated
# ELF, and the PC with its symbols, says what happened.

def elf_parts(path):
    """(executable PROGBITS sections as (name, addr, bytes), symbols as sorted
    (addr, name)) of a 32-bit little-endian ELF."""
    elf = Path(path).read_bytes()
    shoff, = struct.unpack_from("<I", elf, 0x20)
    entsize, count, strndx = struct.unpack_from("<HHH", elf, 0x2E)
    heads = [struct.unpack_from("<IIIIIIIIII", elf, shoff + i * entsize) for i in range(count)]

    def cstr(table, off):
        start = heads[table][4] + off
        return elf[start:elf.index(b"\0", start)].decode(errors="replace")

    code, syms = [], []
    for h in heads:
        name, typ, flags, addr, off, size, link = h[:7]
        if typ == 1 and flags & 2 and flags & 4 and size:
            code.append((cstr(strndx, name), addr, elf[off:off + size]))
        elif typ == 2:  # SYMTAB
            for i in range(0, size, 16):
                st_name, value, st_size, info = struct.unpack_from("<IIIB", elf, off + i)
                if st_name and (info & 0xF) in (0, 1, 2):
                    syms.append((value, cstr(link, st_name), info & 0xF, st_size))
    return code, sorted(syms)


def loader_in_log(text):
    """(base, ELF file name) of the loader the host left running, from its log;
    None when it kept the CDI's own (nothing in the set to compare with)."""
    bases = re.findall(r"loader is now at 0x([0-9a-f]{8})", text)
    if not bases:
        return None
    if "loader image: resident with the title's network" in text:
        image = "dcload-resident-net.elf"
    elif "loader image: resident" in text:
        image = "dcload-resident.elf"
    else:
        image = "dcload-relocatable.elf"
    return int(bases[-1], 16), image


def relocated_loader(host_exe, loader_dir, base, image, out_dir):
    out = Path(out_dir) / f"{Path(image).stem}-{base:08x}.elf"
    if not out.exists():
        subprocess.run([str(host_exe), "relocate", str(Path(loader_dir) / image), f"0x{base:08x}",
                        "-o", str(out)], capture_output=True, timeout=60, check=True)
    return out


def loader_damage(elf_path):
    """[(section, start, end)] of the loader's C functions that RAM no longer
    matches (runs merged across gaps of 64 bytes), or None if the stub cannot be
    read. Only STT_FUNC bytes count: go.S keeps its save areas (`saved_regs`,
    `saved_stack`, `cdfs_saved`) in .text, and they change by design."""
    code, syms = elf_parts(elf_path)
    funcs = [(v, v + n) for v, _, t, n in syms if t == 2 and n]
    try:
        r = Rsp()
    except OSError:
        return None
    runs = []
    try:
        for name, addr, want in code:
            ram = r.read(addr, len(want))
            if len(ram) < len(want):
                return None
            for i in range(0, len(want), 4):
                if ram[i:i + 4] != want[i:i + 4] and any(a <= addr + i < b for a, b in funcs):
                    if runs and runs[-1][0] == name and addr + i - runs[-1][2] <= 64:
                        runs[-1][2] = addr + i + 4
                    else:
                        runs.append([name, addr + i, addr + i + 4])
    finally:
        r.detach()
    return [tuple(x) for x in runs]


def cpu_state(samples=3, gap=0.4):
    """PC, PR, SR of a few samples (one attach each). Identical registers
    across samples mean the emulator is halted, not just looping."""
    out = []
    for i in range(samples):
        if i:
            time.sleep(gap)
        try:
            r = Rsp()
        except OSError:
            return None
        try:
            g = r.cmd("g").decode()
        finally:
            r.detach()
        regs = [int.from_bytes(bytes.fromhex(g[j:j + 8]), "little") for j in range(0, len(g) - 7, 8)]
        if len(regs) < 23:
            return None
        out.append({"pc": regs[16], "pr": regs[17], "sr": regs[22], "r15": regs[15],
                    "all": tuple(regs[:23])})
    return {"pc": out[-1]["pc"], "pr": out[-1]["pr"], "sr": out[-1]["sr"], "sp": out[-1]["r15"],
            "halted": len(out) > 1 and len({s["all"] for s in out}) == 1}


def symbolize(addr, syms):
    best = None
    for value, name, *_ in syms:
        if value > addr:
            break
        best = (value, name)
    return f"{best[1]}+0x{addr - best[0]:x}" if best and addr - best[0] < 0x4000 else None


def loader_report(host_exe, loader_dir, host_log, out_dir, flycast_log):
    """What the CPU and the loader's code say, as a dict for result.json."""
    info = loader_in_log(Path(host_log).read_text(encoding="utf-8", errors="replace"))
    rep = {}
    cpu = cpu_state()
    if cpu:
        rep["cpu"] = {k: (f"0x{v:08x}" if isinstance(v, int) and k != "halted" else v)
                      for k, v in cpu.items()}
    # After a reboot RAM is the CDI's dcload again, and "damage" would be the
    # boot, not the title (Sonic Adventure 2 PAL, 2026-10-29: 34 KB "damaged").
    try:
        flog = Path(flycast_log).read_text(encoding="utf-8", errors="replace")
    except OSError:
        flog = ""
    boots = flog.count("REIOS: Booting up")
    if boots > 1:
        rep["rebooted"] = ("the title asked for the BIOS menu (SYS_MISC 1)"
                           if "SYS_MISC 1" in flog else "the SH4 ran address 0 (a crash)")
        return rep
    if info is None:
        return rep
    base, image = info
    rep["loader"] = {"base": f"0x{base:08x}", "image": image}
    try:
        elf = relocated_loader(host_exe, loader_dir, base, image, out_dir)
    except (subprocess.SubprocessError, OSError) as e:
        rep["loader"]["error"] = f"relocate failed: {e}"
        return rep
    _, syms = elf_parts(elf)
    if cpu:
        for reg in ("pc", "pr"):
            name = symbolize(cpu[reg], syms) if base <= cpu[reg] < base + 0x10000 else None
            if name:
                rep["cpu"][reg + "_in_loader"] = name
    damage = loader_damage(elf)
    if damage is not None:
        rep["loader"]["damaged"] = [
            f"{s} 0x{a:08x}-0x{b:08x} ({b - a} bytes)" + (
                f" in {symbolize(a, syms)}" if symbolize(a, syms) else "")
            for s, a, b in damage]
    return rep


# --- keys --------------------------------------------------------------------
#
# PostMessage to flycast's window, so it needs no focus (SendKeys was measured
# to do nothing from a non-interactive shell). (VK, PC scancode) pairs from
# flycast's mappings/SDL_Clavier.cfg: SDL 40 Return = Start, 27 X = A, 6 C = B,
# 25 V = X, 5 B = Y, 9 F = L trigger, WASD analog, arrows d-pad. SDL takes its
# scancode from lParam bits 16-23, so a zero lParam is discarded.

KEYS = {
    "start": (0x0D, 0x1C), "a": (0x58, 0x2D), "b": (0x43, 0x2E), "x": (0x56, 0x2F),
    "y": (0x42, 0x30), "lt": (0x46, 0x21),
    "up": (0x57, 0x11), "down": (0x53, 0x1F), "left": (0x41, 0x1E), "right": (0x44, 0x20),
    "dup": (0x26, 0x48), "ddown": (0x28, 0x50), "dleft": (0x25, 0x4B), "dright": (0x27, 0x4D),
}


def parse_inputs(spec, hold_ms):
    """'40000:start,45000:a*2:300' -> [(40000, 'start', 1, hold_ms), (45000, 'a', 2, 300)]:
    TIME:KEY[*COUNT][:HOLD], TIME in ms after EXEC, HOLD in ms (default `hold_ms`)."""
    out = []
    for item in filter(None, (s.strip() for s in (spec or "").split(","))):
        parts = item.split(":")
        if len(parts) not in (2, 3):
            raise SystemExit(f"--input: {item!r} is not TIME:KEY[*COUNT][:HOLD] (milliseconds)")
        key, _, count = parts[1].partition("*")
        key = key.strip().lower()
        if key not in KEYS:
            raise SystemExit(f"--input: unknown key {key!r}; known: {', '.join(KEYS)}")
        try:
            hold = int(parts[2]) if len(parts) == 3 else hold_ms
            out.append((int(parts[0]), key, int(count or 1), hold))
        except ValueError:
            raise SystemExit(f"--input: {item!r}: TIME, COUNT and HOLD are whole numbers (ms)")
    return sorted(out)


def flycast_window(pid):
    user32 = ctypes.windll.user32
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def each(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(each, 0)
    return found[0] if found else None


def press(pid, key, count=1, hold=0.09, gap=0.6):
    hwnd = flycast_window(pid)
    if not hwnd:
        return False
    vk, scan = KEYS[key]
    post = ctypes.windll.user32.PostMessageW
    post.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    down = 1 | (scan << 16)
    up = down | 0xC0000000
    for i in range(count):
        post(hwnd, 0x0100, vk, down)
        time.sleep(hold)
        post(hwnd, 0x0101, vk, ctypes.c_long(up - (1 << 32)).value)
        if i + 1 < count:
            time.sleep(gap)
    return True


# --- one run -----------------------------------------------------------------

def spawn(cmd, detached, **kw):
    """Popen; detached, the process outlives this script (and the job object a
    calling shell may kill on exit), which is what `start` needs."""
    if detached:
        base = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            return subprocess.Popen(cmd, creationflags=base | subprocess.CREATE_BREAKAWAY_FROM_JOB,
                                    **kw)
        except OSError:
            return subprocess.Popen(cmd, creationflags=base, **kw)
    return subprocess.Popen(cmd, **kw)


class Run:
    def __init__(self, image, opts, out_dir, detached=False):
        self.detached = detached
        self.image = Path(image)
        self.o = opts
        self.dir = out_dir
        self.shots = out_dir / "screens"
        self.shots.mkdir(parents=True, exist_ok=True)
        self.r = {
            "image": str(self.image), "started": dt.datetime.now().isoformat(timespec="seconds"),
            "verdict": None, "reason": "", "milestones": {}, "reads": 0, "last_read_s": None,
            "warnings": [], "errors": [], "console": [], "screen": [], "host_rc": None,
        }
        self.t0 = time.monotonic()
        self.exec_t = None
        self.flycast = None
        self.host = None
        self.card = None

    def now(self):
        return round(time.monotonic() - self.t0, 1)

    def mark(self, name):
        self.r["milestones"].setdefault(name, self.now())

    def finish(self, verdict, reason):
        if self.r["verdict"] is None:
            self.r["verdict"], self.r["reason"] = verdict, reason
        return self.r

    # -- phases --

    def start_flycast(self):
        o = self.o
        close_flycast()
        kill_all()
        assert_emu_cfg(o.flycast_dir)
        self.card = None if o.keep_card else fresh_card(o.flycast_dir, o.cdi, self.dir)
        flog = o.flycast_dir / "flycast.log"
        try:
            flog.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            # Windows keeps the handle a moment after the kill.
            time.sleep(1)
            flog.unlink(missing_ok=True)
        self.flog = Tail(flog)
        self.flycast = spawn([str(o.flycast_dir / "flycast.exe"), str(o.cdi)],
                             self.detached, cwd=o.flycast_dir, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        self.mark("flycast_started")
        deadline = time.monotonic() + 30
        while not port_open(GDB_PORT):
            if time.monotonic() > deadline or self.flycast.poll() is not None:
                raise HarnessError("flycast's GDB stub never opened :3263 (a build without "
                                   "ENABLE_GDB_SERVER, or Debug.GDBEnabled off)")
            time.sleep(0.25)
        for _ in range(8):
            if resume_flycast():
                break
            time.sleep(0.25)
        self.mark("flycast_resumed")
        deadline = time.monotonic() + 60
        while True:
            if any("using capture device" in l for l in self.flog.lines()):
                break
            if time.monotonic() > deadline:
                raise HarnessError("no guest frame on the BBA bridge in 60 s: dcload did not "
                                   "boot from the CDI (or the bridge has no capture device)")
            time.sleep(0.25)
        self.mark("guest_up")
        state = warm_neighbour(o.dc_ip)
        self.r["neighbour"] = state
        if state not in ("Reachable", "Stale", "Permanent"):
            log(f"WARNING: neighbour entry for {o.dc_ip} is {state or 'absent'}; the host's "
                "datagrams may be dropped")

    def host_cmd(self, sub, *rest):
        o = self.o
        cmd = [str(o.host_exe), "--loader-dir", str(o.loader_dir)]
        if not o.learn:
            cmd += ["--memory-db", str(self.dir / "game-memory.tsv")]
        if sub == "u-exec":
            cmd = cmd[:1] + ["-H", o.dc_ip, "-i", "--no-vm2"] + cmd[1:]
            if not o.ra:
                cmd.append("--no-ra")
            # Off unless asked: under flycast it ended a live session at Crazy
            # Taxi's title screen (2026-10-29, loader intact, CPU in the title,
            # "nothing from the console for 10s"), and with the session gone the
            # next disc read is never answered. The harness judges freezes itself.
            if not any(a.startswith("--keepalive") for a in o.host_global):
                cmd += ["--keepalive", "0"]
            cmd += o.host_global
        return cmd + [sub, *rest]

    def identify(self):
        if not self.o.learn:
            src = REPO / "game-memory.tsv"
            if src.exists():
                shutil.copyfile(src, self.dir / "game-memory.tsv")
        try:
            p = subprocess.run(self.host_cmd("identify", str(self.image)), cwd=REPO,
                               capture_output=True, text=True, timeout=600,
                               env=dict(os.environ, RUST_LOG="info"))
            text = ANSI.sub("", p.stdout + p.stderr)
        except subprocess.TimeoutExpired:
            text = "identify timed out after 600 s\n"
        (self.dir / "identify.txt").write_text(text, encoding="utf-8")
        for line in text.splitlines():
            m = re.search(r"(product|title)\s*:\s*(.+)$", line)
            if m and m.group(1) not in self.r:
                self.r[m.group(1)] = m.group(2).strip()

    def start_host(self):
        env = dict(os.environ)
        # Debug for the session, TRACE for one module: one line per disc read
        # (`Received ReadSector syscall`) without -vv's per-packet flood.
        env["RUST_LOG"] = "debug,dcload_ip_rs::dispatch::sectors=trace"
        self.host_log_path = self.dir / "host.log"
        self.host_log_fh = open(self.host_log_path, "wb")
        cmd = self.host_cmd("u-exec", str(self.image), *self.o.host_extra)
        (self.dir / "command.txt").write_text(subprocess.list2cmdline(cmd), encoding="utf-8")
        self.host = spawn(cmd, self.detached, cwd=REPO, env=env, stdout=self.host_log_fh,
                          stderr=subprocess.STDOUT)
        self.hlog = Tail(self.host_log_path)
        self.mark("host_started")

    def take_host_lines(self):
        for line in self.hlog.lines():
            m = LEVEL.search(line)
            level = m.group(1) if m else ""
            msg = line.split(" > ", 1)[1] if " > " in line else line
            if "ReadSector LBA" in msg and "answer sent" in msg:
                self.r["reads"] += 1
                self.r["last_read_s"] = self.now()
                continue
            if "the Dreamcast answered after" in msg:
                self.mark("handshake")
            elif "loader is now at" in msg:
                self.mark("loader_placed")
            elif "Upload complete, executing at" in msg:
                self.mark("exec")
                self.exec_t = time.monotonic()
                log(f"EXEC ({msg.split('at ')[-1]})")
            elif "Received Exit syscall" in msg:
                self.mark("exit_syscall")
            if level == "ERROR":
                self._note("errors", msg)
            elif level == "WARN":
                self._note("warnings", msg)
            elif level == "INFO" and self.exec_t and " dcload_ip_rs::dispatch::syscalls " in line:
                # Console text (DC25) from the title.
                self._note("console", msg, cap=40)

    def _note(self, key, msg, cap=25):
        lst = self.r[key]
        if msg not in lst and len(lst) < cap:
            lst.append(msg)

    def take_flycast_lines(self):
        for line in self.flog.lines():
            if "SYS_MISC 1" in line and self.exec_t:
                self.mark("sys_misc_1")
            if "REIOS: Booting up" in line and self.exec_t:
                self.mark("reios_boot")
            if ("Unhandled" in line or "FATAL" in line or "Exception" in line) and self.exec_t:
                self._note("errors", "flycast: " + line.strip(), cap=30)

    def probe(self, save_as=None, step=None):
        got = grab(step or self.o.probe_scale)
        t = self.now()
        if got is None:
            self.r["screen"].append({"t": t, "ok": False})
            return None
        rows, enabled = got
        crc = zlib.crc32(b"".join(rows)) & 0xFFFFFFFF
        lit = round(lit_percent(rows), 1) if enabled else 0.0
        entry = {"t": t, "ok": True, "crc": f"{crc:08x}", "lit": lit, "enabled": enabled}
        if save_as:
            (self.shots / save_as).write_bytes(png(rows))
            entry["png"] = save_as
        self.r["screen"].append(entry)
        return entry

    def watch(self):
        o = self.o
        inputs = parse_inputs(o.input, o.hold)
        next_probe = next_shot = 0.0
        boot_deadline = time.monotonic() + o.boot_timeout
        last_change = None
        prev_crc = None
        while True:
            self.take_host_lines()
            self.take_flycast_lines()
            rc = self.host.poll()
            if self.flycast.poll() is not None:
                return self.finish("CRASH", "flycast exited")
            if self.exec_t is None:
                if rc is not None:
                    self.r["host_rc"] = rc
                    if "handshake" not in self.r["milestones"]:
                        return self.finish("NO_LOADER", f"host exited (rc {rc}) before the handshake")
                    return self.finish("NO_EXEC", f"host exited (rc {rc}) before EXEC")
                if time.monotonic() > boot_deadline:
                    return self.finish("NO_LOADER" if "handshake" not in self.r["milestones"]
                                       else "NO_EXEC", f"no EXEC within {o.boot_timeout} s")
                time.sleep(0.25)
                continue

            since = time.monotonic() - self.exec_t
            ms = self.r["milestones"]
            if "reios_boot" in ms:
                if "sys_misc_1" in ms:
                    return self.finish("BIOS_MENU", "the title asked the BIOS for its menu "
                                       "(SYS_MISC 1, then REIOS boot)")
                return self.finish("CRASH", "REIOS boot after EXEC: the SH4 ran address 0")
            if rc is not None:
                self.r["host_rc"] = rc
                if "exit_syscall" in ms:
                    return self.finish("EXITED", "the title made the Exit syscall")
                return self.finish("SILENT", f"the host ended the session (rc {rc}) "
                                   f"{since:.0f} s after EXEC")

            while inputs and since * 1000 >= inputs[0][0]:
                when, key, count, hold = inputs.pop(0)
                ok = press(self.flycast.pid, key, count, hold=hold / 1000)
                log(f"press {key}x{count} for {hold} ms at +{when} ms"
                    + ("" if ok else " (no window!)"))
                self.r.setdefault("inputs", []).append({"t": self.now(), "at_ms": when, "key": key,
                                                        "count": count, "hold_ms": hold,
                                                        "sent": ok})

            if since >= next_probe:
                shot = None
                if since >= next_shot:
                    shot = f"t{int(since):04d}.png"
                    next_shot = since + o.shot_interval
                e = self.probe(save_as=shot)
                next_probe = since + o.probe_interval
                if e:
                    if e["crc"] != prev_crc:
                        last_change = time.monotonic()
                        prev_crc = e["crc"]
            if since >= o.duration:
                break
            time.sleep(0.2)

        rep = loader_report(o.host_exe, o.loader_dir, self.host_log_path, self.dir,
                            o.flycast_dir / "flycast.log")
        self.r["loader_check"] = rep
        damage = rep.get("loader", {}).get("damaged")
        if damage:
            cpu = rep.get("cpu", {})
            where = cpu.get("pc_in_loader") or cpu.get("pc", "?")
            return self.finish("LOADER_HIT", f"the title wrote over the loader ({len(damage)} "
                               f"runs, first {damage[0]}); CPU "
                               + ("halted" if cpu.get("halted") else "running") + f" at {where}")
        # Judged over the whole window after the grace period.
        after = [e for e in self.r["screen"]
                 if e.get("ok") and e["t"] >= ms["exec"] + o.grace]
        if after and all(e["lit"] < 1.0 for e in after):
            return self.finish("BLACK", f"no lit picture in the {len(after)} probes after "
                               f"+{o.grace:g} s")
        now = time.monotonic()
        read_age = None if self.r["last_read_s"] is None else self.now() - self.r["last_read_s"]
        still = last_change is not None and now - last_change >= o.freeze_after
        quiet = read_age is None or read_age >= o.freeze_after
        if still and quiet:
            cpu = rep.get("cpu", {})
            return self.finish("FROZEN", f"picture unchanged for {now - last_change:.0f} s and no "
                               "disc read for " + ("the whole run" if read_age is None
                                                   else f"{read_age:.0f} s")
                               + (f"; emulator halted at {cpu.get('pc_in_loader') or cpu['pc']}"
                                  if cpu.get("halted") else ""))
        return self.finish("RUNNING", f"picture changing or disc being read at +{o.duration:g} s")

    def stop(self):
        if self.exec_t is not None and self.flycast and self.flycast.poll() is None:
            self.probe(save_as="final.png", step=1)
        if self.host and self.host.poll() is None:
            self.host.kill()
        if self.flycast and self.flycast.poll() is None:
            close_flycast()
        for p in (self.host, self.flycast):
            if p and p.poll() is None:
                p.kill()
        for p in (self.host, self.flycast):
            if p:
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
        if self.host:
            self.take_host_lines()
            self.host_log_fh.close()
        if not self.o.keep_flycast:
            kill_all()
        try:
            shutil.copyfile(self.o.flycast_dir / "flycast.log", self.dir / "flycast.log")
        except OSError:
            pass
        if self.card:
            try:
                shutil.copyfile(self.card, self.dir / "vmu-A1-after.bin")
            except OSError:
                pass

    def execute(self):
        log(f"=== {self.image.name}")
        try:
            self.identify()
            self.start_flycast()
            self.start_host()
            self.watch()
        except HarnessError as e:
            self.finish("HARNESS", str(e))
        except KeyboardInterrupt:
            self.finish("HARNESS", "interrupted")
            raise
        finally:
            self.stop()
            self.r["elapsed_s"] = self.now()
            (self.dir / "result.json").write_text(json.dumps(self.r, indent=2), encoding="utf-8")
        log(f"{self.r['verdict']}: {self.r['reason']}  (reads {self.r['reads']}, "
            f"{len(self.r['warnings'])} warnings, {len(self.r['errors'])} errors) -> {self.dir}")
        return self.r


# --- batch -------------------------------------------------------------------

def run_options(parser):
    """Options that a games list may override per image (after ' ;; ')."""
    g = parser.add_argument_group("per run (overridable per line in --list)")
    g.add_argument("--duration", type=float, default=120,
                   help="seconds to watch after EXEC (default 120)")
    g.add_argument("--boot-timeout", type=float, default=300,
                   help="seconds from the host's start to EXEC; a deflated zip builds its index "
                        "first (default 300)")
    g.add_argument("--grace", type=float, default=20,
                   help="seconds after EXEC before a black screen counts (default 20)")
    g.add_argument("--freeze-after", type=float, default=45,
                   help="no picture change AND no disc read for this long is FROZEN (default 45)")
    g.add_argument("--probe-interval", type=float, default=5, help="seconds between screen probes")
    g.add_argument("--shot-interval", type=float, default=30, help="seconds between saved PNGs")
    g.add_argument("--probe-scale", type=int, default=4,
                   help="keep every Nth pixel when probing (default 4: the guest halts less)")
    g.add_argument("--input", default="",
                   help="key presses after EXEC, TIME:KEY[*COUNT][:HOLD] in milliseconds, e.g. "
                        "'40000:start,45000:a*2:300' (A twice, each held 300 ms). Keys: "
                        + ", ".join(KEYS))
    g.add_argument("--hold", type=int, default=120,
                   help="milliseconds a key is held when --input gives no HOLD (default 120)")


def setup_options(ap):
    ap.add_argument("--out", type=Path, default=REPO / "harness-runs")
    ap.add_argument("--flycast-dir", type=Path, default=DEFAULT_FLYCAST_DIR)
    ap.add_argument("--cdi", type=Path, default=DEFAULT_CDI, help="the dcload CDI flycast boots")
    ap.add_argument("--loader-dir", type=Path, default=DEFAULT_LOADER_DIR,
                    help="a loader set built for flycast (DREAMCAST_IP=192.168.1.130)")
    ap.add_argument("--dc-ip", default=DEFAULT_DC_IP)
    builds = [p for p in (REPO / "target" / b / "dcload-ip-rs.exe" for b in ("release", "debug"))
              if p.exists()]
    ap.add_argument("--host-exe", type=Path,
                    default=max(builds, key=lambda p: p.stat().st_mtime, default=builds and builds[0]),
                    help="default: the newer of target/release and target/debug")
    ap.add_argument("--build", action="store_true", help="cargo build --release first")
    ap.add_argument("--host-global", default="",
                    help="options for dcload-ip-rs before the subcommand, e.g. '--no-marks'")
    ap.add_argument("--learn", action="store_true",
                    help="let the runs write the real game-memory.tsv")
    ap.add_argument("--keep-card", action="store_true",
                    help="boot on the A1 card the last run left (default: a blank card per "
                         "run, the old one kept as vmu-A1-before.bin)")
    ap.add_argument("--ra", action="store_true",
                    help="keep RetroAchievements on (reports to retroachievements.org)")
    run_options(ap)


def parse_with_host_extra(ap, argv):
    """Everything after `--` goes to u-exec."""
    host_extra = []
    if "--" in argv:
        i = argv.index("--")
        argv, host_extra = argv[:i], argv[i + 1:]
    o = ap.parse_args(argv)
    o.host_extra = host_extra
    o.host_global = shlex.split(o.host_global)
    return o


def check_setup(ap, o):
    for what, p in (("flycast", o.flycast_dir / "flycast.exe"), ("CDI", o.cdi),
                    ("loader set", o.loader_dir)):
        if not p.exists():
            ap.error(f"{what} not found: {p} (scripts/flycast-build-loader.sh builds the CDI "
                     "and loader set)")
    if o.build:
        log("cargo build --release")
        subprocess.run(["cargo", "build", "--release"], cwd=REPO, check=True)
        o.host_exe = REPO / "target" / "release" / "dcload-ip-rs.exe"
    if not o.host_exe or not o.host_exe.exists():
        ap.error(f"host tool not found: {o.host_exe} (use --build)")
    # A run of the previous binary looks exactly like a run of this one.
    newest = max(f.stat().st_mtime for f in (REPO / "src").rglob("*") if f.is_file())
    stale = o.host_exe.stat().st_mtime < newest
    if stale:
        log(f"WARNING: {o.host_exe} is older than src/: this tests the previous build "
            "(use --build)")
    return stale


# --- interactive: one session left running, driven step by step ---------------
#
# `start` brings a title up to EXEC and returns, leaving flycast and the host
# running; `screen`, `peek`, `press` and `status` then look at it and drive it,
# one command at a time, so that whoever is driving (a person or an agent) can
# read the picture and the RAM between key presses and decide the next one.
# `stop` ends it. The session is described by <out>/session.json.

SESSION = REPO / "harness-runs" / "session.json"


def load_session():
    try:
        return json.loads(SESSION.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise SystemExit("no session: run `start <image>` first")


def cmd_start(argv):
    ap = argparse.ArgumentParser(prog="flycast-harness.py start")
    ap.add_argument("image", type=Path)
    setup_options(ap)
    o = parse_with_host_extra(ap, argv)
    o.input = ""
    o.keep_flycast = True
    if not o.image.exists():
        ap.error(f"no such image: {o.image}")
    stale = check_setup(ap, o)
    out = o.out / (dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + slug(o.image.stem))
    run = Run(o.image, o, out, detached=True)
    log(f"=== {o.image.name} -> {out}")
    try:
        run.identify()
        run.start_flycast()
        run.start_host()
        o.duration = 0
        run.watch()
    except HarnessError as e:
        run.finish("HARNESS", str(e))
    ms = run.r["milestones"]
    ok = "exec" in ms and run.r["verdict"] in ("RUNNING", "FROZEN", "BLACK")
    session = {
        "image": str(o.image), "dir": str(out), "flycast_pid": run.flycast and run.flycast.pid,
        "host_pid": run.host and run.host.pid, "host_log": str(out / "host.log"),
        "flycast_log": str(o.flycast_dir / "flycast.log"), "exec_s": ms.get("exec"),
        "started": run.r["started"], "stale_host": stale, "host_exe": str(o.host_exe),
        "loader_dir": str(o.loader_dir), "card": str(run.card) if run.card else None,
    }
    SESSION.parent.mkdir(parents=True, exist_ok=True)
    SESSION.write_text(json.dumps(session, indent=2), encoding="utf-8")
    (out / "result.json").write_text(json.dumps(run.r, indent=2), encoding="utf-8")
    if ok:
        log(f"EXEC reached at +{ms['exec']} s; flycast and the host keep running "
            f"(product: {run.r.get('product', '?')})")
        return 0
    log(f"{run.r['verdict']}: {run.r['reason']}")
    return 1


def cmd_screen(argv):
    ap = argparse.ArgumentParser(prog="flycast-harness.py screen")
    ap.add_argument("output", nargs="?", type=Path,
                    help="PNG path (default: the session's screens/ directory)")
    ap.add_argument("--scale", type=int, default=1, help="keep every Nth pixel")
    o = ap.parse_args(argv)
    if o.output is None:
        s = load_session()
        o.output = Path(s["dir"]) / "screens" / f"live-{dt.datetime.now():%H%M%S}.png"
    got = grab(o.scale)
    if got is None:
        raise SystemExit("cannot read the framebuffer (flycast or its GDB stub is not up)")
    rows, enabled = got
    o.output.parent.mkdir(parents=True, exist_ok=True)
    o.output.write_bytes(png(rows))
    print(f"{o.output}  {len(rows[0]) // 3}x{len(rows)}  "
          f"crc={zlib.crc32(b''.join(rows)) & 0xFFFFFFFF:08x}  lit={lit_percent(rows):.1f}%"
          + ("" if enabled else "  (display DISABLED)"))
    return 0


def cmd_peek(argv):
    ap = argparse.ArgumentParser(prog="flycast-harness.py peek",
                                 description="read guest memory over flycast's GDB stub")
    ap.add_argument("address", help="hex, e.g. 8c010000 or 0x8c010000")
    ap.add_argument("length", nargs="?", default="0x100", help="bytes (default 0x100)")
    ap.add_argument("--u32", action="store_true", help="print little-endian words")
    ap.add_argument("--u16", action="store_true", help="print little-endian halfwords")
    ap.add_argument("--out", type=Path, help="write the bytes to this file instead")
    o = ap.parse_args(argv)
    addr, length = int(o.address, 16), int(o.length, 0)
    try:
        r = Rsp()
    except OSError:
        raise SystemExit("flycast's GDB stub is not up")
    try:
        data = r.read(addr, length)
    finally:
        r.detach()
    if len(data) < length:
        print(f"short read: {len(data)} of {length} bytes", file=sys.stderr)
    if o.out:
        o.out.write_bytes(data)
        print(f"{o.out}: {len(data)} bytes from 0x{addr:08x}")
        return 0
    width = 2 if o.u16 else 4 if o.u32 else 1
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        if width == 1:
            cells = " ".join(f"{b:02x}" for b in chunk)
        else:
            fmt = "H" if width == 2 else "I"
            n = len(chunk) // width
            cells = " ".join(f"{v:0{width * 2}x}" for v in struct.unpack(f"<{n}{fmt}",
                                                                         chunk[:n * width]))
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{addr + off:08x}  {cells:<47}  {text}")
    return 0


def cmd_press(argv):
    ap = argparse.ArgumentParser(prog="flycast-harness.py press",
                                 description="press Dreamcast buttons: start a b x y lt, "
                                             "up/down/left/right (stick), dup/ddown/dleft/dright")
    ap.add_argument("keys", nargs="+", help="KEY or KEY*N, in order")
    ap.add_argument("--gap", type=float, default=0.8, help="seconds between presses")
    ap.add_argument("--hold", type=float, default=0.12, help="seconds each key is held")
    ap.add_argument("--wait", type=float, default=0.0, help="seconds to wait after the last")
    o = ap.parse_args(argv)
    pids = running("flycast.exe")
    if not pids:
        raise SystemExit("flycast is not running")
    for i, item in enumerate(o.keys):
        key, _, count = item.lower().partition("*")
        if key not in KEYS:
            raise SystemExit(f"unknown key {key!r}; known: {', '.join(KEYS)}")
        if not press(pids[0], key, int(count or 1), hold=o.hold, gap=o.gap):
            raise SystemExit("flycast has no visible window")
        if i + 1 < len(o.keys):
            time.sleep(o.gap)
    time.sleep(o.wait)
    print("pressed " + " ".join(o.keys))
    return 0


def cmd_status(argv):
    ap = argparse.ArgumentParser(prog="flycast-harness.py status")
    ap.add_argument("--lines", type=int, default=12, help="last host log lines to show")
    o = ap.parse_args(argv)
    s = load_session()
    host_log = Path(s["host_log"])
    lines = [ANSI.sub("", l) for l in host_log.read_text(encoding="utf-8",
                                                         errors="replace").splitlines()]
    reads = [l for l in lines if "ReadSector LBA" in l and "answer sent" in l]
    try:
        flog = Path(s["flycast_log"]).read_text(encoding="utf-8", errors="replace")
    except OSError:
        flog = ""
    alive = {n: bool(running(n)) for n in ("flycast.exe", "dcload-ip-rs.exe")}
    print(f"image   : {s['image']}")
    print(f"running : flycast {alive['flycast.exe']}, host {alive['dcload-ip-rs.exe']}")
    print(f"reads   : {len(reads)}" + (f", last: {reads[-1].split(' > ')[-1]}" if reads else ""))
    print(f"resets  : REIOS boots {flog.count('REIOS: Booting up')} (1 = the CDI's own), "
          f"SYS_MISC 1 {flog.count('SYS_MISC 1')}")
    for level in ("ERROR", "WARN"):
        hits = [l.split(" > ", 1)[-1] for l in lines if re.search(rf"\b{level}\b", l)]
        if hits:
            print(f"{level.lower()}s ({len(hits)}):")
            for h in hits[-5:]:
                print(f"  {h[:200]}")
    tail = [l for l in lines if "ReadSector" not in l][-o.lines:]
    print("host log:")
    for l in tail:
        print(f"  {l[:220]}")
    return 0


def cmd_check(argv):
    ap = argparse.ArgumentParser(prog="flycast-harness.py check",
                                 description="where the CPU is, and whether the loader's code is "
                                             "still the loader's")
    ap.add_argument("--loader-dir", type=Path, default=DEFAULT_LOADER_DIR)
    o = ap.parse_args(argv)
    s = load_session()
    host_exe = Path(s.get("host_exe") or REPO / "target" / "debug" / "dcload-ip-rs.exe")
    rep = loader_report(host_exe, Path(s.get("loader_dir") or o.loader_dir), s["host_log"], s["dir"],
                        s["flycast_log"])
    print(json.dumps(rep, indent=2))
    return 0


def cmd_stop(argv):
    s = None
    try:
        s = load_session()
    except SystemExit:
        pass
    close_flycast()
    kill_all()
    if s:
        try:
            shutil.copyfile(s["flycast_log"], Path(s["dir"]) / "flycast.log")
        except OSError:
            pass
        if s.get("card"):
            try:
                shutil.copyfile(s["card"], Path(s["dir"]) / "vmu-A1-after.bin")
            except OSError:
                pass
        SESSION.unlink(missing_ok=True)
        print(f"stopped; logs in {s['dir']}")
    else:
        print("stopped")
    return 0


COMMANDS = {"start": cmd_start, "screen": cmd_screen, "peek": cmd_peek, "press": cmd_press,
            "status": cmd_status, "check": cmd_check, "stop": cmd_stop}


def main():
    argv = sys.argv[1:]
    if argv and argv[0] in COMMANDS:
        return COMMANDS[argv[0]](argv[1:])
    if argv and argv[0] == "run":
        argv = argv[1:]
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter,
                                 epilog="Interactive: start IMAGE | screen [PNG] | peek ADDR [LEN] "
                                        "| press KEY... | status | stop  (each has --help)")
    ap.add_argument("images", nargs="*", help="disc images (.gdi .cdi .zip ...)")
    ap.add_argument("--list", type=Path,
                    help="file of images, one per line; '#' comments; options after ' ;; '")
    ap.add_argument("--dir", type=Path, help="every image in this directory")
    ap.add_argument("--match", help="with --dir: only names containing this (case-insensitive)")
    ap.add_argument("--limit", type=int, help="run at most this many images")
    ap.add_argument("--keep-flycast", action="store_true",
                    help="leave the last flycast running for inspection")
    setup_options(ap)
    o = parse_with_host_extra(ap, argv)

    jobs = [(Path(p), o) for p in o.images]
    if o.list:
        for raw in o.list.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            path, _, extra = line.partition(" ;; ")
            # The harness's per-run options; anything else goes to u-exec.
            sub = argparse.ArgumentParser(add_help=False)
            run_options(sub)
            # Global options of dcload-ip-rs (--loader-base, ...) must come
            # before the subcommand: a line gives them with --host-global too.
            sub.add_argument("--host-global")
            per, unknown = sub.parse_known_args(shlex.split(extra, posix=False),
                                                namespace=argparse.Namespace(**vars(o)))
            if isinstance(per.host_global, str):
                per.host_global = o.host_global + shlex.split(per.host_global.strip('"'))
            per.host_extra = o.host_extra + [a for a in unknown if a != "--"]
            jobs.append((Path(path.strip().strip('"')), per))
    if o.dir:
        for p in sorted(o.dir.iterdir()):
            if p.suffix.lower() in IMAGE_SUFFIXES and (not o.match or o.match.lower() in p.name.lower()):
                jobs.append((p, o))
    if o.limit:
        jobs = jobs[:o.limit]
    if not jobs:
        ap.error("no image: give paths, --list or --dir")
    for p, _ in jobs:
        if not p.exists():
            ap.error(f"no such image: {p}")
    stale = check_setup(ap, o)

    batch = o.out / dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    batch.mkdir(parents=True, exist_ok=True)
    log(f"{len(jobs)} image(s) -> {batch}")
    results = []
    try:
        for n, (image, opts) in enumerate(jobs, 1):
            opts.keep_flycast = o.keep_flycast and n == len(jobs)
            r = Run(image, opts, batch / f"{n:02d}-{slug(image.stem)}").execute()
            r["stale_host"] = stale
            results.append(r)
    except KeyboardInterrupt:
        log("interrupted; summarising what finished")
    finally:
        write_summary(batch, results)
    return 0 if results and all(r["verdict"] in ("RUNNING", "EXITED") for r in results) else 1


def write_summary(batch, results):
    cols = ["verdict", "image", "exec_s", "reads", "warnings", "errors", "reason"]
    with open(batch / "summary.tsv", "w", encoding="utf-8") as fh:
        fh.write("\t".join(cols) + "\n")
        for r in results:
            fh.write("\t".join(str(x) for x in (
                r["verdict"], r["image"], r["milestones"].get("exec", ""), r["reads"],
                len(r["warnings"]), len(r["errors"]), r["reason"])) + "\n")
    (batch / "summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    if results:
        log("summary:")
        for r in results:
            log(f"  {r['verdict']:<9} {Path(r['image']).name}  -- {r['reason']}")
        log(f"written: {batch / 'summary.tsv'}")


if __name__ == "__main__":
    sys.exit(main())
