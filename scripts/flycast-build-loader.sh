#!/usr/bin/env bash
# Build the dcload CDI and loader set that scripts/flycast-harness.py boots.
#
#   wsl -d Debian -- bash scripts/flycast-build-loader.sh
#
# A STATIC address: DHCP never completes through flycast's BBA bridge here, and
# a CDI built with the tree's 0.0.0.0 sits on its DHCP screen forever. The loader
# set must carry the same address (a chainloaded relocatable image knows only
# what it was compiled with) and flycast's exact AICA clock (loader AGENTS.md
# 4.13: CDDA_TICKS_X8192=580480).
#
# Built in a COPY of the loader repo: DREAMCAST_IP reaches the compiler as a -D
# with no file dependency, so building it in the real tree would leave static
# objects that the next plain `make` for the console silently reuses.
#
# Writes:
#   C:\Users\arnod\Documents\Dreamcast\dc-load\dcload-flycast.cdi
#   <this repo>/loaders-flycast/{dcload-relocatable,dcload-resident,dcload-resident-net}.elf
set -euo pipefail

SRC="${DCLOAD_REPO:-/opt/toolchains/dc/dcload-ip}"
IP="${DCLOAD_IP:-192.168.1.130}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-/tmp/dcload-flycast-build}"
CDI_OUT="${CDI_OUT:-/mnt/c/Users/arnod/Documents/Dreamcast/dc-load/dcload-flycast.cdi}"
LOADERS_OUT="$HERE/loaders-flycast"
MAKE_ARGS=("DREAMCAST_IP=$IP" "CDDA_TICKS_X8192=580480")

echo "[copy] $SRC -> $WORK ($(git -C "$SRC" log --oneline -1), $(git -C "$SRC" status --short | wc -l) local changes)"
rm -rf "$WORK" && mkdir -p "$WORK"
tar -C "$SRC" --exclude=.git -cf - . | tar -C "$WORK" -xf -

set +u
# shellcheck disable=SC1091
source /opt/toolchains/dc/kos/environ.sh
set -u

make -C "$WORK" clean >/dev/null 2>&1 || true
echo "[build] make loaders ${MAKE_ARGS[*]}"
# The network resident image (virtual NIC, PSO / UT) does not fit with a static
# address (2026-10-29: "the big GD stage (.gdstage) does not fit under _stack"),
# and it is linked last. Keep the two that do: without the file the host serves
# the relocatable image, so a network title runs without the virtual NIC here.
if ! make -C "$WORK/target-src/dcload" "${MAKE_ARGS[@]}" loaders >"$WORK/loaders.log" 2>&1; then
  if grep -q "linking dcload-resident-net.elf" "$WORK/loaders.log" \
     && [[ -f "$WORK/target-src/dcload/loaders/dcload-resident.elf" ]]; then
    echo "[build] WARNING: dcload-resident-net.elf does not fit with a static IP; skipped" >&2
    rm -f "$WORK/target-src/dcload/loaders/dcload-resident-net.elf"
  else
    tail -30 "$WORK/loaders.log"; exit 1
  fi
fi
echo "[build] make ${MAKE_ARGS[*]}"
# `loaders` restores the default objects only when it succeeds.
make -C "$WORK" clean >/dev/null 2>&1 || true
make -C "$WORK" "${MAKE_ARGS[@]}" >"$WORK/build.log" 2>&1 || { tail -30 "$WORK/build.log"; exit 1; }

echo "[package] mkdcdisc"
/opt/toolchains/dc/mkdcdisc/build/mkdcdisc -B "$WORK/target-src/1st_read/1st_read.bin" -N \
  -o "$WORK/target-src/1st_read/dcload.cdi" >"$WORK/mkdcdisc.log" 2>&1 \
  || { tail -30 "$WORK/mkdcdisc.log"; exit 1; }
cp "$WORK/target-src/1st_read/dcload.cdi" "$CDI_OUT"

# Mirror, not merge: a stale ELF answers with counters at moved addresses.
rm -rf "$LOADERS_OUT"
mkdir -p "$LOADERS_OUT"
cp "$WORK"/target-src/dcload/loaders/*.elf "$LOADERS_OUT/"
(cd "$WORK/target-src/dcload/loaders" && md5sum ./*.elf) > /tmp/a.md5
(cd "$LOADERS_OUT" && md5sum ./*.elf) | diff - /tmp/a.md5 >/dev/null \
  || { echo "loader copy does not match the build" >&2; exit 1; }

# The address really is in what was built (a stale object would not show it),
# and the CDI holds that 1st_read.bin (mkdcdisc stores it verbatim; the address
# itself may straddle a raw sector's framing there).
python3 - "$CDI_OUT" "$WORK/target-src/1st_read/1st_read.bin" "$LOADERS_OUT" "$IP" <<'PY'
import pathlib, sys
cdi, first, loaders, ip = sys.argv[1:]
first_bytes = open(first, "rb").read()
if ip.encode() not in first_bytes:
    sys.exit(f"1st_read.bin does not contain {ip}")
if first_bytes[:64] not in open(cdi, "rb").read():
    sys.exit("the CDI does not contain this 1st_read.bin")
for elf in pathlib.Path(loaders).glob("*.elf"):
    if ip.encode() not in elf.read_bytes():
        sys.exit(f"{elf.name} does not contain {ip}")
PY
echo "CDI=$CDI_OUT"
echo "LOADERS=$LOADERS_OUT"
