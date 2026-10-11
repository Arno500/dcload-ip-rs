//! A Katana allocator that owns all the RAM a title leaves free, found by its
//! literal pool, and the loader taken out of it. Two of them: Shenmue II's
//! "HLib", and the Katana library's own syMalloc (further down).
//!
//! WHY (Shenmue II, 2026-10-05). Its allocator ("HLib") is set up once from a
//! pool of literals: the heap's start, the first block (start + 0x20), the end,
//! the first block's size (end - (start + 0x20)) and three tags. Everything
//! between the end of the program and a fixed region at the top of RAM is that
//! heap, so no fixed base is free for long: a loader anywhere in it is
//! overwritten when the heap fills (disc 4), and the top is not safe either,
//! because a fixed loading buffer runs over the heap's end there. Taking the
//! loader's 64 KB off the heap's BOTTOM -- moving its start up, and the size
//! with it -- was measured to run the title perfectly.
//!
//! The init writes a "HLib" header at the start, a free block at start + 0x20
//! of the pool's size, and a "HLib" header at the end (32 bytes, so the heap's
//! RAM ends at end + 0x20). Moving the start or the end is three or two words
//! of that pool; the code that reads them is left alone. The words are guarded
//! like the GAPS one: the title reloads its program after a disc swap.

use super::*;

const TAG_FREE: u32 = u32::from_le_bytes(*b"fREe");
const TAG_USED: u32 = u32::from_le_bytes(*b"USE ");
const TAG_LIB: u32 = u32::from_le_bytes(*b"HLib");
/// A block header, and the end sentinel.
const HEADER: u32 = 0x20;
/// How far apart the pool's words may sit, in bytes.
const POOL_SPAN: usize = 0x40;
/// The least heap worth keeping once the loader is out of it.
const MIN_LEFT: u32 = 0x10_0000;

/// One HLib heap: its bounds (P1) and where each pool word is (P1 address of
/// the literal, and the word as the title has it, segment bits included).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HlibHeap {
    pub start: u32,
    pub end: u32,
    start_at: (u32, u32),
    first_at: (u32, u32),
    end_at: (u32, u32),
    size_at: u32,
}

/// The HLib heap a title sets up, if its pool is in the image -- and only if
/// exactly one is (two would leave the choice to chance).
pub fn hlib_heap(buf: &[u8], address: u32) -> Option<HlibHeap> {
    let mut found: Vec<HlibHeap> = vec![];
    for (base, data) in payload_spans(buf, address) {
        let at = |i: usize| p1(base).wrapping_add(i as u32);
        let word = |i: usize| (i + 4 <= data.len()).then(|| le32(data, i));
        for (i, s) in words(data) {
            if !names_ram(s) || word(i + 4) != Some(s.wrapping_add(HEADER)) {
                continue;
            }
            let (lo, hi) = (i.saturating_sub(POOL_SPAN), (i + POOL_SPAN).min(data.len()));
            let near: Vec<(usize, u32)> = (lo..hi.saturating_sub(3))
                .step_by(4)
                .filter_map(|j| word(j).map(|w| (j, w)))
                .collect();
            let has = |tag| near.iter().any(|&(_, w)| w == tag);
            if !(has(TAG_FREE) && has(TAG_USED) && has(TAG_LIB)) {
                continue;
            }
            let start = p1(s);
            for &(j, e) in near.iter().filter(|&&(j, _)| j > i + 4) {
                if !names_ram(e) || p1(e) <= start.wrapping_add(HEADER) {
                    continue;
                }
                let size = p1(e) - (start + HEADER);
                if let Some(&(k, _)) = near.iter().find(|&&(_, w)| w == size) {
                    found.push(HlibHeap {
                        start,
                        end: p1(e),
                        start_at: (at(i), s),
                        first_at: (at(i + 4), word(i + 4).unwrap_or(0)),
                        end_at: (at(j), e),
                        size_at: at(k),
                    });
                    break;
                }
            }
        }
    }
    found.dedup();
    match found.as_slice() {
        [one] => Some(*one),
        _ => None,
    }
}

impl HlibHeap {
    /// Where the loader goes: the first 64 KB boundary at or above the heap's
    /// start, if enough heap is left above it.
    pub fn loader_base(&self) -> Option<u32> {
        let base = self.start.checked_add(0xffff)? & !0xffff;
        let left = self.end.checked_sub(base.checked_add(crate::loaders::LOADER_SPAN + HEADER)?)?;
        (crate::loaders::is_high(base) && left >= MIN_LEFT).then_some(base)
    }

    /// The pool words that keep the heap off a loader at `base`: the start
    /// moved above it when it sits at the bottom, the end moved under it when
    /// it sits at the top. Nothing when it is outside the heap; an error when
    /// it is in the middle, where no two words can take it out.
    pub fn patches(&self, base: u32) -> Result<Vec<(u32, u32)>, String> {
        let span = crate::loaders::LOADER_SPAN;
        let (lo, hi) = (p1(base), p1(base) + span);
        let top = self.end + HEADER;
        if hi <= self.start || lo >= top {
            return Ok(vec![]);
        }
        let keep = |raw: u32, to: u32| (to & 0x1fff_ffff) | (raw & 0xe000_0000);
        if lo <= self.start.saturating_add(0xffff) {
            let start = hi;
            if start + HEADER + MIN_LEFT > self.end {
                return Err(format!("only 0x{:x} bytes of heap would be left", self.end.saturating_sub(start)));
            }
            return Ok(vec![
                (self.start_at.0, keep(self.start_at.1, start)),
                (self.first_at.0, keep(self.first_at.1, start + HEADER)),
                (self.size_at, self.end - (start + HEADER)),
            ]);
        }
        if hi >= self.end {
            let end = lo - HEADER;
            if self.start + HEADER + MIN_LEFT > end {
                return Err(format!("only 0x{:x} bytes of heap would be left", end.saturating_sub(self.start)));
            }
            return Ok(vec![
                (self.end_at.0, keep(self.end_at.1, end)),
                (self.size_at, end - (self.start + HEADER)),
            ]);
        }
        Err(format!(
            "it sits in the middle of the heap (0x{:08x}..0x{top:08x}), which only its \
             bottom or its top can be taken out of",
            self.start
        ))
    }

    /// The constants the patches change: a loaded literal naming one of them
    /// is the allocator's own, not a title writing over the loader.
    pub fn names_own_bound(&self, at: u32) -> bool {
        at == self.start || at == self.start + HEADER || at == self.end
    }
}

// ---------------------------------------------------------------------------
// KATANA'S OWN ALLOCATOR: syMalloc, set up by sbInitSystem.
//
// WHY (Jet Set Radio, 2026-10-10). Katana's sbinit.c hands syMallocInit
// everything from the end of the program's BSS to a fixed address:
//
//     mov.l   @r0,r4          ; r0 = &_end (a word of crt0's section table)
//     mov.l   @(disp,pc),r5   ; the heap's end, a literal (0x8c800000 there)
//     mov     #-32,r0
//     or      r2,r4           ; r2 = 0x80000000
//     and     r0,r4
//     add     #32,r4          ; area = (_end | P1) & ~31) + 32
//     sub     r4,r5           ; size = end - area
//
// Jet Set Radio's JET_PAL.BIN does it for 0x8c35d740..0x8c800000, and every
// base the learned memory map offered was in there: 0x8c650000 and 0x8c580000
// were overwritten while a level loaded (the console rebooted, the hook being
// on every interrupt), because the map only knows the blocks a session has
// seen written so far, and a heap fills differently each time. Above the
// heap the title keeps fixed buffers at fixed addresses; there is no hole.
//
// So the loader goes at the heap's TOP and the heap's end literal is lowered
// to the loader's base: one word, unlike the start, which is crt0's own `_end`
// (raising it would make crt0 clear the loader with the BSS).
//
// THE PROGRAM THAT SETS THE HEAP IS NOT ALWAYS THE ONE THIS HOST UPLOADS.
// Jet Set Radio boots a small 1ST_READ.BIN that reads JET_PAL.BIN off the disc
// into a buffer, copies it to 0x8c010000 and runs it. So the programs on the
// disc are scanned too, and the word is patched in the sectors served
// (`DiscPatch`), wherever the read lands.
//
// A SECOND FORM: THE HEAP TO THE TOP OF RAM (Skies of Arcadia, 2026-10-11).
// Its sbInitSystem (1ST_READ.BIN, 0x8c015e02) has no fixed end: the end is
// `_end`'s segment with the literal 0x0d000000, so the heap is everything from
// the BSS to 0x8d000000 and no base above the program is outside it. With the
// loader at 0x8cfd0000 the console reset at EXEC, before answering anything:
//
//     mov.l   @(disp,pc),r3   ; 0xe0000000
//     mov.l   @(disp,pc),r1   ; &_end
//     mov.l   @r1,r5
//     and     r3,r5
//     mov.l   @(disp,pc),r2   ; the heap's end, 0x0d000000
//     or      r2,r5           ; end = (_end & 0xe0000000) | 0x0d000000
//     mov.l   @(disp,pc),r1   ; 0x80000000
//     mov.l   @(disp,pc),r3   ; &_end
//     mov.l   @r3,r0
//     or      r1,r0
//     mov     #-32,r2
//     and     r2,r0
//     sub     r0,r5
//     add     #-32,r5         ; size = end - (((_end | P1) & ~31) + 32)
//
// The same function loads the literal a second time to keep the size in a
// global; lowering the one word lowers both. The literal is the same kind of
// word as the first form's, so the same patch applies.
//
// Tony Hawk's Pro Skater 2 PAL (2026-10-11) has the same arithmetic scheduled
// differently (1ST_READ.BIN, 0x8c062e10, heap 0x8c3495a0..0x8d000000): the
// loader at 0x8ce00000 was in it and the console reset at the menu, right
// after a 1.5 MB read to 0x8ce82380..0x8cfffb80, the heap's top.
//
//     mov.l   @(disp,pc),r1   ; &_end
//     mov.l   @r1,r5
//     mov.l   @(disp,pc),r4   ; 0x80000000
//     mov.l   @(disp,pc),r1   ; 0xe0000000
//     or      r5,r4
//     and     r1,r5
//     mov.l   @(disp,pc),r1   ; the heap's end, 0x0d000000
//     mov     #-32,r8
//     or      r1,r5
//     and     r8,r4
//     mov.l   @(disp,pc),r1   ; syMallocInit
//     add     r8,r5
//     sub     r4,r5
//     add     #32,r4
//
// Its sbInitSystem is 0x52de0 into the program, linked after the game's own
// code: the boot program is scanned whole (`disc_katana_heaps`).
//
// Its TOP is not free either: the title points the Maple DMA at 0x0cff0000,
// inside the heap's last 64 KB. So the loader may sit up to `TOP_SLACK` under
// the top, the heap above it given up with it (`katana_loader_base` takes the
// highest base its caller accepts).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ANY SCHEDULE, READ FROM WHAT THE CODE DOES WITH THE END (2026-10-11).
//
// Three byte patterns above, one per title, and the fourth title matched none
// of them. Unreal Tournament PAL's sbInitSystem (1ST_READ.BIN, 0x8c05b0e8)
// is the same arithmetic in yet another order, with its own end, 0x0cfdd000:
// a heap 0x8c313740..0x8cfdd000. With the loader at 0x8c940000, the middle of
// RAM no read had landed in, the console went silent after seven sector reads.
// Two more functions size the same heap again (0x8c05b1a6 keeps the size in a
// global, 0x8c05b26a sets it up afresh), one of them sharing the first's
// literal pool: two words to lower, not one. And Snow Surfers, run for weeks
// with its loader at 0x8ce00000, has two sbInitSystems of a fourth schedule
// (0x8c081bda, 0x8c081d10) handing syMalloc everything to 0x8d000000: that
// loader was inside a heap that happened not to fill so far.
//
// A byte pattern is one compiler's schedule of one library's code. What all of
// them share is what the code does with the end: A HEAP'S SIZE IS ITS END
// MINUS ITS START -- a `sub` whose minuend comes from a literal naming high
// RAM and whose subtrahend is a known RAM address at or above the program
// (`_end`, rounded). So each program is read straight through once by a small
// evaluator: it knows literals, immediates, words read through a known pointer
// (`&_end`) and a few ALU operations, and which literal a value still names
// (the same RAM, give or take an alignment: `& ~31`, `+ 32`, the segment). An
// unconditional transfer (rts, bra, jmp) ends what it knows, a call clobbers
// r0..r7, a conditional branch is read through. Each end it finds names the
// literal; lowering that word lowers the end, whatever the allocator, the
// library version or the schedule (`KatanaHeap::patch`).
//
// A literal is taken only if every instruction that loads it sizes a heap, or
// sits in a function that does (Skies of Arcadia's loads it again to keep the
// size): a word also used as a buffer's address would move the buffer onto the
// loader. Nothing under `MIN_LEFT`, nothing in Windows CE or KOS programs
// (their RAM has rules of their own: `wince::take`, `kos_mem_top_patches`).
//
// Not seen: an end passed as an end (`init(start, end)`, no subtraction), an
// end that is not a literal (from a table, from the hardware), a heap whose
// size is a constant (HLib, above, has its own rule), a stack moved to the top
// of RAM (Unreal Tournament's is, above its heap: a rule for that found
// "stacks" in Crazy Taxi, Sonic Adventure and data files read as code, and was
// dropped).
// ---------------------------------------------------------------------------

/// Where a Katana program runs, wherever it was read to.
const KATANA_LOAD: u32 = 0x8c01_0000;
/// The reach of `mov.l @(disp,pc)`: a literal is named from at most this far.
const PC_REACH: usize = 1024;
/// How much of a disc file is searched: sbinit is linked right after crt0
/// (0x3dbc and 0x3f50 into Jet Set Radio's two programs). The program IP.BIN
/// boots is searched whole: Tony Hawk's Pro Skater 2's sbinit is 0x52de0 into
/// it, Unreal Tournament's `main` 0x48e80.
const SCAN_BYTES: u32 = 0x1_0000;
/// How far an ALU result may stray from its literal and still name it: an
/// alignment (`& ~31`, `+ 32`), not another buffer.
const SAME_RAM: u32 = 0x40;
/// How much heap may be given up above the loader, when the top is not free.
const TOP_SLACK: u32 = 0x4_0000;

/// One heap a program sets up, and the literal that ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KatanaHeap {
    /// Its start (P1): what its size is computed from.
    pub start: u32,
    /// Its end (P1), from the literal.
    pub end: u32,
    /// Where that literal is in RAM once the program runs, and as it is.
    pub end_at: u32,
    end_raw: u32,
}

/// Whether `w` can be the end of RAM a heap or stack runs to: an address in
/// main RAM or one past it, in P0, P1 or P2.
fn ends_ram(w: u32) -> bool {
    matches!(w & 0xe000_0000, 0 | 0x8000_0000 | 0xa000_0000)
        && (0x0c00_0001..=0x0d00_0000).contains(&(w & 0x1fff_ffff))
}

/// A literal: its offset in the program, the word, and where it was loaded.
type Lit = (usize, u32, usize);

/// What a register holds, as far as one straight read can tell.
#[derive(Clone, Copy, Debug, Default)]
struct Val {
    /// Its value, when every input was known.
    v: Option<u32>,
    /// The literal it still names.
    lit: Option<Lit>,
}

impl Val {
    fn known(v: u32) -> Self {
        Val { v: Some(v), lit: None }
    }
}

/// `lit`, if `v` still names its RAM.
fn carry(lit: Option<Lit>, v: Option<u32>) -> Option<Lit> {
    let (l, v) = (lit?, v?);
    ((v & 0x1fff_ffff).abs_diff(l.1 & 0x1fff_ffff) <= SAME_RAM).then_some(l)
}

/// A heap size the evaluator saw: `end - start`, `end` from a literal.
struct Size {
    lit: Lit,
    start: u32,
}

/// What an instruction does to control flow, after its delay slot if it has one.
enum Flow {
    Next,
    Call,
    Stop,
}

/// One program as it will run: its bytes from `base`, and how to read a word
/// of RAM it names (`&_end`) that the bytes may not hold.
struct Code<'a> {
    data: &'a [u8],
    base: u32,
    read_word: &'a dyn Fn(u32) -> Option<u32>,
}

impl Code<'_> {
    fn op(&self, i: usize) -> Option<u16> {
        (i + 2 <= self.data.len()).then(|| le16(self.data, i))
    }

    /// Ends control flow for good: rts, rte, bra, braf, jmp.
    fn stops(op: u16) -> bool {
        op == 0x000b || op == 0x002b || op >> 12 == 0xa || op & 0xf0ff == 0x0023 || op & 0xf0ff == 0x402b
    }

    /// One instruction at `i` on `r`.
    fn step(&self, op: u16, i: usize, r: &mut [Val; 16], seen: &mut Vec<Size>) -> Flow {
        let n = ((op >> 8) & 0xf) as usize;
        let m = ((op >> 4) & 0xf) as usize;
        let simm = op as u8 as i8 as i32 as u32;
        let uimm = (op & 0xff) as u32;
        let none = Val::default();
        // An address register moved by `by`: known if it was, naming nothing.
        let moved = |x: Val, by: i32| Val { v: x.v.map(|v| v.wrapping_add(by as u32)), lit: None };
        let alu = |a: Val, b: Val, v: Option<u32>| Val { v, lit: carry(a.lit, v).or_else(|| carry(b.lit, v)) };
        match op >> 12 {
            0x0 => match op & 0xf {
                0xb if op == 0x000b || op == 0x002b => return Flow::Stop,
                0x3 => match op & 0xf0 {
                    0x00 => return Flow::Call,
                    0x20 => return Flow::Stop,
                    _ => {}
                },
                0x9 if op & 0xff == 0x29 => r[n] = none,
                0x2 | 0xa | 0xc | 0xd | 0xe => r[n] = none,
                0xf => (r[n], r[m]) = (none, none),
                _ => {}
            },
            0x2 => match op & 0xf {
                0x4 => r[n] = moved(r[n], -1),
                0x5 => r[n] = moved(r[n], -2),
                0x6 => r[n] = moved(r[n], -4),
                0x9 => r[n] = alu(r[n], r[m], r[n].v.zip(r[m].v).map(|(a, b)| a & b)),
                0xa => r[n] = alu(r[n], r[m], r[n].v.zip(r[m].v).map(|(a, b)| a ^ b)),
                0xb => r[n] = alu(r[n], r[m], r[n].v.zip(r[m].v).map(|(a, b)| a | b)),
                0xd => r[n] = none,
                _ => {}
            },
            0x3 => match op & 0xf {
                0x8 => {
                    if let (Some(lit), Some(_), Some(start)) = (r[n].lit, r[n].v, r[m].v) {
                        seen.push(Size { lit, start });
                    }
                    r[n] = alu(r[n], r[m], r[n].v.zip(r[m].v).map(|(a, b)| a.wrapping_sub(b)));
                }
                0xc => {
                    r[n] = alu(r[n], r[m], r[n].v.zip(r[m].v).map(|(a, b)| a.wrapping_add(b)));
                }
                0x4 | 0xa | 0xb | 0xe | 0xf => r[n] = none,
                _ => {}
            },
            0x4 => match op & 0xff {
                0x0b => return Flow::Call,
                0x2b => return Flow::Stop,
                0x00 | 0x20 => r[n] = Val { v: r[n].v.map(|v| v << 1), lit: None },
                0x01 => r[n] = Val { v: r[n].v.map(|v| v >> 1), lit: None },
                0x21 => r[n] = Val { v: r[n].v.map(|v| ((v as i32) >> 1) as u32), lit: None },
                0x08 => r[n] = Val { v: r[n].v.map(|v| v << 2), lit: None },
                0x09 => r[n] = Val { v: r[n].v.map(|v| v >> 2), lit: None },
                0x18 => r[n] = Val { v: r[n].v.map(|v| v << 8), lit: None },
                0x19 => r[n] = Val { v: r[n].v.map(|v| v >> 8), lit: None },
                0x28 => r[n] = Val { v: r[n].v.map(|v| v << 16), lit: None },
                0x29 => r[n] = Val { v: r[n].v.map(|v| v >> 16), lit: None },
                0x10 => r[n] = moved(r[n], -1),
                0x04 | 0x05 | 0x24 | 0x25 => r[n] = none,
                x if x & 0xf == 0x6 || x & 0xf == 0x7 => r[n] = moved(r[n], 4),
                x if x & 0xf == 0x2 || x & 0xf == 0x3 => r[n] = moved(r[n], -4),
                x if x & 0xf == 0xc || x & 0xf == 0xd => r[n] = none,
                x if x & 0xf == 0xf => (r[n], r[m]) = (none, none),
                _ => {}
            },
            0x5 => {
                let at = r[m].v.map(|v| v.wrapping_add((op & 0xf) as u32 * 4));
                r[n] = Val { v: at.and_then(|a| (self.read_word)(a)), lit: None };
            }
            0x6 => match op & 0xf {
                0x3 => r[n] = r[m],
                0x2 | 0x6 => {
                    let v = r[m].v.and_then(|a| (self.read_word)(a));
                    if op & 0xf == 0x6 && m != n {
                        r[m] = moved(r[m], 4);
                    }
                    r[n] = Val { v, lit: None };
                }
                0x4 | 0x5 => {
                    if m != n {
                        r[m] = moved(r[m], if op & 0xf == 0x4 { 1 } else { 2 });
                    }
                    r[n] = none;
                }
                _ => r[n] = none,
            },
            0x7 => {
                let v = r[n].v.map(|v| v.wrapping_add(simm));
                r[n] = alu(r[n], Val::known(simm), v);
            }
            0x8 => match op >> 8 {
                0x84 | 0x85 => r[0] = none,
                _ => {}
            },
            0x9 => {
                let at = i + 4 + uimm as usize * 2;
                r[n] = self.op(at).map_or(none, |w| Val::known(w as i16 as i32 as u32));
            }
            0xa => return Flow::Stop,
            0xb => return Flow::Call,
            0xc => match op >> 8 {
                0xc4..=0xc6 => r[0] = none,
                0xc7 => r[0] = Val::known(p1(self.base).wrapping_add((((i + 4) & !3) + uimm as usize * 4) as u32)),
                0xc9 => r[0] = alu(r[0], Val::known(uimm), r[0].v.map(|v| v & uimm)),
                0xca => r[0] = alu(r[0], Val::known(uimm), r[0].v.map(|v| v ^ uimm)),
                0xcb => r[0] = alu(r[0], Val::known(uimm), r[0].v.map(|v| v | uimm)),
                _ => {}
            },
            0xd => {
                let (_, at) = pc_load(op, i).unwrap_or((0, usize::MAX));
                r[n] = match (at.checked_add(4)).is_some_and(|e| e <= self.data.len()) {
                    true => {
                        let w = le32(self.data, at);
                        Val { v: Some(w), lit: ends_ram(w).then_some((at, w, i)) }
                    }
                    false => none,
                };
            }
            0xe => r[n] = Val::known(simm),
            0xf => match op & 0xf {
                0x9 => r[m] = none,
                0xb => r[n] = none,
                _ => {}
            },
            _ => {}
        }
        Flow::Next
    }

    /// Read the program straight through, and every heap size seen.
    fn sizes(&self) -> Vec<Size> {
        let mut seen = vec![];
        let mut r = [Val::default(); 16];
        let mut pending: Option<Flow> = None;
        let mut i = 0;
        while let Some(op) = self.op(i) {
            let flow = self.step(op, i, &mut r, &mut seen);
            // The delay slot ran: now the branch.
            match pending.take() {
                Some(Flow::Call) => r[..8].fill(Val::default()),
                Some(Flow::Stop) => r = [Val::default(); 16],
                _ if !matches!(flow, Flow::Next) => pending = Some(flow),
                _ => {}
            }
            i += 2;
        }
        seen
    }

    /// Whether nothing between `a` and `b` ends control flow: the same function.
    fn same_stretch(&self, a: usize, b: usize) -> bool {
        !(a.min(b)..a.max(b)).step_by(2).any(|k| self.op(k).is_some_and(Self::stops))
    }

    /// Every heap end this program sets up from a literal.
    fn ends(&self, image_end: u32) -> Vec<KatanaHeap> {
        let sizes = self.sizes();
        let floor = p1(self.base);
        let mut out: Vec<KatanaHeap> = vec![];
        for s in &sizes {
            let (at, raw, _) = s.lit;
            let (start, end) = (p1(s.start), p1(raw));
            let end_at = floor.wrapping_add(at as u32);
            if !names_ram(s.start)
                || start < floor
                || end <= image_end
                || end < start.saturating_add(MIN_LEFT)
                || out.iter().any(|h| h.end_at == end_at)
            {
                continue;
            }
            // Every load of the word sizes a heap, or is in a function that does.
            let sizing: Vec<usize> = sizes.iter().filter(|t| t.lit.0 == at).map(|t| t.lit.2).collect();
            let loaders = (at.saturating_sub(PC_REACH)..at)
                .step_by(2)
                .filter(|&j| self.op(j).and_then(|o| pc_load(o, j)).is_some_and(|(_, t)| t == at));
            if loaders.into_iter().all(|j| sizing.iter().any(|&k| k == j || self.same_stretch(j, k))) {
                out.push(KatanaHeap { start, end, end_at, end_raw: raw });
            }
        }
        out
    }
}

/// Every heap end a program sets up from a literal (above), read as it runs
/// from `address`.
pub fn program_heaps(buf: &[u8], address: u32) -> Vec<KatanaHeap> {
    let mut found = vec![];
    for (base, data) in payload_spans(buf, address) {
        let word = |a: u32| {
            let off = p1(a).checked_sub(p1(base))? as usize;
            (a & 3 == 0 && off + 4 <= data.len()).then(|| le32(data, off))
        };
        let image_end = p1(base).wrapping_add(data.len() as u32);
        found.extend(Code { data, base, read_word: &word }.ends(image_end));
    }
    found
}

impl KatanaHeap {
    /// Where the loader goes: the highest 64 KB boundary that leaves its span
    /// inside the heap.
    pub fn loader_base(&self) -> Option<u32> {
        let base = self.end.checked_sub(crate::loaders::LOADER_SPAN)? & !0xffff;
        (crate::loaders::is_high(base) && base >= self.start + MIN_LEFT).then_some(base)
    }

    /// The 64 KB boundaries the loader may take, highest first: the top, then
    /// down to `TOP_SLACK` under it, the heap above the loader given up.
    pub fn loader_bases(&self) -> impl Iterator<Item = u32> + '_ {
        let top = self.loader_base();
        (0..=TOP_SLACK / 0x1_0000)
            .filter_map(move |k| top?.checked_sub(k * 0x1_0000))
            .filter(|&b| crate::loaders::is_high(b) && b >= self.start + MIN_LEFT)
    }

    /// The heap's end lowered to a loader at `base`, as (RAM address, word).
    /// Nothing when the loader is outside the heap; an error when it is not
    /// near its top, where lowering the end would throw away the heap above it.
    pub fn patch(&self, base: u32) -> Result<Option<(u32, u32)>, String> {
        let (lo, hi) = (p1(base), p1(base) + crate::loaders::LOADER_SPAN);
        if hi <= self.start || lo >= self.end {
            return Ok(None);
        }
        if !self.loader_bases().any(|b| b == lo) {
            return Err(format!(
                "it is not at the top of the heap (0x{:08x}..0x{:08x}) or within 0x{TOP_SLACK:x} \
                 under it, the only part of it the end can be lowered past",
                self.start, self.end
            ));
        }
        Ok(Some((self.end_at, (lo & 0x1fff_ffff) | (self.end_raw & 0xe000_0000))))
    }
}

/// A program on the disc that sets up a syMalloc heap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscHeap {
    pub file: String,
    /// The file's first sector, as `read_sector` takes it, and its length.
    pub lba: u32,
    pub size: u32,
    pub heap: KatanaHeap,
}

/// A word to change in the sectors served, wherever the read lands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscPatch {
    pub file: String,
    pub lba: u32,
    /// Byte offset of the word in that sector (4-aligned: never split).
    pub off: usize,
    pub was: u32,
    pub value: u32,
}

/// Every heap end the programs in the boot area's root set up from a literal
/// (`Code::ends`), read as Katana runs them: from 0x8c010000. Reads
/// the first `SCAN_BYTES` of each `.BIN`, all of the boot program, and one
/// sector more for `_end`. Nothing for a Windows CE disc, and nothing in a KOS
/// program: their RAM has rules of their own.
pub fn disc_katana_heaps(disc: &dyn DiscFormat) -> Vec<DiscHeap> {
    let root = crate::disc_formats::iso9660::list_root(disc, disc.boot_sector());
    let boot = crate::disc_formats::types::ip_bin_at(disc, disc.boot_sector())
        .and_then(|h| crate::disc_formats::iso9660::boot_file_name(&h));
    if boot.as_deref().is_some_and(|b| b.eq_ignore_ascii_case("0WINCEOS.BIN")) {
        return vec![];
    }
    let mut out = vec![];
    for e in root.iter().filter(|e| {
        !e.is_dir
            && e.name.to_ascii_uppercase().ends_with(".BIN")
            && e.size >= SCAN_BYTES
            && e.size <= crate::disc_formats::iso9660::MAX_FILE_BYTES
    }) {
        let whole = boot.as_deref().is_some_and(|b| b.eq_ignore_ascii_case(&e.name));
        let scan = if whole { e.size } else { SCAN_BYTES };
        let Ok(mut head) = disc.read_sector(e.lba, scan.div_ceil(2048)) else {
            continue;
        };
        head.truncate(scan as usize);
        let word = |a: u32| {
            let off = p1(a).checked_sub(KATANA_LOAD)?;
            if a & 3 != 0 || off + 4 > e.size {
                return None;
            }
            match head.get(off as usize..off as usize + 4) {
                Some(b) => Some(u32::from_le_bytes(b.try_into().ok()?)),
                None => {
                    let s = disc.read_sector(e.lba + off / 2048, 1).ok()?;
                    let o = (off % 2048) as usize;
                    Some(u32::from_le_bytes(s.get(o..o + 4)?.try_into().ok()?))
                }
            }
        };
        if is_kos_binary(&head) {
            continue;
        }
        let code = Code { data: &head, base: KATANA_LOAD, read_word: &word };
        for h in code.ends(KATANA_LOAD + e.size) {
            out.push(DiscHeap { file: e.name.clone(), lba: e.lba, size: e.size, heap: h });
        }
    }
    out
}

impl DiscHeap {
    /// The constants of this program, run from 0x8c010000, that an instruction
    /// loads and that name RAM a loader at `base` occupies: what the placement
    /// rules check a base against, for a program they never see.
    pub fn literals_in_loader(&self, disc: &dyn DiscFormat, base: u32) -> Result<Vec<(u32, u32)>, String> {
        let mut bytes = disc
            .read_sector(self.lba, self.size.div_ceil(2048))
            .map_err(|e| format!("could not read {}: {e}", self.file))?;
        bytes.truncate(self.size as usize);
        Ok(literals_in_loader_footprint(&bytes, KATANA_LOAD, base))
    }

    /// The sector word that lowers this heap's end to a loader at `base`.
    pub fn patch(&self, base: u32) -> Result<Option<DiscPatch>, String> {
        let Some((at, value)) = self.heap.patch(base)? else {
            return Ok(None);
        };
        let off = at - KATANA_LOAD;
        Ok(Some(DiscPatch {
            file: self.file.clone(),
            lba: self.lba + off / 2048,
            off: (off % 2048) as usize,
            was: self.heap.end_raw,
            value,
        }))
    }
}

/// Where the loader goes when its base would be inside a syMalloc heap: the
/// highest base `free` accepts at the top of the lowest-ending heap it is in
/// (or up to `TOP_SLACK` under it), if every heap it then sits in can be
/// lowered past it.
pub fn katana_loader_base(heaps: &[KatanaHeap], base: u32, free: &dyn Fn(u32) -> bool) -> Option<u32> {
    let inside = |b: u32| heaps.iter().filter(move |h| h.patch(b).map_or(true, |p| p.is_some()));
    let lowest = inside(base).filter(|h| h.loader_base().is_some()).min_by_key(|h| h.end)?;
    lowest.loader_bases().find(|&b| inside(b).all(|h| h.patch(b).is_ok()) && free(b))
}

/// Put the disc patches into a read of `buf.len()` bytes from `start`. Only a
/// word that is still the disc's own is changed. Returns the words changed.
pub fn patch_disc_read(patches: &[DiscPatch], start: u32, buf: &mut [u8]) -> usize {
    let mut n = 0;
    for p in patches {
        let Some(sector) = p.lba.checked_sub(start) else { continue };
        let i = sector as usize * 2048 + p.off;
        if let Some(w) = buf.get_mut(i..i + 4)
            && *w == p.was.to_le_bytes()
        {
            w.copy_from_slice(&p.value.to_le_bytes());
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shenmue II's pool (PAL 1.001, 1ST_READ at 0x8c010000), at 0x8c051968.
    fn shenmue2_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x41a00];
        let pool = 0x41968;
        for (k, w) in [
            0x8c36_0000u32,
            0x8c36_0020,
            0x8ceb_ffe0,
            TAG_FREE,
            0x00b5_ffc0,
            TAG_USED,
            TAG_LIB,
        ]
        .iter()
        .enumerate()
        {
            img[pool + 4 * k..pool + 4 * k + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    #[test]
    fn the_pool_is_found_and_the_loader_goes_at_the_bottom() {
        let h = hlib_heap(&shenmue2_like(), 0x8c01_0000).expect("pool");
        assert_eq!((h.start, h.end), (0x8c36_0000, 0x8ceb_ffe0));
        assert_eq!(h.loader_base(), Some(0x8c36_0000));
        // What was measured by hand on 2026-10-05.
        assert_eq!(
            h.patches(0x8c36_0000).unwrap(),
            vec![
                (0x8c05_1968, 0x8c37_0000),
                (0x8c05_196c, 0x8c37_0020),
                (0x8c05_1978, 0x00b4_ffc0),
            ]
        );
        assert!(h.names_own_bound(0x8c36_0020));
    }

    #[test]
    fn a_loader_at_the_top_lowers_the_end_and_one_in_the_middle_is_refused() {
        let h = hlib_heap(&shenmue2_like(), 0x8c01_0000).unwrap();
        assert_eq!(
            h.patches(0x8ceb_0000).unwrap(),
            vec![(0x8c05_1970, 0x8cea_ffe0), (0x8c05_1978, 0x00b4_ffc0)]
        );
        assert!(h.patches(0x8c80_0000).is_err());
        assert!(h.patches(0x8cf0_0000).unwrap().is_empty());
        assert!(h.patches(0x8c30_0000).unwrap().is_empty());
    }

    #[test]
    fn an_unaligned_start_gives_the_next_boundary_and_keeps_p2_literals_p2() {
        let mut img = shenmue2_like();
        let pool = 0x41968;
        img[pool..pool + 4].copy_from_slice(&0xac35_8000u32.to_le_bytes());
        img[pool + 4..pool + 8].copy_from_slice(&0xac35_8020u32.to_le_bytes());
        img[pool + 16..pool + 20].copy_from_slice(&(0x8ceb_ffe0u32 - 0x8c35_8020).to_le_bytes());
        let h = hlib_heap(&img, 0x8c01_0000).unwrap();
        assert_eq!(h.loader_base(), Some(0x8c36_0000));
        let p = h.patches(0x8c36_0000).unwrap();
        assert_eq!(p[0], (0x8c05_1968, 0xac37_0000));
        assert_eq!(p[1], (0x8c05_196c, 0xac37_0020));
    }

    /// Jet Set Radio PAL's sbInitSystem (JET_PAL.BIN, run at 0x8c010000): the
    /// sequence at 0x8c013f4c and its literals, with `&_end` pointed at a word
    /// kept inside this smaller image.
    fn jsr_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x4100];
        let code: [u16; 9] = [0xd024, 0xd225, 0x6402, 0xd525, 0xe0e0, 0x242b, 0x2409, 0x7420, 0x3548];
        for (k, op) in code.iter().enumerate() {
            img[0x3f4c + 2 * k..0x3f4e + 2 * k].copy_from_slice(&op.to_le_bytes());
        }
        for (at, w) in [(0x3fe0, 0x8c01_4080u32), (0x3fe4, 0x8000_0000), (0x3fe8, 0x8c80_0000), (0x4080, 0x8c35_d720)] {
            img[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    /// The one end a program sets up.
    fn one_end(img: &[u8]) -> KatanaHeap {
        match program_heaps(img, 0x8c01_0000).as_slice() {
            [h] => *h,
            other => panic!("expected one end, found {other:?}"),
        }
    }

    #[test]
    fn jet_set_radios_heap_is_found_and_the_loader_goes_at_its_top() {
        let h = one_end(&jsr_like());
        assert_eq!((h.start, h.end, h.end_at), (0x8c35_d740, 0x8c80_0000, 0x8c01_3fe8));
        assert_eq!(h.loader_base(), Some(0x8c7f_0000));
        assert_eq!(h.patch(0x8c7f_0000).unwrap(), Some((0x8c01_3fe8, 0x8c7f_0000)));
        // Outside: nothing to do. In the middle: refused.
        assert_eq!(h.patch(0x8c80_0000).unwrap(), None);
        assert_eq!(h.patch(0x8c30_0000).unwrap(), None);
        assert!(h.patch(0x8c65_0000).is_err());
        // The bases the learned map gave move to the top; one above stays.
        assert_eq!(katana_loader_base(&[h], 0x8c65_0000, &|_| true), Some(0x8c7f_0000));
        assert_eq!(katana_loader_base(&[h], 0x8c58_0000, &|_| true), Some(0x8c7f_0000));
        assert_eq!(katana_loader_base(&[h], 0x8cef_0000, &|_| true), None);
    }

    #[test]
    fn a_heap_end_another_function_loads_is_not_taken() {
        let mut img = jsr_like();
        // sbInitSystem returns (rts; nop), and mov.l @(disp,pc),r1 naming the
        // same literal follows, from 0x3f70: another function's use of it.
        img[0x3f60..0x3f62].copy_from_slice(&0x000bu16.to_le_bytes());
        img[0x3f62..0x3f64].copy_from_slice(&0x0009u16.to_le_bytes());
        img[0x3f70..0x3f72].copy_from_slice(&0xd11du16.to_le_bytes());
        assert_eq!(program_heaps(&img, 0x8c01_0000), vec![]);
    }

    /// Skies of Arcadia PAL's sbInitSystem (1ST_READ.BIN, 0x8c015e02): the
    /// heap's end is `_end`'s segment | 0x0d000000, its literal loaded again at
    /// 0x8c015e54; `&_end` pointed at a word kept inside this smaller image.
    fn skies_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x6000];
        let code: [u16; 14] = [
            0xd32a, 0xd12a, 0x6512, 0x2539, 0xd22a, 0x252b, 0xd12a, 0xd327, 0x6032, 0x201b, 0xe2e0, 0x2029,
            0x3508, 0x75e0,
        ];
        for (k, op) in code.iter().enumerate() {
            img[0x5e02 + 2 * k..0x5e04 + 2 * k].copy_from_slice(&op.to_le_bytes());
        }
        img[0x5e54..0x5e56].copy_from_slice(&0xd117u16.to_le_bytes());
        for (at, w) in [
            (0x5eac, 0xe000_0000u32),
            (0x5eb0, 0x8c01_5f00),
            (0x5eb4, 0x0d00_0000),
            (0x5eb8, 0x8000_0000),
            (0x5f00, 0x8c55_34c0),
        ] {
            img[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    #[test]
    fn a_heap_to_the_top_of_ram_is_found_and_the_loader_goes_under_the_maple_list() {
        let h = one_end(&skies_like());
        // The start is what the size is computed from: `_end` rounded, before
        // the 32 bytes sbInitSystem takes off both sides afterwards.
        assert_eq!((h.start, h.end, h.end_at), (0x8c55_34c0, 0x8d00_0000, 0x8c01_5eb4));
        assert_eq!(h.loader_base(), Some(0x8cff_0000));
        // The literal keeps its segment bits (none): the end is `_end`'s.
        assert_eq!(h.patch(0x8cfe_0000).unwrap(), Some((0x8c01_5eb4, 0x0cfe_0000)));
        assert!(h.patch(0x8cf0_0000).is_err());
        // 0x8cff0000 named by the title (its Maple DMA list): the next one down.
        let free = |b: u32| b != 0x8cff_0000;
        assert_eq!(katana_loader_base(&[h], 0x8cfd_0000, &free), Some(0x8cfe_0000));
        assert_eq!(katana_loader_base(&[h], 0x8cfd_0000, &|_| false), None);
    }

    /// Tony Hawk's Pro Skater 2 PAL's sbInitSystem (1ST_READ.BIN, 0x8c062e10):
    /// the same heap as Skies of Arcadia's, scheduled differently, with the
    /// displacements and literals of the real program.
    fn thps2_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x5_4000];
        let code: [u16; 14] = [
            0xd13b, 0x6512, 0xd43b, 0xd13c, 0x245b, 0x2519, 0xd13b, 0xe8e0, 0x251b, 0x2489, 0xd13a, 0x358c,
            0x3548, 0x7420,
        ];
        for (k, op) in code.iter().enumerate() {
            img[0x5_2e10 + 2 * k..0x5_2e12 + 2 * k].copy_from_slice(&op.to_le_bytes());
        }
        for (at, w) in [
            (0x5_2f00, 0x8c05_3eb4u32),
            (0x5_2f04, 0x8000_0000),
            (0x5_2f08, 0xe000_0000),
            (0x5_2f0c, 0x0d00_0000),
            (0x5_2f10, 0x8c04_81c4),
            (0x4_3eb4, 0x8c34_9580),
        ] {
            img[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    #[test]
    fn the_second_scheduling_of_a_heap_to_the_top_is_found_too() {
        let h = one_end(&thps2_like());
        assert_eq!((h.start, h.end, h.end_at), (0x8c34_9580, 0x8d00_0000, 0x8c06_2f0c));
        assert_eq!(h.patch(0x8cfd_0000).unwrap(), Some((0x8c06_2f0c, 0x0cfd_0000)));
        // It names 0x8cfe0000 and 0x8cff0000 (gdFs buffers) and 0x0cff0000.
        let free = |b: u32| b < 0x8cfe_0000;
        assert_eq!(katana_loader_base(&[h], 0x8ce0_0000, &free), Some(0x8cfd_0000));
        // Without its `sub r4,r5` nothing says 0x0d000000 is an end.
        let mut img = thps2_like();
        img[0x5_2e28..0x5_2e2a].copy_from_slice(&0x0009u16.to_le_bytes());
        assert_eq!(program_heaps(&img, 0x8c01_0000), vec![]);
    }

    #[test]
    fn a_top_of_ram_end_loaded_from_outside_sbinitsystem_is_not_taken() {
        let mut img = skies_like();
        // mov.l @(disp,pc),r1 naming the same literal, in a function that
        // returns (rts; nop) before the sequence.
        img[0x5d00..0x5d02].copy_from_slice(&0xd16cu16.to_le_bytes());
        img[0x5d02..0x5d04].copy_from_slice(&0x000bu16.to_le_bytes());
        img[0x5d04..0x5d06].copy_from_slice(&0x0009u16.to_le_bytes());
        assert_eq!(program_heaps(&img, 0x8c01_0000), vec![]);
        // In sbInitSystem itself (0x8c015e54 already loads it again): taken.
        assert_eq!(one_end(&skies_like()).end_at, 0x8c01_5eb4);
    }

    /// Unreal Tournament PAL's three heap set-ups (1ST_READ.BIN): sbInitSystem
    /// (0x8c05b0e8), a function sizing the heap again from the same literal
    /// pool (0x8c05b1a6), and another set-up with a pool of its own
    /// (0x8c05b26a), with the opcodes and literals of the real program; each
    /// function ends with rts here, as there.
    fn ut_like() -> Vec<u8> {
        let mut img = vec![0u8; 0x4_b400];
        let put = |img: &mut Vec<u8>, at: usize, ops: &[u16]| {
            for (k, op) in ops.iter().enumerate() {
                img[at + 2 * k..at + 2 * k + 2].copy_from_slice(&op.to_le_bytes());
            }
        };
        // jsr @r1 with `mov #-32,r8` in its delay slot: r8 outlives the call.
        put(&mut img, 0x4_b0e4, &[0x410b, 0xe8e0]);
        put(&mut img, 0x4_b0e8, &[
            0xdb40, 0xd441, 0xd141, 0x65b2, 0x245b, 0x2519, 0xd140, 0x251b, 0x2489, 0xd140, 0x358c, 0x3548,
            0x410b, 0x7420, 0x000b, 0x0009,
        ]);
        put(&mut img, 0x4_b1a6, &[
            0xdc11, 0xd111, 0x62c2, 0xe3e0, 0x212b, 0x2139, 0xd323, 0x7120, 0x2312, 0xd30e, 0x2239, 0xd30e,
            0x71e0, 0x223b, 0x72e0, 0xdc1f, 0x3218, 0xd11f, 0x4c0b, 0x2122, 0x000b, 0x0009,
        ]);
        put(&mut img, 0x4_b26a, &[
            0xd10a, 0xd40a, 0x6512, 0x245b, 0xe1e0, 0x2419, 0xd109, 0x2519, 0xd109, 0x251b, 0xd109, 0x75e0,
            0x3548, 0x410b, 0x7420, 0x6fe3, 0x4f26, 0x000b, 0x6ef6,
        ]);
        for (at, w) in [
            (0x4_13acusize, 0x8c31_3740u32), // &_end's word (0x8c0513ac), read by all three
            (0x4_b1ec, 0x8c05_13ac),
            (0x4_b1f0, 0x8000_0000),
            (0x4_b1f4, 0xe000_0000),
            (0x4_b1f8, 0x0cfd_d000),
            (0x4_b1fc, 0x8c01_63fc),
            (0x4_b240, 0x8c2e_8400),
            (0x4_b244, 0x8c1d_554c),
            (0x4_b248, 0x8c2c_f010),
            (0x4_b294, 0x8c05_13ac),
            (0x4_b298, 0x8000_0000),
            (0x4_b29c, 0xe000_0000),
            (0x4_b2a0, 0x0cfd_d000),
            (0x4_b2a4, 0x8c01_63fc),
        ] {
            img[at..at + 4].copy_from_slice(&w.to_le_bytes());
        }
        img
    }

    #[test]
    fn a_heap_end_two_functions_share_is_lowered_with_the_third_ones() {
        let found = program_heaps(&ut_like(), 0x8c01_0000);
        let ats: Vec<u32> = found.iter().map(|h| h.end_at).collect();
        assert_eq!(ats, vec![0x8c05_b1f8, 0x8c05_b2a0], "{found:x?}");
        for h in &found {
            assert_eq!((h.start, h.end), (0x8c31_3740, 0x8cfd_d000));
        }
        // The loader where the middle-of-RAM guess put it goes to the heaps'
        // top, and both words come down to it.
        assert_eq!(katana_loader_base(&found, 0x8c94_0000, &|_| true), Some(0x8cfc_0000));
        for h in &found {
            assert_eq!(h.patch(0x8cfc_0000).unwrap(), Some((h.end_at, 0x0cfc_0000)));
        }
    }

    #[test]
    fn a_shared_end_one_function_uses_otherwise_is_not_taken() {
        let mut img = ut_like();
        // The second function's `sub r1,r2` -> nop: it loads 0x0cfdd000 for
        // something else, so the word it shares with sbInitSystem stays.
        img[0x4_b1c6..0x4_b1c8].copy_from_slice(&0x0009u16.to_le_bytes());
        let ats: Vec<u32> = program_heaps(&img, 0x8c01_0000).iter().map(|h| h.end_at).collect();
        assert_eq!(ats, vec![0x8c05_b2a0]);
    }

    #[test]
    fn the_disc_patch_lands_in_any_read_of_its_sector_and_only_on_the_disc_word() {
        let d = DiscHeap {
            file: "JET_PAL.BIN".into(),
            lba: 0x85fe1,
            size: 0x2f_0ae0,
            heap: one_end(&jsr_like()),
        };
        let p = d.patch(0x8c7f_0000).unwrap().expect("patch");
        assert_eq!((p.lba, p.off), (0x85fe1 + 7, 0x7e8));
        // A read of sectors 6..9 of the file, landing anywhere.
        let mut buf = vec![0u8; 3 * 2048];
        buf[2048 + 0x7e8..2048 + 0x7ec].copy_from_slice(&0x8c80_0000u32.to_le_bytes());
        assert_eq!(patch_disc_read(std::slice::from_ref(&p), 0x85fe1 + 6, &mut buf), 1);
        assert_eq!(&buf[2048 + 0x7e8..2048 + 0x7ec], &0x8c7f_0000u32.to_le_bytes());
        // Other data at that place (another disc): left alone.
        let mut other = vec![0x55u8; 3 * 2048];
        assert_eq!(patch_disc_read(std::slice::from_ref(&p), 0x85fe1 + 6, &mut other), 0);
        // A read that does not reach it.
        assert_eq!(patch_disc_read(std::slice::from_ref(&p), 0x85fe1 + 8, &mut buf), 0);
    }

    #[test]
    fn no_tags_no_heap() {
        let mut img = shenmue2_like();
        img[0x41968 + 24..0x41968 + 28].fill(0);
        assert_eq!(hlib_heap(&img, 0x8c01_0000), None);
    }
}
