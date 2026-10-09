//! The mechanism the whole bridge rests on, against the real rcheevos: a set
//! is run on the console's memory a frame ahead, and every read the table
//! lacks -- including the target of a pointer -- is found and added.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::mpsc::channel;

use super::env::{Env, Probe, Shared};
use super::table::Table;

/// A game-sets response as retroachievements.org sends it, with two
/// achievements: one on a byte at 0x1000, one on a byte 0x10 past the pointer
/// stored at 0x2000 (`I:` is AddAddress).
pub(super) const SET: &str = r#"{"Success":true,"GameId":42,"Title":"Test Game","ConsoleId":40,
"ImageIconUrl":"/Images/000001.png","RichPresencePatch":"",
"Sets":[{"AchievementSetId":7,"GameId":42,"Title":"Test Game","Type":"core",
"ImageIconUrl":"/Images/000001.png",
"Achievements":[
{"ID":1,"Title":"Direct","Description":"d","Flags":3,"Points":5,
 "MemAddr":"0xH001000=5","Author":"a","BadgeName":"00001","Created":1,"Modified":1,"Type":""},
{"ID":2,"Title":"Pointer","Description":"p","Flags":3,"Points":10,
 "MemAddr":"I:0xW002000_0xH000010=1","Author":"a","BadgeName":"00002","Created":1,"Modified":1,"Type":""}
],"Leaderboards":[]}]}"#;

fn env() -> Shared {
    let (tx, _rx) = channel();
    Rc::new(RefCell::new(Env {
        table: Table { ranges: vec![], chains: vec![] },
        words: vec![],
        chain_addr: vec![],
        missed: vec![],
        real_missed: false,
        in_real: false,
        events: vec![],
        tx,
        user_agent: String::new(),
        disc: None,
        sets_requests: vec![],
        slow_mode: false,
        slow_vals: Default::default(),
        slow_new: Default::default(),
    }))
}

/// One growth step, as `Session::grow` does it.
fn grow(env: &Shared) -> Vec<u32> {
    let mut e = env.borrow_mut();
    let all: Vec<u32> = e.table.word_addresses().chain(e.missed.iter().copied()).collect();
    let t = Table::from_addresses(all).unwrap();
    e.words = vec![0; t.words()];
    e.table = t;
    let seen = std::mem::take(&mut e.missed);
    seen
}

#[test]
fn the_probe_finds_direct_reads_then_follows_the_pointer() {
    let mut probe = Probe::new(SET.as_bytes()).expect("the set parses");
    assert_eq!(probe.counts(), (2, 0, false));
    let env = env();

    // 1. nothing is known: both direct reads are missing
    probe.frame(&env);
    let mut first = grow(&env);
    first.sort();
    // the byte, the pointer itself, and where a NULL pointer would aim (0x10):
    // the first pass reads zeros, so the chain is followed from address 0
    assert_eq!(first, vec![0x10, 0x1000, 0x2000]);

    // 2. the pointer, read from the table, aims at 0x3000: its target is new
    {
        let mut e = env.borrow_mut();
        let ix = e.table.index_of(0x2000).unwrap();
        e.words[ix] = 0x3000;
    }
    probe.frame(&env);
    assert_eq!(env.borrow().missed, vec![0x3010]);
    grow(&env);

    // 3. the table now holds all of it: a frame reads nothing outside it
    {
        let mut e = env.borrow_mut();
        let ix = e.table.index_of(0x2000).unwrap();
        e.words[ix] = 0x3000;
    }
    probe.frame(&env);
    assert!(env.borrow().missed.is_empty(), "{:?}", env.borrow().missed);
    assert!(env.borrow().table.index_of(0x3010).is_some());
}

#[test]
fn a_pointer_that_moves_grows_the_table_again() {
    let mut probe = Probe::new(SET.as_bytes()).unwrap();
    let env = env();
    probe.frame(&env);
    grow(&env);
    for target in [0x3000u32, 0x4000] {
        {
            let mut e = env.borrow_mut();
            let ix = e.table.index_of(0x2000).unwrap();
            e.words[ix] = target;
        }
        probe.frame(&env);
        assert_eq!(env.borrow().missed, vec![target + 0x10]);
        grow(&env);
    }
}

#[test]
fn a_firing_achievement_keeps_being_probed() {
    // The byte reaches 5: the engine deactivates the trigger, and the probe
    // must put it back or it would stop following the pointer's chain.
    let mut probe = Probe::new(SET.as_bytes()).unwrap();
    let env = env();
    probe.frame(&env);
    grow(&env);
    for _ in 0..3 {
        {
            let mut e = env.borrow_mut();
            let ix = e.table.index_of(0x1000).unwrap();
            e.words[ix] = 5;
            let ix = e.table.index_of(0x2000).unwrap();
            e.words[ix] = 0x5000;
        }
        probe.frame(&env);
        grow(&env);
        let e = env.borrow();
        assert!(e.table.index_of(0x5010).is_some(), "the pointer chain is still followed");
    }
}

#[test]
fn a_malformed_set_is_refused() {
    assert!(Probe::new(b"{\"Success\":false}").is_none());
}

// ---------------------------------------------------------------------------
// Pointer chains, found through rcheevos' PUBLIC structures only. These tests are
// also what notices an rcheevos update that changes what those fields hold.

use super::chains::{Chain, Parent};

/// Achievements with a nested pointer, a negative offset, a read across two words
/// and an unaligned pointer, and a leaderboard whose value is indirect.
pub(super) const CHAINS: &str = r#"{"Success":true,"GameId":43,"Title":"Chains","ConsoleId":40,
"ImageIconUrl":"/Images/000001.png","RichPresencePatch":"",
"Sets":[{"AchievementSetId":8,"GameId":43,"Title":"Chains","Type":"core",
"ImageIconUrl":"/Images/000001.png",
"Achievements":[
{"ID":1,"Title":"Nested","Description":"d","Flags":3,"Points":5,
 "MemAddr":"I:0xW002000_I:0xW000004_0xH00002c=1","Author":"a","BadgeName":"00001","Created":1,"Modified":1,"Type":""},
{"ID":2,"Title":"Negative","Description":"d","Flags":3,"Points":5,
 "MemAddr":"I:0xW002000_0xHfffffc18=1_0xH001000=2","Author":"a","BadgeName":"00002","Created":1,"Modified":1,"Type":""},
{"ID":3,"Title":"Straddle","Description":"d","Flags":3,"Points":5,
 "MemAddr":"I:0xW002000_0xX00002e=1","Author":"a","BadgeName":"00003","Created":1,"Modified":1,"Type":""},
{"ID":4,"Title":"Unaligned pointer","Description":"d","Flags":3,"Points":5,
 "MemAddr":"I:0xW002002_0xH000010=1","Author":"a","BadgeName":"00004","Created":1,"Modified":1,"Type":""},
{"ID":5,"Title":"Two operands","Description":"d","Flags":3,"Points":5,
 "MemAddr":"I:0xW003000_0xH000010=0xH000014","Author":"a","BadgeName":"00005","Created":1,"Modified":1,"Type":""}
],
"Leaderboards":[{"ID":9,"Title":"L","Description":"d","Mem":"STA:0xH001000=1::CAN:0xH001000=2::SUB:0xH001000=3::VAL:I:0xW004000_M:0xX000020","Format":"VALUE","LowerIsBetter":0,"Hidden":false}]}]}"#;

#[test]
fn the_walk_finds_a_pointer_chain_in_a_real_set() {
    let mut probe = Probe::new(SET.as_bytes()).unwrap();
    let w = probe.walk();
    assert_eq!(w.direct.iter().copied().collect::<Vec<_>>(), vec![0x1000, 0x2000]);
    assert_eq!(w.chains, vec![Chain { parent: Parent::Direct(0x2000), shift: 0, word_off: 0x10 }]);
    assert_eq!(w.unsupported, 0);
}

#[test]
fn the_walk_covers_nesting_negative_offsets_two_words_and_leaderboards() {
    let mut probe = Probe::new(CHAINS.as_bytes()).expect("the set parses");
    let w = probe.walk();
    let has = |parent, off| w.chains.iter().any(|c| c.parent == parent && c.shift == 0 && c.word_off == off);
    // 0x2000 is the root of three chains, 0x3000 of one, 0x4000 of the leaderboard's
    assert!(w.direct.contains(&0x2000) && w.direct.contains(&0x3000) && w.direct.contains(&0x4000));
    assert!(w.direct.contains(&0x1000), "a plain read in the same set");
    // nested: the pointer inside 0x2000's target at +4, then a byte at +0x2c
    assert!(has(Parent::Direct(0x2000), 4));
    let inner = w.chains.iter().position(|c| *c == Chain { parent: Parent::Direct(0x2000), shift: 0, word_off: 4 }).unwrap();
    assert!(has(Parent::Chain(inner), 0x2c));
    // negative offset, as rcheevos holds it
    assert!(has(Parent::Direct(0x2000), 0xffff_fc18));
    // a 4-byte read at +0x2e straddles +0x2c and +0x30
    assert!(has(Parent::Direct(0x2000), 0x2c) && has(Parent::Direct(0x2000), 0x30));
    // both operands of one condition follow the pointer
    assert!(has(Parent::Direct(0x3000), 0x10) && has(Parent::Direct(0x3000), 0x14));
    // the leaderboard's value: 4 bytes at +0x20, a whole word
    assert!(has(Parent::Direct(0x4000), 0x20));
    // the pointer at an unaligned address is left to discovery
    assert!(w.unsupported >= 1);
    assert!(!w.direct.contains(&0x2002), "never a word it cannot sample as a pointer");
}

/// A frame of the fake machine as the loader would see it, for `table`: direct words
/// from `ram`, chain words worked out from their parents.
fn machine(table: &Table, ram: &dyn Fn(u32) -> u32) -> Vec<u32> {
    let nd = table.direct_words();
    let mut words: Vec<u32> = table
        .ranges
        .iter()
        .flat_map(|r| (0..r.words).map(move |i| r.offset + 4 * i))
        .map(ram)
        .collect();
    for c in &table.chains {
        let pv = (match c.parent {
            Parent::Direct(a) => words[table.index_of(a).unwrap()],
            Parent::Chain(i) => words[nd + i],
        } >> c.shift)
            & 0xff_ffff;
        words.push(ram(pv.wrapping_add(c.word_off) & 0xff_fffc));
    }
    words
}

#[test]
fn a_moving_pointer_needs_no_new_word_and_no_lost_frame() {
    let mut probe = Probe::new(SET.as_bytes()).unwrap();
    let walk = probe.walk();
    let env = env();
    let table = Table::build(walk.direct.iter().copied(), &walk.chains, 512).unwrap();
    assert_eq!(table.words(), 3, "0x1000, 0x2000 and the word behind the pointer");
    env.borrow_mut().table = table.clone();

    // The pointer takes a new value every frame, as an object list does, and what
    // it points at is a byte that becomes 1 only for the last.
    for (n, target) in [0x3000u32, 0x4000, 0x7f000, 0xc0_0000 - 0x100].into_iter().enumerate() {
        let ram = |a: u32| match a {
            0x2000 => target | 0x8c00_0000, // a P1 pointer: the 24-bit read drops the 8c
            a if a == target + 0x10 => (n == 3) as u32,
            _ => 0,
        };
        env.borrow_mut().set_words(&machine(&table, &ram));
        env.borrow_mut().missed.clear();
        probe.frame(&env);
        assert!(env.borrow().missed.is_empty(), "pointer {target:#x}: {:?}", env.borrow().missed);
    }
}

#[test]
fn a_read_past_ram_is_nothing_not_a_miss() {
    // A null pointer and a negative offset make address 0xfffffc18: no memory. It
    // used to count as a miss that no table could ever answer, and every frame was
    // skipped for good.
    let mut probe = Probe::new(CHAINS.as_bytes()).unwrap();
    let walk = probe.walk();
    let env = env();
    let table = Table::build(walk.direct.iter().copied(), &walk.chains, 512).unwrap();
    env.borrow_mut().table = table.clone();
    env.borrow_mut().set_words(&machine(&table, &|_| 0));
    env.borrow_mut().missed.clear();
    probe.frame(&env);
    let missed = env.borrow().missed.clone();
    assert!(
        missed.iter().all(|a| *a < 0x0100_0000),
        "nothing outside RAM is ever asked for: {missed:x?}"
    );
}
