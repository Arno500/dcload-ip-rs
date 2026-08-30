//! Terminal presentation: the progress display and the logger, in one place.
//!
//! WHY THIS MODULE EXISTS. indicatif draws a bar by parking the cursor on a
//! line and rewriting that line in place; `log` writes a record to stderr the
//! instant it is emitted. Nothing arbitrates between them, so as soon as a
//! transfer runs at debug level the two shred each other -- a bar left
//! stranded mid-line with a log record welded to its tail, the trailing
//! blanks of the erase still visible:
//!
//! ```text
//! [00:00:00] [####----] 45.00 KiB/360.00 KiB (1.76 MiB/s, 0s)      2026-08-14T18:31:08.178Z DEBUG ...
//! ```
//!
//! The fix is the one indicatif prescribes: print every log record from
//! inside `MultiProgress::suspend`, which erases the bars, lets the record
//! through, and redraws them below it. That needs ONE MultiProgress for the
//! whole process -- hence the `OnceLock` -- because the logger is installed
//! once, globally, before anything knows which transfers will happen.
//!
//! Two consequences worth knowing:
//!
//! - **A bar must be created through `bytes_bar()`**, not `ProgressBar::new`,
//!   or it is not in the MultiProgress and the logger cannot suspend it.
//! - **Nothing here draws when stderr is not a terminal.** indicatif checks
//!   `is_term()` and turns every draw into a no-op, so piping to a file or
//!   into a pager gives clean logs and no escape sequences, with `suspend`
//!   degrading to a plain call.

use std::borrow::Cow;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use console::style;
use indicatif::{HumanBytes, MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use log::{LevelFilter, Log, Metadata, Record};
use pretty_env_logger::formatted_timed_builder;

/// Transfers below this size get no bar at all.
///
/// A bar that appears and completes inside one frame is noise, not progress,
/// and the runtime CDFS path issues a lot of small reads while a title is
/// frozen waiting for them.
pub const BAR_MIN_BYTES: u64 = 10_000;

static UI: OnceLock<MultiProgress> = OnceLock::new();

/// The one draw target every bar and every log record goes through.
pub fn multi() -> &'static MultiProgress {
    // 15 Hz: fast enough to look live, slow enough that a bar redraw is never
    // the reason a packet is late. The DC blocks its running title for the
    // whole of a runtime transfer, so host-side work on that path is not free.
    UI.get_or_init(|| MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(15)))
}

/// A bar that takes itself off the display when it goes out of scope.
///
/// A bar left in the MultiProgress after its job ended is worse than no bar:
/// it keeps a line of the terminal, keeps ticking, and every log record after
/// it pays to erase and repaint it. Transfers here end through `?` as often as
/// they end normally -- a lost LoadBinary echo, a section that will not parse,
/// a read-back that times out -- so tying the cleanup to the scope is the only
/// version of this that cannot be forgotten on an error path.
pub struct Bar(ProgressBar);

impl std::ops::Deref for Bar {
    type Target = ProgressBar;

    fn deref(&self) -> &ProgressBar {
        &self.0
    }
}

impl Drop for Bar {
    fn drop(&mut self) {
        self.0.finish_and_clear();
        multi().remove(&self.0);
    }
}

/// EVERY FIELD EXCEPT THE BAR HAS A FIXED WIDTH, and that is deliberate.
///
/// `{wide_bar}` is handed whatever columns the rest of the line does not use,
/// so any field that grows -- the message going from `.text` to
/// `repairing +24` -- makes the bar visibly jump to a different length.
/// `{msg:<!16}` pads and truncates to sixteen columns, and the numbers are all
/// right-aligned to a fixed width, so the geometry of the line is the same from
/// the first byte to the last.
///
/// The fixed part is about 90 columns, which is more than a default 80-column
/// terminal has: there, `{wide_bar}` gets nothing and the line wraps into a
/// mess. So pick the layout from the width we actually have, dropping the file
/// name and the byte counts (both are in the log lines anyway) rather than
/// dropping the bar, which is the one thing a bar is for.
fn bar_template() -> &'static str {
    const WIDE: &str = "{prefix:.bold.dim} {msg:<!16} {spinner:.cyan} [{elapsed_precise}] \
                        [{wide_bar:.cyan/blue}] {percent:>3}% \
                        {binary_bytes:>9}/{binary_total_bytes} \
                        {binary_bytes_per_sec:>11} ETA {eta:>4}";
    const NARROW: &str = "{msg:<!14} {spinner:.cyan} [{wide_bar:.cyan/blue}] {percent:>3}% \
                          {binary_bytes_per_sec:>11} ETA {eta:>4}";

    match console::Term::stderr().size_checked() {
        Some((_rows, cols)) if cols >= 100 => WIDE,
        Some(_) => NARROW,
        // Not a terminal: nothing will be drawn anyway.
        None => WIDE,
    }
}

/// A byte-counting bar, already registered with the global MultiProgress.
///
/// `total` is the whole job -- not one LoadBinary window. The rate and the ETA
/// are only meaningful if the bar spans something a human recognises as a unit
/// of work, which is why `upload_bytes()` creates exactly one of these per file and
/// hands it down, rather than letting each 360 KiB transfer make its own.
pub fn bytes_bar(total: u64, prefix: impl Into<Cow<'static, str>>) -> Bar {
    if total < BAR_MIN_BYTES {
        return Bar(ProgressBar::hidden());
    }

    let style = ProgressStyle::with_template(bar_template())
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("█▉▊▋▌▍▎▏░");

    let bar = attach(
        ProgressBar::new(total)
            .with_style(style)
            .with_prefix(prefix),
    );
    // A steady tick keeps the elapsed time, the spinner and the rate moving
    // even while we are blocked waiting on the Dreamcast. That is the whole
    // difference between "this is slow" and "this is wedged", and it is the
    // question the display is most often asked.
    //
    // It also bounds how stale the display can get, which matters more than it
    // looks: a bar re-renders its own line on its own schedule, and
    // `MultiProgress::suspend` only REPAINTS the lines it already has. So the
    // line printed above a log record is the last one the bar rendered -- with
    // no tick between them, a burst of log lines all show the same stale
    // percentage. At 60 ms nothing on screen is ever more than one frame old.
    bar.enable_steady_tick(Duration::from_millis(60));
    Bar(bar)
}

/// The wait spinner's layout. A `const` so a test can prove it parses: the
/// fallback below is silent, and a typo here would quietly cost the elapsed
/// time -- the one field this display exists for.
const WAIT_TEMPLATE: &str = "{prefix:.bold.dim} {msg} {spinner:.cyan} [{elapsed_precise}]";

/// A wait with no measurable progress: a message, a spinner and the clock.
///
/// There is no bar because there is no total -- what is being waited for is a
/// console appearing on the network, which either has happened or has not. The
/// steady tick is the whole point: it is what separates "still trying" from
/// "wedged", and that is the only question an indefinite wait is ever asked.
/// Nothing is drawn when stderr is not a terminal, so the caller still owes a
/// log record to whoever is reading a redirected log.
pub fn wait_spinner(msg: impl Into<Cow<'static, str>>) -> Bar {
    let style = ProgressStyle::with_template(WAIT_TEMPLATE)
        .unwrap_or_else(|_| ProgressStyle::default_spinner());

    let bar = attach(
        ProgressBar::no_length()
            .with_style(style)
            .with_prefix("waiting for the Dreamcast")
            .with_message(msg),
    );
    bar.enable_steady_tick(Duration::from_millis(120));
    Bar(bar)
}

/// What a running title's disc loading looks like, aggregated.
///
/// THE UNIT OF WORK IS THE BURST, NOT THE REQUEST. dcload asks for at most
/// `GD_EMU_ASYNC` sectors at a time -- 8, i.e. 16 KiB -- so a title loading a
/// level does not make one big read, it makes a hundred small ones back to
/// back. A bar per request would appear and vanish inside a millisecond and
/// tell nobody anything; what a human wants to see is "it is loading, this
/// much so far, at this rate, and it is still moving".
///
/// THERE IS NO PERCENTAGE, AND THAT IS NOT AN OVERSIGHT. The GD command the
/// title issued knows its own total (`_GDS.param[1]` sectors), but the wire
/// protocol carries only the chunk being fetched -- LBA, destination, byte
/// count -- so the host genuinely cannot know how much more is coming. A
/// percentage here would have to be invented, and an invented ETA on a loading
/// screen is worse than none.
///
/// COST ON THE CRITICAL PATH. dcload serves a disc read synchronously: the
/// title is frozen from the request until the last packet lands. So this is
/// only ever updated AFTER the ReturnValue has gone out, while the title is
/// running again, and the bar is created only once a burst proves itself big
/// (`DCLOAD_LOAD_BAR_KB`, 256 KiB by default). Small reads -- the ones a title
/// makes constantly while playing -- cost one add and one comparison.
pub struct LoadMonitor {
    bar: Option<Bar>,
    bytes: u64,
    reads: u64,
    started: Option<Instant>,
    last: Option<Instant>,
    min_bytes: u64,
    idle: Duration,
}

impl LoadMonitor {
    /// Both thresholds are overridable, in the style of the rest of the tool:
    ///   DCLOAD_LOAD_BAR_KB   burst size that earns a bar; 0 disables it
    ///   DCLOAD_LOAD_IDLE_MS  silence that ends a burst
    pub fn new() -> Self {
        let min_kb = std::env::var("DCLOAD_LOAD_BAR_KB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(256);
        let idle_ms = std::env::var("DCLOAD_LOAD_IDLE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(250);
        Self {
            bar: None,
            bytes: 0,
            reads: 0,
            started: None,
            last: None,
            min_bytes: min_kb.saturating_mul(1024),
            idle: Duration::from_millis(idle_ms),
        }
    }

    /// One disc read served. Call it after the ReturnValue, never before.
    pub fn record(&mut self, bytes: usize, lba: u32) {
        if self.min_bytes == 0 {
            return;
        }
        let now = Instant::now();
        // A gap longer than `idle` means the burst we were watching is over
        // and this read starts a new one. Close the old one out first, so its
        // summary is reported against its own duration and not merged into the
        // next level's.
        if let Some(last) = self.last
            && now.duration_since(last) >= self.idle
        {
            self.finish();
        }
        let started = *self.started.get_or_insert(now);
        self.last = Some(now);
        self.bytes += bytes as u64;
        self.reads += 1;

        // THE RATE IS THE BURST AVERAGE, computed here rather than taken from
        // indicatif's `{binary_bytes_per_sec}`. That one is a sliding estimate
        // over the last few increments, and an increment here is a whole 16 KiB
        // request answered in one go: on a fast link the first few frames read
        // "2.12 GiB/s" and settle down afterwards, which is not a number anyone
        // can use. The average over the burst is the same figure the summary
        // line reports when the load ends, so the two agree.
        let elapsed = now.duration_since(started).as_secs_f64();
        let rate = if elapsed > 0.0 {
            (self.bytes as f64 / elapsed) as u64
        } else {
            0
        };
        let detail = format!("LBA 0x{lba:08x} · {}/s", HumanBytes(rate));

        match &self.bar {
            Some(bar) => {
                bar.set_position(self.bytes);
                bar.set_message(detail);
            }
            None if self.bytes >= self.min_bytes => {
                // Hand the bar the burst's real start time, or its elapsed
                // counter would start at zero even though the load did not.
                let bar = load_bar(self.bytes, now.duration_since(started));
                bar.set_message(detail);
                self.bar = Some(bar);
            }
            None => {}
        }
    }

    /// Nothing arrived. Ends the burst once the line has been quiet long enough.
    pub fn settle(&mut self) {
        if let Some(last) = self.last
            && last.elapsed() >= self.idle
        {
            self.finish();
        }
    }

    /// How long to wait for the next packet.
    ///
    /// `None` -- block forever -- whenever no burst is in flight, which is the
    /// normal state of a running title and costs nothing. Only while a burst is
    /// open do we want to be woken up, and only so the bar can be taken down
    /// promptly when the loading stops.
    pub fn poll_timeout(&self) -> Option<Duration> {
        self.started.map(|_| self.idle / 2)
    }

    fn finish(&mut self) {
        let (bytes, reads) = (self.bytes, self.reads);
        let elapsed = self
            .started
            .zip(self.last)
            .map(|(start, last)| last.duration_since(start))
            .unwrap_or_default();
        let visible = self.bar.is_some();
        self.bar = None; // dropping it clears the line
        self.bytes = 0;
        self.reads = 0;
        self.started = None;
        self.last = None;

        // Only bursts that were worth a bar are worth a line in the log; a
        // title reads small things constantly and summarising each one would
        // be the noise this whole rework set out to remove.
        if visible && elapsed > Duration::ZERO {
            let rate = (bytes as f64 / elapsed.as_secs_f64()) as u64;
            info!(
                "Loaded {} in {:.2} s ({}/s, {} reads)",
                HumanBytes(bytes),
                elapsed.as_secs_f64(),
                HumanBytes(rate),
                reads
            );
        }
    }
}

impl Drop for LoadMonitor {
    fn drop(&mut self) {
        self.finish();
    }
}

/// The burst bar: a spinner with a byte count, no length, no ETA.
fn load_bar(bytes_so_far: u64, elapsed: Duration) -> Bar {
    let style = ProgressStyle::with_template(
        "{prefix:.bold.dim} {msg:<!30} {spinner:.cyan} [{elapsed_precise}] \
         {binary_bytes:>9} read",
    )
    .unwrap_or_else(|_| ProgressStyle::default_spinner());

    let bar = attach(
        ProgressBar::no_length()
            .with_style(style)
            .with_prefix("loading")
            .with_position(bytes_so_far)
            .with_elapsed(elapsed),
    );
    bar.enable_steady_tick(Duration::from_millis(60));
    Bar(bar)
}

/// A `log` implementation that prints through the progress display.
struct BarAwareLogger {
    inner: Box<dyn Log>,
}

impl Log for BarAwareLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        // Filter BEFORE suspending. `suspend` takes the draw lock, erases
        // every bar and repaints it; doing that for a record the inner logger
        // is going to throw away would make the display pay for filtered-out
        // trace output during the busiest part of a transfer.
        if !self.inner.enabled(record.metadata()) {
            return;
        }
        multi().suspend(|| self.inner.log(record));
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

/// Install the global logger. Call once, before anything logs.
///
/// Same policy as before this module existed: `-v` is debug, `-vv` and beyond
/// are trace, and with neither, `RUST_LOG` wins if it is set, otherwise info.
pub fn init_logging(verbose: Option<u8>) {
    let mut builder = formatted_timed_builder();
    match verbose {
        Some(0) | None => match std::env::var("RUST_LOG") {
            Ok(filters) => {
                builder.parse_filters(&filters);
            }
            Err(_) => {
                builder.filter_level(LevelFilter::Info);
            }
        },
        Some(1) => {
            builder.filter_level(LevelFilter::Debug);
        }
        Some(_) => {
            builder.filter_level(LevelFilter::Trace);
        }
    }

    let logger = builder.build();
    // `set_max_level` is what makes `debug!` and friends cheap when they are
    // disabled -- the macro checks it before building the record. Take it from
    // the logger we just built so it always matches the filters above.
    let max_level = logger.filter();
    let bridged = BarAwareLogger {
        inner: Box::new(logger),
    };

    if log::set_boxed_logger(Box::new(bridged)).is_ok() {
        log::set_max_level(max_level);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wait_spinner_template_parses() {
        assert!(ProgressStyle::with_template(WAIT_TEMPLATE).is_ok());
    }

    fn sample_state() -> PanelState {
        PanelState {
            rows: vec![
                PanelRow::header("RX ring"),
                PanelRow::value("g_rx_polls".into(), "184 210  +4102".into(), true, false),
                PanelRow::value("g_rx_frames".into(), "9 411".into(), false, false),
                PanelRow::value("g_rx_link_giveup".into(), "0".into(), false, true),
                PanelRow::header("CD-DA"),
                PanelRow::value("g_cdda_plays".into(), "0".into(), false, true),
            ],
            status: "2.0s".into(),
            page: 0,
            show_all: true,
            collapsed: false,
            interval: Duration::from_secs(2),
            painted: String::new(),
        }
    }

    /// EVERY LINE THE SAME WIDTH, or the box is a staircase. Measured on the
    /// visible width, since the borders and the highlight are styled.
    #[test]
    fn the_box_is_rectangular() {
        let mut st = sample_state();
        let text = compose(&mut st, 40, 100);
        let widths: Vec<usize> = text.lines().map(console::measure_text_width).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "ragged box: {widths:?}"
        );
        // And right-aligned: the block ends at the last column.
        assert_eq!(widths[0], 100);
    }

    /// WHAT THE REDRAW SKIP RESTS ON. `paint` draws only when the composed
    /// block differs from the last one, because a redraw clears the live region
    /// and the terminal's selection with it. That is only sound while compose
    /// is a pure function of the state -- put a spinner or a clock in the
    /// caption and the panel silently goes back to eating every selection.
    #[test]
    fn composing_twice_with_nothing_changed_gives_the_same_block() {
        let mut st = long_state();
        let first = compose(&mut st, 40, 200);
        let second = compose(&mut st, 40, 200);
        assert_eq!(first, second);
    }

    /// A long set on a wide terminal, which is the shape this is normally in:
    /// 59 counters and their headings, on a screen with room for three columns.
    fn long_state() -> PanelState {
        let mut st = sample_state();
        st.rows.clear();
        for g in 0..7 {
            st.rows.push(PanelRow::header(format!("group {g}")));
            for c in 0..9 {
                st.rows.push(PanelRow::value(
                    format!("g_some_counter_{g}{c}"),
                    "184 210  +4102".into(),
                    c == 0,
                    false,
                ));
            }
        }
        st
    }

    /// THE WHOLE POINT OF THE GRID: a wide terminal shows the set, instead of a
    /// quarter of it beside 140 empty columns.
    #[test]
    fn a_wide_terminal_uses_more_than_one_column() {
        let mut st = long_state();
        let rows = st.rows.len();
        let text = compose(&mut st, 40, 200);
        let widths: Vec<usize> = text.lines().map(console::measure_text_width).collect();
        assert!(
            widths.windows(2).all(|w| w[0] == w[1]),
            "ragged box: {widths:?}"
        );
        assert_eq!(
            widths[0], 200,
            "the block is right-aligned to the last column"
        );
        // Two rules plus the body: a grid is shorter than the list it lays out.
        assert!(
            text.lines().count() < rows,
            "a grid must be shorter than the list it lays out"
        );
        assert!(text.contains("g_some_counter_00"), "the first row is on screen");
        assert!(
            text.contains("g_some_counter_40"),
            "and so is a row four groups further down, which one column could \
             not have reached"
        );
    }

    /// EVERY ROW ON EXACTLY ONE PAGE. Paging replaced a scroll, and the way a
    /// pagination goes wrong is by losing a row at a boundary or showing it
    /// twice -- neither of which a scroll could do, so neither had a test.
    #[test]
    fn paging_shows_every_counter_exactly_once() {
        let mut st = long_state();
        let mut seen: Vec<String> = Vec::new();
        let mut page = 0;
        loop {
            st.page = page;
            let text = compose(&mut st, 20, 200);
            assert_eq!(st.page, page, "page {page} was clamped away");
            for g in 0..7 {
                for c in 0..9 {
                    let name = format!("g_some_counter_{g}{c}");
                    if text.contains(&name) {
                        seen.push(name);
                    }
                }
            }
            page += 1;
            st.page = page;
            compose(&mut st, 20, 200);
            if st.page != page {
                break;
            }
        }
        assert!(page > 1, "the long set must take more than one page");
        let mut unique = seen.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 63, "a counter went missing at a page boundary");
        assert_eq!(seen.len(), 63, "a counter is on two pages");
    }

    /// A stand-in for `show all`: the real set is 7 groups and 135 rows, of
    /// which 66 are the two GD histograms.
    fn show_all_state() -> PanelState {
        let mut st = sample_state();
        st.rows.clear();
        let groups: [(&str, usize); 7] = [
            ("RX ring", 16),
            ("UDP", 3),
            ("Upload path", 13),
            ("GD emulation", 79),
            ("CD-DA", 7),
            ("Warm start / DHCP", 5),
            ("State", 5),
        ];
        for (name, n) in groups {
            st.rows.push(PanelRow::header(name));
            for c in 0..n {
                st.rows.push(PanelRow::value(
                    format!("g_{}_{c:02}", name.split(' ').next().unwrap().to_lowercase()),
                    "184 210".into(),
                    c == 0,
                    false,
                ));
            }
        }
        st
    }

    /// EVERY COLUMN SAYS WHICH SECTION IT IS. A column opening on a bare
    /// `CMD_…` name is one the reader cannot place, and with `show all` the GD
    /// group alone fills three of them. The newspaper rule and the widow
    /// control together make this structural rather than lucky: a column is
    /// only ever started by a section, whose heading goes in first, or by an
    /// overflow, which puts a continuation marker there.
    #[test]
    fn every_column_says_which_section_it_is() {
        let st = show_all_state();
        let visible: Vec<usize> = (0..st.rows.len()).collect();
        for height in [5usize, 12, 20, 24] {
            for (n, col) in lay_out(&st.rows, &visible, height).iter().enumerate() {
                let titled = match col.first() {
                    Some(Slot::Cont(_)) => true,
                    Some(Slot::Row(i)) => st.rows[*i].header,
                    None => false,
                };
                assert!(titled, "column {n} at height {height} has no heading");
            }
        }
    }

    /// The whole set, on a normal screen, in the number of pages the panel is
    /// meant to cost -- two. A regression here means someone has made the flow
    /// waste columns.
    #[test]
    fn the_whole_set_takes_two_pages() {
        let mut st = show_all_state();
        assert_eq!(st.rows.len(), 135, "the fixture is the size of `show all`");
        st.page = usize::MAX;
        compose(&mut st, 44, 130);
        assert_eq!(st.page, 1, "135 rows must fit in two pages of four columns");
    }

    /// THE NEWSPAPER RULE. A section that would fit in a column of its own is
    /// not split across two, and one that cannot fit anywhere is not moved for
    /// nothing -- it flows, and says so at the top of every column it reaches.
    #[test]
    fn a_section_is_split_only_when_it_has_to_be() {
        let st = long_state();
        let visible: Vec<usize> = (0..st.rows.len()).collect();

        // Ten rows a group, so a column of 18 holds one and never two.
        let columns = lay_out(&st.rows, &visible, 18);
        assert_eq!(columns.len(), 7, "one column a group");
        for col in &columns {
            let heads = col
                .iter()
                .filter(|c| matches!(c, Slot::Row(i) if st.rows[*i].header))
                .count();
            assert_eq!(heads, 1, "a column must hold one section, whole");
        }

        // Four rows a column cannot hold a group of ten: it spills, and every
        // column after the first carries the heading again.
        let columns = lay_out(&st.rows, &visible, 4);
        let continued = columns
            .iter()
            .filter(|c| matches!(c.first(), Some(Slot::Cont(_))))
            .count();
        assert!(continued >= 7, "a spilt section must be titled again");
    }

    /// The flow may not lose, duplicate or reorder a row, whatever the height.
    #[test]
    fn the_flow_preserves_the_list() {
        let st = long_state();
        let visible: Vec<usize> = (0..st.rows.len()).collect();
        for height in [2usize, 3, 5, 10, 18, 24, 100] {
            let kept: Vec<usize> = lay_out(&st.rows, &visible, height)
                .iter()
                .flatten()
                .filter_map(|c| match c {
                    Slot::Row(i) => Some(*i),
                    Slot::Cont(_) => None,
                })
                .collect();
            assert_eq!(kept, visible, "the flow changed the list at height {height}");
        }
    }

    /// One column is still one column when that is all there is room for, and
    /// the old geometry is exactly what it reduces to.
    #[test]
    fn a_narrow_terminal_keeps_a_single_column() {
        let mut st = long_state();
        let text = compose(&mut st, 40, 46);
        for line in text.lines() {
            assert!(console::measure_text_width(line) <= 46);
        }
        assert!(
            !text.lines().next().unwrap().contains("┬"),
            "no column separator in a single-column box"
        );
    }

    /// A narrow terminal must not make the panel wider than the screen, which
    /// would wrap every line and shred the display it is drawn into.
    #[test]
    fn a_narrow_terminal_does_not_overflow() {
        let mut st = sample_state();
        for cols in [20usize, 30, 40, 60, 200] {
            let text = compose(&mut st, 40, cols);
            for line in text.lines() {
                assert!(
                    console::measure_text_width(line) <= cols,
                    "line wider than {cols} columns"
                );
            }
        }
    }

    /// `a` off hides the counters still at zero -- and takes their heading with
    /// them when that empties a whole group, or the panel becomes a list of
    /// section titles with nothing under them.
    #[test]
    fn a_heading_goes_with_the_group_it_titles() {
        let mut st = sample_state();
        st.show_all = false;
        let text = compose(&mut st, 40, 100);
        assert!(text.contains("RX ring"), "a group with live counters stays");
        assert!(!text.contains("CD-DA"), "a group with nothing to show goes");
        assert!(
            !text.contains("g_rx_link_giveup"),
            "a zero counter is hidden"
        );
        assert!(text.contains("g_rx_polls"));
    }

    /// End is "as far as it goes", not a number: the key thread cannot know how
    /// many pages there are, so it sets the page past the end and the paint
    /// clamps it. If that clamp is wrong the panel shows an empty box.
    #[test]
    fn a_page_past_the_end_still_shows_the_last_rows() {
        let mut st = sample_state();
        st.page = usize::MAX;
        let text = compose(&mut st, 40, 100);
        assert!(
            text.contains("g_cdda_plays"),
            "the last row must be on screen"
        );
        assert_eq!(st.page, 0, "one page, and End must land on it");

        // And with more than one page, on the last of them.
        let mut st = long_state();
        st.page = usize::MAX;
        let text = compose(&mut st, 20, 200);
        assert!(st.page > 0, "the long set must not fit on one page");
        assert!(
            text.contains("g_some_counter_68"),
            "the last counter must be on the last page"
        );
    }

    /// Folded away, it is one line and says how to get it back.
    #[test]
    fn collapsed_is_a_single_line() {
        let mut st = sample_state();
        st.collapsed = true;
        let text = compose(&mut st, 40, 100);
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains('d'));
    }
}

// ---------------------------------------------------------------------------
// The diagnostic counter panel
// ---------------------------------------------------------------------------

/// WHY THE PANEL LIVES AT THE BOTTOM AND NOT DOWN THE RIGHT-HAND SIDE.
///
/// The requirement was "copying the logs must select the logs, not the panel",
/// and in a terminal that is not a matter of drawing: a selection returns what
/// is in the cell grid. A full-height column on the right shares every physical
/// line with a log line, so every one of those lines carries the panel's cells
/// into the scrollback and into the clipboard with it. There is no escape
/// sequence that makes a region unselectable, and left/right margins (DECSLRM)
/// make it worse rather than better -- terminals that support them at all only
/// save FULL-WIDTH lines to scrollback, so the logs would stop being scrollable
/// at all.
///
/// What does work is the arrangement indicatif already imposes, which is also
/// what Claude Code does: the log records scroll away full width into the
/// scrollback, and everything drawn by this module lives in the live region at
/// the bottom, which `MultiProgress::suspend` ERASES before each record and
/// repaints after it. The panel therefore never enters the scrollback at all.
/// Select anything above the live region and you get logs and nothing else.
///
/// So the panel is a right-aligned block at the bottom of the screen. It is
/// bounded to about half the terminal's height for the same reason: what is
/// above it has to stay readable.
static PANEL_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Register a bar with the display, keeping the panel last.
///
/// `MultiProgress::add` appends, so with a panel present every transfer bar
/// would appear BELOW it and the panel would drift up the screen as bars come
/// and go. Inserting one from the back puts each new bar immediately above the
/// panel instead, which leaves the panel pinned to the bottom-right corner
/// where a human can find it.
fn attach(pb: ProgressBar) -> ProgressBar {
    if PANEL_ON.load(std::sync::atomic::Ordering::Relaxed) {
        multi().insert_from_back(1, pb)
    } else {
        multi().add(pb)
    }
}

/// One line of the panel: a group heading, or a counter and its value.
pub struct PanelRow {
    pub label: String,
    pub value: String,
    pub header: bool,
    /// Moved since the previous sample -- what the highlight is for.
    pub changed: bool,
    /// Currently zero, and therefore hidden unless `a` is pressed.
    pub zero: bool,
}

impl PanelRow {
    pub fn header(label: impl Into<String>) -> Self {
        PanelRow {
            label: label.into(),
            value: String::new(),
            header: true,
            changed: false,
            zero: false,
        }
    }

    /// What the panel says before the first sample lands. An empty box looks
    /// like a broken instrument -- and the first thing a reader wants to know
    /// is whether anything is coming at all.
    pub fn placeholder(label: impl Into<String>) -> Self {
        PanelRow {
            label: label.into(),
            value: String::new(),
            header: false,
            changed: false,
            // Never filtered out by the all/used-only toggle.
            zero: false,
        }
    }

    pub fn value(label: String, value: String, changed: bool, zero: bool) -> Self {
        PanelRow {
            label,
            value,
            header: false,
            changed,
            zero,
        }
    }
}

struct PanelState {
    rows: Vec<PanelRow>,
    status: String,
    /// Which page is on screen. Clamped at paint time, so a key can move it
    /// past the end and the display still makes sense -- and it is a PAGE and
    /// not a scroll position, which is the whole argument in `compose`.
    page: usize,
    show_all: bool,
    collapsed: bool,
    interval: Duration,
    /// The last block actually drawn. A redraw with identical content is not
    /// free: it clears the live region, and clearing it DROPS THE TERMINAL'S
    /// SELECTION -- so anyone trying to copy a number out of the panel, or a
    /// line of log above it, loses it every time the panel breathes. At a
    /// 30-second interval the content changes twice a minute while the repaint
    /// wakes six times a second, which is 200 selections destroyed per useful
    /// update.
    painted: String,
}

/// The smallest and largest sampling intervals `+` and `-` will reach.
///
/// The floor is not politeness. Every sample is a UDP round trip that dcload
/// answers from inside `bb->loop()`, and while a title is loading that is the
/// same loop serving its disc reads; four samples a second is already more
/// interference than any of these numbers is worth.
const INTERVAL_MIN: Duration = Duration::from_millis(250);
const INTERVAL_MAX: Duration = Duration::from_secs(30);

pub struct DiagPanel {
    bar: ProgressBar,
    state: std::sync::Arc<std::sync::Mutex<PanelState>>,
    on_screen: bool,
}

impl DiagPanel {
    pub fn new(interval: Duration) -> Self {
        // Nothing here draws when stderr is not a terminal (indicatif turns
        // every draw into a no-op), and a key reader would then spin on a
        // stdin that answers instantly. So both are decided by the same test.
        let on_screen = console::Term::stderr().is_term();
        let state = std::sync::Arc::new(std::sync::Mutex::new(PanelState {
            rows: vec![PanelRow::placeholder("no sample yet")],
            status: "waiting for the first sample".into(),
            page: 0,
            show_all: false,
            collapsed: false,
            interval,
            painted: String::new(),
        }));

        let bar = if on_screen {
            let style = ProgressStyle::with_template("{msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner());
            let pb = multi().add(ProgressBar::new_spinner().with_style(style));
            PANEL_ON.store(true, std::sync::atomic::Ordering::Relaxed);
            pb
        } else {
            ProgressBar::hidden()
        };

        let panel = DiagPanel {
            bar,
            state,
            on_screen,
        };
        if on_screen {
            panel.spawn_key_reader();
            panel.render();
        }
        panel
    }

    /// Whether anything is actually being drawn. False when stderr is
    /// redirected, which is when the caller owes the numbers to the log
    /// instead.
    pub fn on_screen(&self) -> bool {
        self.on_screen
    }

    pub fn interval(&self) -> Duration {
        self.state
            .lock()
            .map(|s| s.interval)
            .unwrap_or(Duration::from_secs(2))
    }

    pub fn set_rows(&self, rows: Vec<PanelRow>) {
        if let Ok(mut s) = self.state.lock() {
            s.rows = rows;
        }
    }

    pub fn set_status(&self, status: String) {
        if let Ok(mut s) = self.state.lock() {
            s.status = status;
        }
    }

    pub fn render(&self) {
        if self.on_screen {
            paint(&self.bar, &self.state);
        }
    }

    /// The reader thread, and the two things that make it safe here.
    ///
    /// **Ctrl-C keeps working, and that was not free to establish.** The panel
    /// needs raw mode -- an arrow key is an escape sequence nobody is going to
    /// press Enter after -- and raw mode is exactly what stops the terminal
    /// turning Ctrl-C into SIGINT. `console::Term::read_key` handles it: on
    /// Unix it reads the `0x03` itself and calls `raise(SIGINT)` after
    /// restoring the terminal, and on Windows it leaves `ENABLE_PROCESSED_INPUT`
    /// alone so the console still raises the event. Either way the handler
    /// installed by `memmap::install_signal_handler` runs and the session still
    /// ends with its report. `read_key_raw` would deliver `Key::CtrlC` to us
    /// instead and silently cost that -- do not swap it in.
    ///
    /// **The thread is never joined**, because it spends its life blocked in a
    /// read that nothing can cancel. It exits on the first key after the panel
    /// goes away, or with the process. That is also why `restore_terminal`
    /// exists: between the read waking up and console putting the terminal
    /// back, a kill would leave the tty in raw mode.
    fn spawn_key_reader(&self) {
        tty::save();
        let state = std::sync::Arc::clone(&self.state);
        let bar = self.bar.clone();
        std::thread::spawn(move || {
            let term = console::Term::stderr();
            // Belt and braces: if this ever runs where reads answer instantly
            // -- no controlling terminal, stdin at EOF -- it would spin. Give
            // it a way out that does not depend on the check in `new`.
            let mut unreadable = 0u32;
            while let Ok(key) = term.read_key() {
                if matches!(key, console::Key::Unknown) {
                    unreadable += 1;
                    if unreadable > 64 {
                        break;
                    }
                    continue;
                }
                unreadable = 0;
                let Ok(mut s) = state.lock() else { break };
                // EVERY MOVEMENT KEY IS A PAGE. There is no scroll position to
                // step: the panel pages, for the reason set out in `compose`.
                match key {
                    console::Key::ArrowUp | console::Key::PageUp => {
                        s.page = s.page.saturating_sub(1)
                    }
                    console::Key::ArrowDown | console::Key::PageDown => {
                        s.page = s.page.saturating_add(1)
                    }
                    console::Key::Home => s.page = 0,
                    console::Key::End => s.page = usize::MAX,
                    console::Key::Char('a') | console::Key::Char('A') => {
                        s.show_all = !s.show_all;
                        s.page = 0;
                    }
                    console::Key::Char('d') | console::Key::Char('D') => {
                        s.collapsed = !s.collapsed;
                    }
                    console::Key::Char('+') | console::Key::Char('=') => {
                        s.interval = (s.interval / 2).max(INTERVAL_MIN);
                    }
                    console::Key::Char('-') | console::Key::Char('_') => {
                        s.interval = (s.interval * 2).min(INTERVAL_MAX);
                    }
                    _ => {
                        continue;
                    }
                }
                drop(s);
                paint(&bar, &state);
            }
        });
    }
}

impl Drop for DiagPanel {
    fn drop(&mut self) {
        PANEL_ON.store(false, std::sync::atomic::Ordering::Relaxed);
        self.bar.finish_and_clear();
        multi().remove(&self.bar);
        restore_terminal();
    }
}

/// Draw the whole block into the bar's message, in one string.
///
/// One bar and not one per line: indicatif splits a message on newlines and
/// draws each as its own line, so the block is atomic -- it cannot be caught
/// half-repainted between two log records, and it cannot have a transfer bar
/// inserted into the middle of it.
fn paint(bar: &ProgressBar, state: &std::sync::Mutex<PanelState>) {
    let Ok(mut s) = state.lock() else { return };
    let (rows, cols) = console::Term::stderr().size();
    let block = compose(&mut s, rows as usize, cols.max(20) as usize);
    // NOTHING CHANGED, NOTHING IS DRAWN. See `PanelState::painted`.
    if block == s.painted {
        return;
    }
    s.painted.clone_from(&block);
    bar.set_message(block);
}

/// The block, as text. Split out from `paint` so it can be tested: everything
/// that can be got wrong here -- a box whose lines are not all the same width,
/// a heading left over a group that is entirely hidden, an offset past the end
/// -- is a pure function of the state and the terminal's size, and none of it
/// is observable through a ProgressBar.
fn compose(s: &mut PanelState, term_rows: usize, term_cols: usize) -> String {
    if s.collapsed {
        let text = clip("── diag hidden · d to show ──", term_cols);
        let pad = term_cols.saturating_sub(text.chars().count());
        return format!("{}{}", " ".repeat(pad), style(text).dim());
    }

    // What is on show: everything, or only what a title has actually touched.
    // A heading whose whole group is hidden goes with it, or the panel is a
    // list of empty section titles.
    let visible: Vec<usize> = {
        let mut out: Vec<usize> = Vec::with_capacity(s.rows.len());
        for (i, r) in s.rows.iter().enumerate() {
            if r.header || s.show_all || !r.zero || r.changed {
                out.push(i);
            }
        }
        // Second pass: drop a heading with nothing under it.
        let mut kept = Vec::with_capacity(out.len());
        for (n, &i) in out.iter().enumerate() {
            if s.rows[i].header {
                let has_child = out.get(n + 1).is_some_and(|&j| !s.rows[j].header);
                if !has_child {
                    continue;
                }
            }
            kept.push(i);
        }
        kept
    };

    // Half the screen at most: what is above the panel is the log, and the log
    // is the reason anyone is looking at the terminal at all.
    let body_cap = (term_rows / 2).saturating_sub(2).clamp(3, 24);

    // THE TERMINAL WINS. A box wider than the screen wraps every one of its
    // lines and shreds the display it is drawn into, so the preferred width is
    // a preference: 26 columns is the narrowest that reads as a panel, and even
    // that gives way when there are not 30 columns to put it in.
    let max_inner = term_cols.saturating_sub(4).min(56);
    let min_inner = 26.min(max_inner);

    // Width of ONE column, from the content, so short sets do not draw a mostly
    // empty box.
    let widest = visible
        .iter()
        .map(|&i| {
            let r = &s.rows[i];
            let value = if r.value.is_empty() {
                0
            } else {
                r.value.chars().count() + 2
            };
            r.label.chars().count() + value
        })
        .max()
        .unwrap_or(24);
    let mut inner = widest.clamp(min_inner, max_inner.max(min_inner));

    // HOW MANY COLUMNS. A terminal is wide and this list is long, so the panel
    // is a grid rather than a slot: one column of 24 rows out of 66 leaves the
    // reader scrolling past most of the set with the screen half empty. `fit`
    // is the ceiling, because a box wider than the terminal shreds everything
    // (above).
    let col_width = inner + 3;
    let fit = (term_cols.saturating_sub(1) / col_width.max(1)).max(1);

    // IT PAGES, IT DOES NOT SCROLL, AND THAT IS NOT A PREFERENCE.
    //
    // In a column-major grid a cell's column is `(slot - offset) / body`. Move
    // `offset` by less than a whole column and every entry changes column;
    // move it by exactly one and every entry moves one column left. So reading
    // DOWN a column and nothing jumping BETWEEN columns cannot both hold while
    // a flat list slides through a grid -- and it was tried the other way
    // round, row-major with the keys stepping one grid row, which keeps every
    // counter in its column at the price of reading each group across.
    //
    // The way out is that the content never slides: it is replaced. A page is
    // a whole screenful, the keys move a page at a time, and within a page the
    // fill is column-major again -- so a group reads top to bottom in one place
    // and nothing is ever half-way between two positions.
    //
    // Columns are filled like a newspaper: a section flows down the current
    // column, and starts a fresh one when it does not fit in what is left --
    // unless it would not fit in a whole column either, in which case nothing
    // is gained by moving it and it simply flows on. Every column a section
    // continues into is titled again (`Slot::Cont`), because with `show all`
    // the GD group alone is 79 rows and a page of bare `CMD_…` names with no
    // heading in sight tells the reader nothing.
    let columns = lay_out(&s.rows, &visible, body_cap);

    // Every column that fits, since the point is now to need as few pages as
    // possible -- but never more than there are columns to show, or a short set
    // draws four empty ones beside it.
    let ncols = fit.min(columns.len().max(1));
    let npages = columns.len().div_ceil(ncols).max(1);
    let page = s.page.min(npages - 1);
    s.page = page;

    // The height is what the tallest column needs, not the cap: a set that
    // fits in two short columns should not draw twelve blank lines under it.
    let body = columns.iter().map(Vec::len).max().unwrap_or(1).max(1);

    // Total inner width, i.e. what the top and bottom rules have to span. One
    // column reduces to exactly the old geometry.
    let total_inner = ncols * col_width - 3;

    // THE CAPTIONS ARE PART OF THE WIDTH, and leaving them out of it is how the
    // position ends up displayed as `1-1…`. What the edges say is not
    // decoration: the top one is which page this is, and the bottom one is the
    // only place the keys are written down. So each has a full form and a
    // shorter one, and the widest row is measured against whichever fits.
    //
    // ONE PAGE SAYS NOTHING. `page 1/1` is a control that does not exist, and
    // the panel is normally in exactly that state while a title runs with the
    // zero counters hidden.
    let position = if npages > 1 {
        format!("page {}/{npages}", page + 1)
    } else {
        String::new()
    };
    let caption = fits(
        &if position.is_empty() {
            [
                format!(" diag · {} ", s.status),
                " diag ".to_string(),
                " d ".to_string(),
            ]
        } else {
            [
                format!(" diag · {} · {position} ", s.status),
                format!(" diag · {position} "),
                format!(" {} ", page + 1),
            ]
        },
        total_inner,
    );
    let hint = fits(
        &[
            format!(
                " ↑↓ PgUp/PgDn: page · a: {} · ± rate · d ",
                if s.show_all { "used only" } else { "all" }
            ),
            " ↑↓ · a · ± · d ".to_string(),
            " ↑↓ a ± d ".to_string(),
        ],
        total_inner,
    );

    // A single column still has to hold its own captions, exactly as before --
    // with a grid the rules span every column and there is room already.
    let total_inner = if ncols == 1 {
        inner = inner
            .max(caption.chars().count())
            .max(hint.chars().count())
            .min(max_inner.max(min_inner));
        inner
    } else {
        total_inner
    };
    let total_width = if ncols == 1 {
        inner + 4
    } else {
        ncols * (inner + 3) + 1
    };
    let pad = " ".repeat(term_cols.saturating_sub(total_width));

    let mut out = String::new();
    out.push_str(&pad);
    out.push_str(&rule('┌', '┐', &caption, total_inner));

    let bar = style("│").dim().to_string();
    for j in 0..body {
        out.push('\n');
        out.push_str(&pad);
        for k in 0..ncols {
            out.push_str(&bar);
            out.push(' ');
            // COLUMN-MAJOR within the page, which is where the whole grid came
            // in: read straight down, one section at a time.
            match columns.get(page * ncols + k).and_then(|c| c.get(j)) {
                Some(Slot::Row(i)) => out.push_str(&cell(&s.rows[*i], inner)),
                Some(Slot::Cont(i)) => out.push_str(&continued(&s.rows[*i], inner)),
                None => out.push_str(&" ".repeat(inner)),
            }
            out.push(' ');
        }
        out.push_str(&bar);
    }

    out.push('\n');
    out.push_str(&pad);
    out.push_str(&rule('└', '┘', &hint, total_inner));
    out
}

/// One cell of a laid-out column.
enum Slot {
    /// A row of the panel, by index into `PanelState::rows`.
    Row(usize),
    /// The heading of a section that started in an earlier column, repeated at
    /// the top of this one.
    Cont(usize),
}

/// The filtered list, dealt into columns `height` rows tall.
///
/// Columns, and not a flat grid, because how many of them fit on a page is a
/// question about the terminal's width and this one is not: the flow depends
/// only on the height. `compose` then chops the result into pages.
///
/// The rule is the newspaper one -- a section flows down the current column and
/// starts a fresh one when what is left will not hold it, unless a whole column
/// would not hold it either, in which case moving it gains nothing. A section
/// that does spill is titled again at the top of each column it continues into.
fn lay_out(rows: &[PanelRow], visible: &[usize], height: usize) -> Vec<Vec<Slot>> {
    let height = height.max(2);
    let mut columns: Vec<Vec<Slot>> = Vec::new();
    let mut cur: Vec<Slot> = Vec::with_capacity(height);

    // Sections: a heading and everything under it, up to the next heading.
    // Anything before the first heading -- the "no sample yet" placeholder --
    // is a section of its own with no title to repeat.
    let mut sections: Vec<(Option<usize>, Vec<usize>)> = Vec::new();
    for &i in visible {
        if rows[i].header || sections.is_empty() {
            sections.push((rows[i].header.then_some(i), Vec::new()));
        }
        sections.last_mut().expect("just pushed").1.push(i);
    }

    /// The fewest rows of a section worth leaving at the foot of a column.
    ///
    /// Without this the GD group -- 79 rows, so it cannot fit anywhere and is
    /// never moved on the rule above -- lands its heading on the last line of a
    /// column with nothing under it, and the reader gets a title in one place
    /// and its contents in another.
    const MIN_KEEP: usize = 3;

    for (head, items) in sections {
        // A fresh column for a section that would be split by staying and
        // could be whole by moving, or that would leave a stub behind.
        // Nothing else justifies the blank tail.
        let room = height - cur.len();
        if !cur.is_empty() && items.len() > room && (items.len() <= height || room < MIN_KEEP) {
            columns.push(std::mem::take(&mut cur));
        }
        for &i in &items {
            if cur.len() == height {
                columns.push(std::mem::take(&mut cur));
                if let Some(h) = head {
                    cur.push(Slot::Cont(h));
                }
            }
            cur.push(Slot::Row(i));
        }
    }
    if !cur.is_empty() {
        columns.push(cur);
    }
    columns
}

/// The heading of a section picked up again at the top of the next column.
///
/// Dimmed and marked, so it does not read as a second section with the same
/// name -- what it says is "still the same group", which is the one thing a
/// column of bare `CMD_…` names cannot say for itself.
fn continued(r: &PanelRow, inner: usize) -> String {
    let label = clip(&format!("{} …", r.label), inner);
    let gap = inner - label.chars().count();
    format!("{}{}", style(&label).cyan().dim(), " ".repeat(gap))
}

/// One row, rendered to exactly `inner` display columns.
///
/// Padded by hand throughout: a styled string carries escape bytes that
/// `{:<width$}` would count as columns, and the box would ripple.
fn cell(r: &PanelRow, inner: usize) -> String {
    let mut out = String::new();
    if r.header {
        let label = clip(&r.label, inner);
        let gap = inner - label.chars().count();
        out.push_str(&style(&label).cyan().bold().to_string());
        out.push_str(&" ".repeat(gap));
        return out;
    }
    // The value is what the panel exists to show, so the name is what gives way
    // when the two do not fit.
    let value = clip(&r.value, inner);
    let label = clip(&r.label, inner.saturating_sub(value.chars().count() + 1));
    let gap = inner.saturating_sub(label.chars().count() + value.chars().count());
    out.push_str(&label);
    out.push_str(&" ".repeat(gap));
    if r.changed {
        out.push_str(&style(&value).yellow().bold().to_string());
    } else if r.zero {
        out.push_str(&style(&value).dim().to_string());
    } else {
        out.push_str(&value);
    }
    out
}

/// The first caption that fits, or the last one clipped to fit.
///
/// Ordered longest first: what is wanted is the most it can say, not the least.
fn fits(candidates: &[String], width: usize) -> String {
    for c in candidates {
        if c.chars().count() <= width {
            return c.clone();
        }
    }
    clip(candidates.last().map(String::as_str).unwrap_or(""), width)
}

/// A box edge with a caption in it, dimmed, exactly `inner + 4` columns wide.
fn rule(left: char, right: char, caption: &str, inner: usize) -> String {
    let caption = clip(caption, inner);
    let fill = inner.saturating_sub(caption.chars().count());
    let line = format!("{left}─{caption}{}{right}", "─".repeat(fill + 1));
    style(line).dim().to_string()
}

/// Truncate on character boundaries, with an ellipsis when something was lost.
fn clip(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let mut out: String = s.chars().take(width - 1).collect();
    out.push('…');
    out
}

/// Put the terminal back the way it was found.
///
/// Only ever needed on Unix, and only because of the panel: `Term::read_key`
/// holds the tty in raw mode for the duration of a blocking read, and that read
/// is where the reader thread spends essentially all of its time. A Ctrl-C is
/// safe -- console restores the terminal before raising SIGINT -- but a SIGTERM
/// or a debugger's Stop button is not, and a shell left in raw mode after a
/// debugging session is a needlessly memorable way to end one.
///
/// Called from `memmap::report_and_exit`, which is every ending that runs code,
/// and from the panel's own `Drop`. A no-op when the panel was never started.
pub fn restore_terminal() {
    tty::restore();
}

#[cfg(unix)]
mod tty {
    use std::sync::OnceLock;

    /// The tty and its settings as they were before anything touched them.
    /// `None` when there is no terminal to speak of, which is not an error.
    static SAVED: OnceLock<Option<(i32, libc::termios)>> = OnceLock::new();

    pub fn save() {
        SAVED.get_or_init(|| unsafe {
            // Same choice console makes: stdin when it is a terminal, the
            // controlling terminal otherwise. Either descriptor names the same
            // terminal, and termios settings belong to the terminal, not to the
            // descriptor -- so restoring through this one works whichever one
            // the reader thread ends up using.
            let fd = if libc::isatty(libc::STDIN_FILENO) == 1 {
                libc::STDIN_FILENO
            } else {
                let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR);
                if fd < 0 {
                    return None;
                }
                fd
            };
            let mut settings: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(fd, &mut settings) != 0 {
                return None;
            }
            Some((fd, settings))
        });
    }

    pub fn restore() {
        if let Some(Some((fd, settings))) = SAVED.get() {
            unsafe {
                libc::tcsetattr(*fd, libc::TCSADRAIN, settings);
            }
        }
    }
}

/// Windows needs none of this: `Term::read_key` leaves the console mode alone
/// (the guard that clears `ENABLE_PROCESSED_INPUT` is only taken by
/// `read_key_raw`), so there is nothing to put back.
#[cfg(not(unix))]
mod tty {
    pub fn save() {}
    pub fn restore() {}
}
