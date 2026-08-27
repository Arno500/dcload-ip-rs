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

    let bar = multi().add(ProgressBar::new(total).with_style(style).with_prefix(prefix));
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

    let bar = multi().add(
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
