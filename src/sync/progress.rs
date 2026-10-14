//! Terminal-only, throttled progress. Redirected logs keep round summaries only.
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant};

pub(super) struct Progress {
    terminal: bool,
    active: bool,
    drawn: bool,
    initial: bool,
    total: usize,
    done: usize,
    last: Option<Instant>,
}

impl Progress {
    pub fn new(total: usize, initial: bool) -> Self {
        Self {
            terminal: io::stderr().is_terminal(),
            active: initial,
            drawn: false,
            initial,
            total,
            done: 0,
            last: None,
        }
    }

    pub fn file(&mut self, done: u64, total: u64) {
        self.active = true;
        self.draw(Some((done, total)), false);
    }

    pub fn entry_done(&mut self) {
        self.done += 1;
        self.draw(None, false);
    }

    fn draw(&mut self, file: Option<(u64, u64)>, finished: bool) {
        if !self.terminal || !self.active {
            return;
        }
        if !finished
            && self
                .last
                .is_some_and(|last| last.elapsed() < Duration::from_millis(100))
        {
            return;
        }
        // Completion means the round was validated, not just that bytes arrived.
        let percent = if finished {
            100
        } else {
            (self.done.saturating_mul(100) / self.total.max(1)).min(99)
        };
        let label = if self.initial {
            "Initial sync"
        } else {
            "Incremental sync"
        };
        let detail = file
            .map(|(done, total)| {
                format!(" | file {:.0}%", done as f64 * 100.0 / total.max(1) as f64)
            })
            .unwrap_or_default();
        let mut stderr = io::stderr().lock();
        let _ = write!(
            stderr,
            "\r\x1b[2K{label}: {percent:3}% ({}/{} entries){detail}",
            self.done, self.total
        );
        let _ = stderr.flush();
        self.drawn = true;
        self.last = Some(Instant::now());
    }

    pub fn finish(&mut self) {
        self.draw(None, true);
        self.clear();
    }

    fn clear(&mut self) {
        if self.drawn {
            let mut stderr = io::stderr().lock();
            let _ = write!(stderr, "\r\x1b[2K");
            let _ = stderr.flush();
            self.drawn = false;
        }
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.clear();
    }
}
