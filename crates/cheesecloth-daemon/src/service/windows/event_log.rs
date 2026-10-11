//! The Event Log, for a daemon that the SCM started. Each log event is one
//! entry from the source "cheesecloth", with the formatted event as its one
//! insert string. The message table in cheesecloth.exe shows that string as
//! it is (see crates/cheesecloth/build.rs).

use std::{io, ptr, sync::Arc};

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::{self, MakeWriter};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        System::EventLog::{
            DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
            EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE, RegisterEventSourceW, ReportEventW,
        },
    },
    core::w,
};

use super::BoxedLayer;

/// The message that shows its insert string. crates/cheesecloth/build.rs
/// and tests/cli.rs use the same ID.
pub(super) const MESSAGE_ID: u32 = 1;

/// The longest insert string that the Event Log takes, in UTF-16 units.
pub(super) const MAX_TEXT: usize = 31_839;

/// An open event source.
pub(super) struct EventLog(HANDLE);

// SAFETY: an event source handle may be used from any thread.
#[allow(unsafe_code, reason = "the raw handle is owned")]
unsafe impl Send for EventLog {}
// SAFETY: as above; ReportEventW does not change the handle.
#[allow(unsafe_code, reason = "the raw handle is owned")]
unsafe impl Sync for EventLog {}

impl EventLog {
    #[allow(unsafe_code, reason = "windows-sys has no safe Event Log calls")]
    pub(super) fn open() -> io::Result<Self> {
        // SAFETY: a null server name means this computer, and the source
        // name is a NUL-terminated UTF-16 literal.
        let handle = unsafe { RegisterEventSourceW(ptr::null(), w!("cheesecloth")) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(handle))
    }

    /// Writes one entry. A failure has nowhere to go, since this is the log.
    #[allow(unsafe_code, reason = "windows-sys has no safe Event Log calls")]
    fn report(&self, kind: REPORT_EVENT_TYPE, text: &[u16]) {
        let strings = [text.as_ptr()];
        // SAFETY: the handle is open while self lives, and strings holds one
        // NUL-terminated string that lives until the call returns. There is
        // no user SID and no raw data.
        unsafe {
            ReportEventW(
                self.0,
                kind,
                0,
                MESSAGE_ID,
                ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                ptr::null(),
            )
        };
    }
}

impl Drop for EventLog {
    #[allow(unsafe_code, reason = "windows-sys has no safe Event Log calls")]
    fn drop(&mut self) {
        // SAFETY: the handle is open, and only self closes it.
        unsafe { DeregisterEventSource(self.0) };
    }
}

/// A log output that writes each event to `log`. The level sets the entry's
/// type, and the Event Log has its own time.
pub(super) fn layer(log: Arc<EventLog>) -> BoxedLayer {
    Box::new(
        fmt::layer()
            .with_ansi(false)
            .without_time()
            .with_level(false)
            .with_writer(Shared(log)),
    )
}

/// `MakeWriter` for an `Arc<EventLog>`. tracing-subscriber's own one for
/// `Arc` does not pass on the event's level.
struct Shared(Arc<EventLog>);

impl<'a> MakeWriter<'a> for Shared {
    type Writer = Entry<'a>;

    fn make_writer(&'a self) -> Entry<'a> {
        self.entry(EVENTLOG_INFORMATION_TYPE)
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Entry<'a> {
        self.entry(event_type(meta.level()))
    }
}

impl Shared {
    fn entry(&self, kind: REPORT_EVENT_TYPE) -> Entry<'_> {
        Entry {
            log: &self.0,
            kind,
            text: Vec::new(),
        }
    }
}

/// One event's text, written to the Event Log when it is dropped.
struct Entry<'a> {
    log: &'a EventLog,
    kind: REPORT_EVENT_TYPE,
    text: Vec<u8>,
}

impl io::Write for Entry<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.text.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Entry<'_> {
    fn drop(&mut self) {
        self.log.report(self.kind, &event_text(&self.text));
    }
}

pub(super) fn event_type(level: &Level) -> REPORT_EVENT_TYPE {
    match *level {
        Level::ERROR => EVENTLOG_ERROR_TYPE,
        Level::WARN => EVENTLOG_WARNING_TYPE,
        _ => EVENTLOG_INFORMATION_TYPE,
    }
}

/// The text as a NUL-terminated UTF-16 string, without the trailing newline,
/// and cut to the Event Log's limit.
pub(super) fn event_text(bytes: &[u8]) -> Vec<u16> {
    let text = String::from_utf8_lossy(bytes);
    let mut wide: Vec<u16> = text.trim_end().encode_utf16().take(MAX_TEXT).collect();
    // A cut must not leave half of a surrogate pair.
    if wide.last().is_some_and(|u| (0xD800..0xDC00).contains(u)) {
        wide.pop();
    }
    wide.push(0);
    wide
}
