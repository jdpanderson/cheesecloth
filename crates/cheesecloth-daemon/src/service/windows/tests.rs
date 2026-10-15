use std::time::Duration;

use tracing::Level;
use windows_sys::Win32::System::{
    EventLog::{EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE},
    Services::{SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_SHUTDOWN},
};

use super::*;
use event_log::{MAX_TEXT, event_text, event_type};

/// Whether `stop` has a waiting notification.
async fn notified(stop: &Notify) -> bool {
    tokio::time::timeout(Duration::from_millis(100), stop.notified())
        .await
        .is_ok()
}

#[tokio::test]
async fn only_stop_and_preshutdown_stop_the_daemon() {
    // Each control request, the code it is answered with, and whether it
    // stops the daemon.
    for (control, code, stops) in [
        (SERVICE_CONTROL_STOP, NO_ERROR, true),
        (SERVICE_CONTROL_PRESHUTDOWN, NO_ERROR, true),
        (SERVICE_CONTROL_INTERROGATE, NO_ERROR, false),
        (SERVICE_CONTROL_PAUSE, ERROR_CALL_NOT_IMPLEMENTED, false),
        (SERVICE_CONTROL_SHUTDOWN, ERROR_CALL_NOT_IMPLEMENTED, false),
    ] {
        let stop = Notify::new();
        assert_eq!(on_control(control, &stop), code, "control {control}");
        assert_eq!(notified(&stop).await, stops, "control {control}");
    }
}

#[test]
fn levels_map_to_event_types() {
    assert_eq!(event_type(&Level::ERROR), EVENTLOG_ERROR_TYPE);
    assert_eq!(event_type(&Level::WARN), EVENTLOG_WARNING_TYPE);
    for level in [Level::INFO, Level::DEBUG, Level::TRACE] {
        assert_eq!(event_type(&level), EVENTLOG_INFORMATION_TYPE);
    }
}

#[test]
fn event_text_drops_the_newline_replaces_bad_utf8_and_ends_with_nul() {
    for (bytes, expected) in [
        ("daemon starting: é\n".as_bytes(), "daemon starting: é\0"),
        (b"a\xffb".as_slice(), "a\u{fffd}b\0"),
    ] {
        let text = event_text(bytes);
        assert_eq!(String::from_utf16(&text).unwrap(), expected);
    }
}

#[test]
fn event_text_is_cut_to_the_limit_without_half_a_pair() {
    let text = event_text("x".repeat(MAX_TEXT + 10).as_bytes());
    assert_eq!(text.len(), MAX_TEXT + 1);
    assert_eq!(text.last(), Some(&0));

    // A pair that would cross the limit is left out whole.
    let text = event_text(format!("{}🙂", "x".repeat(MAX_TEXT - 1)).as_bytes());
    let mut expected: Vec<u16> = "x".repeat(MAX_TEXT - 1).encode_utf16().collect();
    expected.push(0);
    assert_eq!(text, expected);
}
