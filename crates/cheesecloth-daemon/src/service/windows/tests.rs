use std::time::Duration;

use windows_sys::Win32::System::Services::{SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_SHUTDOWN};

use super::*;

/// Whether `stop` has a waiting notification.
async fn notified(stop: &Notify) -> bool {
    tokio::time::timeout(Duration::from_millis(100), stop.notified())
        .await
        .is_ok()
}

#[tokio::test]
async fn stop_and_preshutdown_stop_the_daemon() {
    for control in [SERVICE_CONTROL_STOP, SERVICE_CONTROL_PRESHUTDOWN] {
        let stop = Notify::new();
        assert_eq!(on_control(control, &stop), NO_ERROR);
        assert!(notified(&stop).await);
    }
}

#[tokio::test]
async fn interrogate_is_answered_without_a_stop() {
    let stop = Notify::new();
    assert_eq!(on_control(SERVICE_CONTROL_INTERROGATE, &stop), NO_ERROR);
    assert!(!notified(&stop).await);
}

#[tokio::test]
async fn other_requests_are_not_implemented() {
    let stop = Notify::new();
    for control in [SERVICE_CONTROL_PAUSE, SERVICE_CONTROL_SHUTDOWN] {
        assert_eq!(on_control(control, &stop), ERROR_CALL_NOT_IMPLEMENTED);
    }
    assert!(!notified(&stop).await);
}
