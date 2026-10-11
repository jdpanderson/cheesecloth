//! Windows: Ctrl-C or Ctrl-Break on the console. A console daemon does not
//! listen for console close, log-off or shutdown events: Windows ends the
//! process a few seconds after them, so a clean shutdown is not certain (see
//! docs/DESIGN.md, section Windows). The service stops cleanly at shutdown.

use tokio::signal::windows::{ctrl_break, ctrl_c};

pub(super) async fn requested() {
    let mut c = ctrl_c().expect("Ctrl-C handler");
    let mut brk = ctrl_break().expect("Ctrl-Break handler");
    tokio::select! {
        _ = c.recv() => {}
        _ = brk.recv() => {}
    }
}
