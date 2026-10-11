//! The service manager that started the daemon, if it needs to be told about
//! the daemon's state: the Windows service manager. On Unix, and in a
//! console, there is none, and the OS's stop request comes from `stop`. The
//! OS code is in `service/unix.rs` and `service/windows.rs`; the rest of the
//! crate does not name an OS.

use std::io::IsTerminal;

use tracing_subscriber::{Layer, Registry, filter::Targets, prelude::*};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as os;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as os;

/// A log output.
type BoxedLayer = Box<dyn Layer<Registry> + Send + Sync>;

pub(crate) struct Service(os::Service);

impl Service {
    /// Connects to the service manager, if it started this process.
    pub(crate) async fn connect() -> anyhow::Result<Self> {
        os::Service::connect().await.map(Self)
    }

    /// Sends the log through `filter` to the service manager's log, or else
    /// to stdout. Call it once.
    pub(crate) fn init_logging(&self, filter: Targets) {
        let output = self.0.log_layer().unwrap_or_else(|| {
            // Colors only on a terminal, not in a log file or the journal.
            Box::new(tracing_subscriber::fmt::layer().with_ansi(std::io::stdout().is_terminal()))
        });
        tracing_subscriber::registry()
            .with(output)
            .with(filter)
            .init();
    }

    /// Tells the service manager that the daemon has started.
    pub(crate) fn running(&self) {
        self.0.running();
    }

    /// Completes when the service manager or the OS asks the daemon to stop.
    pub(crate) async fn stop_requested(&self) {
        self.0.stop_requested().await;
    }

    /// Tells the service manager that the daemon has stopped, with `result`.
    pub(crate) async fn stopped(self, result: &anyhow::Result<()>) {
        self.0.stopped(result).await;
    }
}
