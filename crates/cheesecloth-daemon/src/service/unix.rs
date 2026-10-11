//! Unix: no service manager needs to be told anything. systemd reads the
//! log from stdout and stops the daemon with SIGTERM.

use super::BoxedLayer;

pub(super) struct Service;

impl Service {
    pub(super) async fn connect() -> anyhow::Result<Self> {
        Ok(Self)
    }

    pub(super) fn log_layer(&self) -> Option<BoxedLayer> {
        None
    }

    pub(super) fn running(&self) {}

    pub(super) async fn stop_requested(&self) {
        crate::stop::requested().await;
    }

    pub(super) async fn stopped(self, _result: &anyhow::Result<()>) {}
}
