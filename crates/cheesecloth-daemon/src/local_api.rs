//! The local API: one JSON request per line on the local IPC channel (see
//! `api` and `ipc`).

use std::sync::Arc;

use anyhow::{Result, bail};
use cheesecloth_core::state::Outcome;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::info;

use crate::{
    Daemon, Phase,
    api::{ApiRequest, ApiResponse, ChangeView, HelloView},
    ipc::{self, Access},
};

fn to_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value> {
    Ok(serde_json::to_value(value)?)
}

/// The answer to a request that changes the cluster.
fn change(outcome: Outcome) -> Result<serde_json::Value> {
    to_json(ChangeView::try_from(outcome)?)
}

async fn write_response(
    write: &mut (impl AsyncWrite + Unpin + ?Sized),
    resp: &ApiResponse,
) -> std::io::Result<()> {
    let mut out = serde_json::to_string(resp).expect("serializable");
    out.push('\n');
    write.write_all(out.as_bytes()).await
}

/// The connection of a `stop` request. It is answered after shutdown, so the
/// client knows that cleanup has finished.
pub(crate) struct StopRequest(Box<dyn AsyncWrite + Send + Unpin>);

impl Daemon {
    pub async fn handle_api(self: &Arc<Self>, req: ApiRequest) -> ApiResponse {
        let res: Result<serde_json::Value> = async {
            Ok(match req {
                ApiRequest::Hello => to_json(HelloView::new())?,
                ApiRequest::Status => to_json(self.status().await?)?,
                ApiRequest::Peers => to_json(self.peers()?)?,
                ApiRequest::Init {
                    ipv4_range,
                    strict_security,
                } => to_json(self.init_with_security(ipv4_range, strict_security).await?)?,
                ApiRequest::Invite => to_json(self.invite().await?)?,
                ApiRequest::Join { token } => to_json(self.join(&token).await?)?,
                ApiRequest::Remove { node } => change(self.remove(&node).await?)?,
                ApiRequest::Leave { force } => to_json(self.leave(force).await?)?,
                ApiRequest::Pending => to_json(self.pending()?)?,
                ApiRequest::Approve { proposal } => change(self.vote(proposal, true).await?)?,
                ApiRequest::Reject { proposal } => change(self.vote(proposal, false).await?)?,
                ApiRequest::ConfigGet => to_json(self.config_get()?)?,
                ApiRequest::ConfigSet { key, value } => {
                    change(self.config_set(&key, &value).await?)?
                }
                // `serve_api` keeps the connection to answer after shutdown.
                ApiRequest::Stop => bail!("stop is only served on the API socket"),
            })
        }
        .await;
        match res {
            Ok(v) => ApiResponse::Ok(v),
            Err(e) => ApiResponse::Err(format!("{e:#}")),
        }
    }

    /// Keeps `write` to answer once shutdown has finished, and wakes `serve`.
    fn request_stop(&self, write: impl AsyncWrite + Send + Unpin + 'static) {
        self.stop_requests.lock().push(StopRequest(Box::new(write)));
        self.stop_requested.notify_one();
    }

    /// Answers the `stop` requests. An error says that local cleanup is still
    /// pending.
    pub(crate) async fn answer_stop_requests(&self) {
        let requests = std::mem::take(&mut *self.stop_requests.lock());
        if requests.is_empty() {
            return;
        }
        let resp = match &*self.phase.read() {
            Phase::Stopping { error, .. } => ApiResponse::Err(match error {
                Some(e) => format!("stopped, but local cleanup is pending: {e}"),
                None => "stopped, but local cleanup is pending".into(),
            }),
            _ => ApiResponse::Ok(serde_json::Value::Null),
        };
        for mut request in requests {
            // A client that has gone away doesn't need the answer.
            let _ = write_response(&mut *request.0, &resp).await;
        }
    }

    /// Serves the local API until the daemon has shut down. During shutdown a
    /// `stop` is still queued, and other requests get an error.
    pub async fn serve_api(self: Arc<Self>) -> Result<()> {
        self.api_conns
            .run(async {
                let gate = Arc::new(ipc::Gate::new(&self.opts)?);
                let addr = self.opts.socket_path()?;
                let mut listener = ipc::Listener::bind(&addr)?;
                info!(socket = %addr.display(), "local API ready");
                loop {
                    let stream = listener.accept().await?;
                    let daemon = self.clone();
                    let gate = gate.clone();
                    self.api_conns.spawn(async move {
                        let access = gate.access(&stream).await;
                        daemon.serve_connection(stream, access).await;
                    });
                }
            })
            .await
            .unwrap_or(Ok(()))
    }

    /// Answers the requests on one connection, as `access` allows.
    pub(crate) async fn serve_connection(
        self: Arc<Self>,
        stream: impl AsyncRead + AsyncWrite + Send + 'static,
        access: Access,
    ) {
        let (read, mut write) = tokio::io::split(stream);
        if let Access::Refused(reason) = access {
            // A client that has gone away doesn't need the answer.
            let _ = write_response(&mut write, &ApiResponse::Err(reason)).await;
            return;
        }
        let mut lines = BufReader::new(read).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let resp = match serde_json::from_str::<ApiRequest>(&line) {
                Ok(ApiRequest::Stop) if access == Access::Full => {
                    self.request_stop(write);
                    return;
                }
                Ok(ApiRequest::Stop) => ApiResponse::Err(
                    "only root may stop the daemon; stop its service instead".into(),
                ),
                Ok(req) => self
                    .api_work
                    .run(self.handle_api(req))
                    .await
                    .unwrap_or_else(|_| ApiResponse::Err("the daemon is shutting down".into())),
                Err(e) => ApiResponse::Err(format!("bad request: {e}")),
            };
            if write_response(&mut write, &resp).await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_closes_idle_api_clients_and_releases_the_daemon() {
        let (d, _dir) = crate::testing::daemon("api-stop", crate::RelayMode::Never).await;
        let weak = Arc::downgrade(&d);
        let socket = d.opts.socket_path().unwrap();
        let server = tokio::spawn(d.clone().serve_api());
        let client = api_client(&socket).await;
        let (read, mut write) = tokio::io::split(client);
        let mut lines = BufReader::new(read).lines();
        write.write_all(b"\"status\"\n").await.unwrap();
        assert!(lines.next_line().await.unwrap().is_some());
        d.shutdown().await;
        assert!(lines.next_line().await.unwrap().is_none());
        server.await.unwrap().unwrap();
        drop(d);
        assert!(weak.upgrade().is_none());
    }

    use std::time::Duration;

    use crate::testing::{api_client, serve};

    /// Fails the test instead of hanging when `f` never finishes.
    async fn within<F: Future>(f: F) -> F::Output {
        tokio::time::timeout(Duration::from_secs(5), f)
            .await
            .expect("finished in time")
    }

    /// Waits until `n` stop requests are queued.
    async fn queued(d: &Daemon, n: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while d.stop_requests.lock().len() < n {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued stop requests");
    }

    #[tokio::test]
    async fn stop_is_answered_after_shutdown_and_ends_serve() {
        let (d, _dir) = crate::testing::daemon("api-stop-request", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        let answer: serde_json::Value = within(crate::api::call(&socket, &ApiRequest::Stop))
            .await
            .unwrap();
        assert!(answer.is_null());
        assert!(matches!(&*d.phase.read(), Phase::Stopped));
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn every_stop_request_is_answered() {
        let (d, _dir) = crate::testing::daemon("api-stop-twice", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        // Holding the operation lock keeps shutdown from finishing. Shutdown
        // starts with the first stop; the second client connects after that.
        let op = d.op.lock().await;
        let mut clients = Vec::new();
        for n in 1..=2 {
            let (read, mut write) = tokio::io::split(ipc::connect(&socket).await.unwrap());
            write.write_all(b"{\"cmd\":\"stop\"}\n").await.unwrap();
            queued(&d, n).await;
            clients.push((BufReader::new(read).lines(), write));
        }
        drop(op);
        for (lines, _) in &mut clients {
            assert_eq!(
                within(lines.next_line()).await.unwrap().unwrap(),
                "{\"ok\":null}"
            );
        }
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn other_requests_during_shutdown_get_an_error() {
        let (d, _dir) = crate::testing::daemon("api-stopping", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        // As in shutdown: the API work has stopped, the listener has not.
        d.api_work.stop().await;
        let client = ipc::connect(&socket).await.unwrap();
        let (read, mut write) = tokio::io::split(client);
        let mut lines = BufReader::new(read).lines();
        write
            .write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"stop\"}\n")
            .await
            .unwrap();
        let status = within(lines.next_line()).await.unwrap().unwrap();
        assert!(status.contains("the daemon is shutting down"), "{status}");
        assert_eq!(
            within(lines.next_line()).await.unwrap().unwrap(),
            "{\"ok\":null}"
        );
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stop_follows_other_requests_on_one_connection() {
        let (d, _dir) = crate::testing::daemon("api-stop-after", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        let client = ipc::connect(&socket).await.unwrap();
        let (read, mut write) = tokio::io::split(client);
        let mut lines = BufReader::new(read).lines();
        write
            .write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"stop\"}\n")
            .await
            .unwrap();
        let status = within(lines.next_line()).await.unwrap().unwrap();
        assert!(status.starts_with("{\"ok\":{"), "{status}");
        assert_eq!(
            within(lines.next_line()).await.unwrap().unwrap(),
            "{\"ok\":null}"
        );
        assert!(within(lines.next_line()).await.unwrap().is_none());
        within(server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_stop_client_that_goes_away_does_not_hold_up_shutdown() {
        let (d, _dir) = crate::testing::daemon("api-stop-gone", crate::RelayMode::Never).await;
        let (server, socket) = serve(&d).await;
        let op = d.op.lock().await;
        let mut client = ipc::connect(&socket).await.unwrap();
        client.write_all(b"{\"cmd\":\"stop\"}\n").await.unwrap();
        queued(&d, 1).await;
        drop(client);
        drop(op);
        within(server).await.unwrap().unwrap();
        assert!(matches!(&*d.phase.read(), Phase::Stopped));
    }

    #[tokio::test]
    async fn a_signal_shuts_down_without_stop_requests() {
        let (d, _dir) = crate::testing::daemon("api-signal", crate::RelayMode::Never).await;
        within(crate::serve(d.clone(), async {})).await.unwrap();
        assert!(matches!(&*d.phase.read(), Phase::Stopped));
    }

    /// Serves one in-memory connection with `access`, and returns the
    /// client's lines and its write half.
    fn connect_with(
        d: &Arc<Daemon>,
        access: Access,
    ) -> (
        tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
        tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) {
        let (client, server) = tokio::io::duplex(4096);
        tokio::spawn(d.clone().serve_connection(server, access));
        let (read, write) = tokio::io::split(client);
        (BufReader::new(read).lines(), write)
    }

    #[tokio::test]
    async fn a_refused_client_gets_the_reason_and_nothing_more() {
        let (d, _dir) = crate::testing::daemon("api-refused", crate::RelayMode::Never).await;
        let (mut lines, mut write) = connect_with(&d, Access::Refused("not you".into()));
        // The request is not read: the answer is the refusal, then the end.
        let _ = write.write_all(b"{\"cmd\":\"status\"}\n").await;
        assert_eq!(
            within(lines.next_line()).await.unwrap().unwrap(),
            "{\"err\":\"not you\"}"
        );
        assert!(within(lines.next_line()).await.unwrap().is_none());
        d.shutdown().await;
    }

    #[tokio::test]
    async fn an_operator_may_do_all_but_stop() {
        let (d, _dir) = crate::testing::daemon("api-operator", crate::RelayMode::Never).await;
        let (mut lines, mut write) = connect_with(&d, Access::Operator);
        write
            .write_all(b"{\"cmd\":\"status\"}\n{\"cmd\":\"stop\"}\n{\"cmd\":\"hello\"}\n")
            .await
            .unwrap();
        let status = within(lines.next_line()).await.unwrap().unwrap();
        assert!(status.starts_with("{\"ok\":{"), "{status}");
        let stop = within(lines.next_line()).await.unwrap().unwrap();
        assert!(stop.contains("only root may stop"), "{stop}");
        assert!(d.stop_requests.lock().is_empty());
        // The connection still serves requests after the refused stop.
        let hello = within(lines.next_line()).await.unwrap().unwrap();
        assert!(hello.contains("\"api\":"), "{hello}");
        d.shutdown().await;
    }

    #[tokio::test]
    async fn handle_api_refuses_stop_without_a_connection() {
        let (d, _dir) = crate::testing::daemon("api-stop-direct", crate::RelayMode::Never).await;
        assert!(matches!(
            d.handle_api(ApiRequest::Stop).await,
            ApiResponse::Err(e) if e.contains("API socket")
        ));
        assert!(d.stop_requests.lock().is_empty());
        d.shutdown().await;
    }
}
