//! The local API: one JSON request per line on the local IPC channel (see
//! `api` and `ipc`).

use std::sync::Arc;

use anyhow::Result;
use cheesecloth_core::state::Outcome;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::info;

use crate::{
    Daemon, Phase,
    api::{self, ApiError, ApiRequest, ApiResponse, ChangeView, ErrorCode, HelloView},
    ipc::{self, Access},
    node::Refused,
};

fn to_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| {
        ApiError::new(ErrorCode::InternalError, format!("writing the answer: {e}")).into()
    })
}

/// The answer to a request that changes the cluster.
fn change(outcome: Outcome) -> Result<serde_json::Value> {
    to_json(ChangeView::try_from(outcome)?)
}

/// `error` as the client sees it: its code, and its whole chain of causes.
fn api_error(error: &anyhow::Error) -> ApiError {
    let default = error
        .downcast_ref::<Refused>()
        .map_or(ErrorCode::OperationFailed, ErrorCode::from);
    ApiError::classify(error, default)
}

async fn write_response(
    write: &mut (impl AsyncWrite + Unpin + ?Sized),
    resp: &ApiResponse,
) -> std::io::Result<()> {
    write.write_all(api::json_line(resp).as_bytes()).await
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
                ApiRequest::Invite { permissions } => to_json(self.invite(permissions).await?)?,
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
                ApiRequest::Stop => {
                    return Err(ApiError::new(
                        ErrorCode::InvalidRequest,
                        "stop is only served on the API socket",
                    )
                    .into());
                }
            })
        }
        .await;
        match res {
            Ok(v) => ApiResponse::Ok(v),
            Err(e) => ApiResponse::Err(api_error(&e)),
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
            Phase::Stopping { error, .. } => ApiResponse::Err(ApiError::new(
                ErrorCode::CleanupPending,
                match error {
                    Some(e) => format!("stopped, but local cleanup is pending: {e}"),
                    None => "stopped, but local cleanup is pending".into(),
                },
            )),
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
        if let Access::Refused(refusal) = access {
            // A client that has gone away doesn't need the answer.
            let _ = write_response(&mut write, &ApiResponse::Err(refusal)).await;
            return;
        }
        let mut lines = BufReader::new(read).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let resp = match serde_json::from_str::<ApiRequest>(&line) {
                Ok(ApiRequest::Stop) if access == Access::Full => {
                    self.request_stop(write);
                    return;
                }
                Ok(ApiRequest::Stop) => ApiResponse::Err(ApiError::new(
                    ErrorCode::PermissionDenied,
                    "only root may stop the daemon; stop its service instead",
                )),
                Ok(req) => self
                    .api_work
                    .run(self.handle_api(req))
                    .await
                    .unwrap_or_else(|_| {
                        ApiResponse::Err(ApiError::new(
                            ErrorCode::ShuttingDown,
                            "the daemon is shutting down",
                        ))
                    }),
                Err(e) => ApiResponse::Err(ApiError::new(
                    ErrorCode::InvalidRequest,
                    format!("bad request: {e}"),
                )),
            };
            if write_response(&mut write, &resp).await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests;
