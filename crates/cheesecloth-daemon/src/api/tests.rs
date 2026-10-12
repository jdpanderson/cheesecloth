use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::*;
use crate::ipc;

/// Fails the test instead of hanging when `f` never finishes.
async fn within<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("finished in time")
}

#[tokio::test]
async fn hello_names_the_api_and_daemon_versions() {
    let (d, _dir) = crate::testing::daemon("api-hello", crate::RelayMode::Never).await;
    let (server, socket) = crate::testing::serve(&d).await;
    let mut client = within(Client::connect(&socket)).await.unwrap();
    let hello: HelloView = within(client.request(&ApiRequest::Hello)).await.unwrap();
    assert_eq!(hello.api, API_VERSION);
    assert_eq!(hello.daemon, env!("CARGO_PKG_VERSION"));
    // The connection serves more requests after hello.
    let _: StatusView = within(client.request(&ApiRequest::Status)).await.unwrap();
    let _: serde_json::Value = within(client.request(&ApiRequest::Stop)).await.unwrap();
    within(server).await.unwrap().unwrap();
}

#[tokio::test]
async fn a_client_refuses_a_daemon_with_another_api_version() {
    let dir = tempfile::tempdir().unwrap();
    let addr = ipc::default_address(dir.path()).unwrap();
    let mut listener = ipc::Listener::bind(&addr).unwrap();
    // A daemon from the future: it answers hello with the next version.
    let server = tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (read, mut write) = tokio::io::split(stream);
        let line = BufReader::new(read).lines().next_line().await.unwrap();
        assert_eq!(line.as_deref(), Some(r#"{"cmd":"hello"}"#));
        let answer = format!(
            "{{\"ok\":{{\"api\":{},\"daemon\":\"9.9.9\"}}}}\n",
            API_VERSION + 1
        );
        write.write_all(answer.as_bytes()).await.unwrap();
    });
    let err = within(call::<StatusView>(&addr, &ApiRequest::Status))
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("cheesecloth 9.9.9"), "{err}");
    assert!(
        err.contains(&format!("local API version {}", API_VERSION + 1)),
        "{err}"
    );
    within(server).await.unwrap();
}
