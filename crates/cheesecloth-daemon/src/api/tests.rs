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

/// The JSON examples in `docs/LOCAL-API.md`, each with the word after
/// "json" on its opening fence.
fn doc_examples() -> Vec<(String, String)> {
    let doc = include_str!("../../../../docs/LOCAL-API.md");
    let mut examples = Vec::new();
    let mut lines = doc.lines();
    while let Some(line) = lines.next() {
        if let Some(kind) = line.strip_prefix("```json ") {
            let body: Vec<&str> = lines.by_ref().take_while(|l| *l != "```").collect();
            examples.push((kind.to_string(), body.join("\n")));
        }
    }
    examples
}

/// Parses `json` as a `T`, and checks that it is `T` exactly: written back,
/// it is the same JSON, so no field is misspelled, missing or extra.
fn check_as<T: serde::Serialize + DeserializeOwned>(json: &str) -> T {
    let doc: serde_json::Value = serde_json::from_str(json).expect(json);
    let typed: T = serde_json::from_value(doc.clone()).expect(json);
    assert_eq!(serde_json::to_value(&typed).unwrap(), doc, "{json}");
    typed
}

/// The `cmd` of a request. Each new request must be added here, and so to
/// the doc.
fn cmd(req: &ApiRequest) -> &'static str {
    match req {
        ApiRequest::Hello => "hello",
        ApiRequest::Status => "status",
        ApiRequest::Peers => "peers",
        ApiRequest::Init { .. } => "init",
        ApiRequest::Invite => "invite",
        ApiRequest::Join { .. } => "join",
        ApiRequest::Remove { .. } => "remove",
        ApiRequest::Leave { .. } => "leave",
        ApiRequest::Pending => "pending",
        ApiRequest::Approve { .. } => "approve",
        ApiRequest::Reject { .. } => "reject",
        ApiRequest::ConfigGet => "config_get",
        ApiRequest::ConfigSet { .. } => "config_set",
        ApiRequest::Stop => "stop",
    }
}

const ALL_CMDS: [&str; 14] = [
    "hello",
    "status",
    "peers",
    "init",
    "invite",
    "join",
    "remove",
    "leave",
    "pending",
    "approve",
    "reject",
    "config_get",
    "config_set",
    "stop",
];

#[test]
fn the_doc_examples_are_what_the_daemon_reads_and_writes() {
    let examples = doc_examples();
    assert!(examples.len() > 20, "{} examples", examples.len());
    let mut documented = std::collections::BTreeSet::new();
    for (kind, json) in &examples {
        match kind.as_str() {
            "request" => {
                documented.insert(cmd(&check_as::<ApiRequest>(json)));
            }
            "response" => drop(check_as::<ApiResponse>(json)),
            "hello" => drop(check_as::<HelloView>(json)),
            "status" => drop(check_as::<StatusView>(json)),
            "peers" => drop(check_as::<Vec<PeerView>>(json)),
            "init" => drop(check_as::<InitView>(json)),
            "invite" => drop(check_as::<InviteView>(json)),
            "join" => drop(check_as::<JoinView>(json)),
            "leave" => drop(check_as::<LeaveView>(json)),
            "change" => drop(check_as::<ChangeView>(json)),
            "pending" => drop(check_as::<Vec<ProposalView>>(json)),
            "config" => drop(check_as::<ConfigView>(json)),
            other => panic!("unknown example kind {other:?}"),
        }
    }
    let all: std::collections::BTreeSet<_> = ALL_CMDS.into_iter().collect();
    assert_eq!(documented, all, "requests without an example in the doc");
}

#[test]
fn the_doc_names_the_current_api_version() {
    let doc = include_str!("../../../../docs/LOCAL-API.md");
    assert!(
        doc.contains(&format!(
            "`hello` answers `api`, one integer, now `{API_VERSION}`"
        )),
        "update the Versions section of docs/LOCAL-API.md"
    );
}
