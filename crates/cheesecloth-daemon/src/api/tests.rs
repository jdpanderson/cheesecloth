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
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::ApiVersionMismatch);
    let err = err.message;
    assert!(err.contains("cheesecloth 9.9.9"), "{err}");
    assert!(
        err.contains(&format!("local API version {}", API_VERSION + 1)),
        "{err}"
    );
    within(server).await.unwrap();
}

/// A daemon that answers the first line with `answer`.
async fn answering(answer: &'static str) -> (std::path::PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let addr = ipc::default_address(dir.path()).unwrap();
    let mut listener = ipc::Listener::bind(&addr).unwrap();
    tokio::spawn(async move {
        let stream = listener.accept().await.unwrap();
        let (read, mut write) = tokio::io::split(stream);
        let _ = BufReader::new(read).lines().next_line().await;
        write.write_all(answer.as_bytes()).await.unwrap();
        write.write_all(b"\n").await.unwrap();
    });
    (addr, dir)
}

#[tokio::test]
async fn a_daemon_from_before_hello_is_a_version_mismatch() {
    // cheesecloth 0.4.0 answers an unknown request with a string.
    let (addr, _dir) = answering(r#"{"err":"bad request: unknown variant `hello`"}"#).await;
    let err = within(Client::connect(&addr)).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::ApiVersionMismatch, "{err}");
}

#[tokio::test]
async fn a_refusal_before_hello_keeps_its_code() {
    let (addr, _dir) =
        answering(r#"{"err":{"code":"permission_denied","message":"only root"}}"#).await;
    let err = within(Client::connect(&addr)).await.err().unwrap();
    assert_eq!(err, ApiError::new(ErrorCode::PermissionDenied, "only root"));
}

#[tokio::test]
async fn a_code_from_a_newer_daemon_is_kept() {
    let (addr, _dir) =
        answering(r#"{"err":{"code":"dragons","message":"here be dragons","extra":1}}"#).await;
    let err = within(Client::connect(&addr)).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::Other("dragons".into()));
    assert_eq!(err.code.as_str(), "dragons");
    assert_eq!(err.message, "here be dragons");
}

#[tokio::test]
async fn a_missing_daemon_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let addr = ipc::default_address(dir.path()).unwrap();
    let err = within(Client::connect(&addr)).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::DaemonUnavailable, "{err}");
}

#[tokio::test]
async fn an_unreadable_answer_is_an_invalid_response() {
    let (addr, _dir) = answering("hello?").await;
    let err = within(Client::connect(&addr)).await.err().unwrap();
    assert_eq!(err.code, ErrorCode::InvalidResponse, "{err}");
}

#[test]
fn a_code_given_at_the_source_survives_added_context() {
    use anyhow::Context;
    let coded: anyhow::Result<()> =
        Err(ApiError::new(ErrorCode::NoQuorum, "couldn't agree").into());
    let e = coded.context("leaving").unwrap_err();
    let api = ApiError::classify(&e, ErrorCode::OperationFailed);
    assert_eq!(api.code, ErrorCode::NoQuorum);
    // The message keeps the whole chain, for people.
    assert_eq!(api.message, "leaving: couldn't agree");

    let refused: anyhow::Result<()> =
        Err(cheesecloth_core::state::CommandError::AlreadyApproved.into());
    let e = refused.context("approving").unwrap_err();
    let api = ApiError::classify(&e, ErrorCode::OperationFailed);
    assert_eq!(api.code, ErrorCode::AlreadyApproved);

    let plain = anyhow::anyhow!("disk full");
    let api = ApiError::classify(&plain, ErrorCode::OperationFailed);
    assert_eq!(api.code, ErrorCode::OperationFailed);
}

#[test]
fn the_doc_lists_every_error_code() {
    let doc = include_str!("../../../../docs/LOCAL-API.md");
    let known: std::collections::BTreeSet<&str> =
        ErrorCode::KNOWN.iter().map(ErrorCode::as_str).collect();
    let documented = error_codes_in_doc(doc);
    assert_eq!(documented, known, "the Errors section and ErrorCode differ");
    let crlf_doc = doc.lines().collect::<Vec<_>>().join("\r\n");
    assert_eq!(error_codes_in_doc(&crlf_doc), known);
    for code in ErrorCode::KNOWN {
        assert!(!matches!(code, ErrorCode::Other(_)));
        let round: ErrorCode = serde_json::from_value(serde_json::to_value(code).unwrap()).unwrap();
        assert_eq!(&round, code);
    }
}

fn error_codes_in_doc(doc: &str) -> std::collections::BTreeSet<&str> {
    let mut lines = doc.lines();
    assert!(lines.any(|line| line == "## Errors"), "an Errors section");
    lines
        .take_while(|line| !line.starts_with("## "))
        .filter_map(|line| line.strip_prefix("| `")?.split('`').next())
        .collect()
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
        ApiRequest::Invite { .. } => "invite",
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
            "cli_error" => drop(check_as::<ErrorDocument>(json)),
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
