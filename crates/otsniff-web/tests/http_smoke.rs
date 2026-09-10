//! End-to-end HTTP smoke tests: starts the real axum app on an ephemeral
//! port (in-process, no subprocess) and drives it with `reqwest`, exactly
//! the way a browser would. These are the closest thing to a browser test
//! this environment can automate.

use std::net::SocketAddr;
use std::path::PathBuf;

use tempfile::TempDir;

/// Starts the app on `127.0.0.1:0` (OS-assigned port) against a fresh temp
/// data directory. Returns the base URL; the server task is detached and
/// dies with the process (fine for tests — each test gets its own port).
async fn spawn_app() -> (String, TempDir) {
    let data_dir = TempDir::new().unwrap();
    let state = otsniff_web::open_state(data_dir.path().to_path_buf()).unwrap();
    let app = otsniff_web::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), data_dir)
}

fn fixture_pcap() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/synthetic-1mb.pcap")
}

#[tokio::test]
async fn dashboard_loads_and_is_empty_before_any_run() {
    let (base, _dir) = spawn_app().await;
    let resp = reqwest::get(format!("{base}/")).await.unwrap();
    assert!(resp.status().is_success());
    let body = resp.text().await.unwrap();
    assert!(body.contains("No runs yet"));
    assert!(body.contains("New analysis"));
}

#[tokio::test]
async fn upload_without_a_file_is_a_bad_request() {
    let (base, _dir) = spawn_app().await;
    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new().text("ot_subnets", "");
    let resp = client
        .post(format!("{base}/runs"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("no PCAP file"));
}

#[tokio::test]
async fn upload_with_invalid_ot_subnet_is_a_bad_request() {
    let pcap = fixture_pcap();
    if !pcap.exists() {
        eprintln!("skipping: fixture not present");
        return;
    }
    let (base, _dir) = spawn_app().await;
    let client = reqwest::Client::new();
    let bytes = std::fs::read(&pcap).unwrap();
    let part = reqwest::multipart::Part::bytes(bytes).file_name("synthetic-1mb.pcap");
    let form = reqwest::multipart::Form::new()
        .part("pcap", part)
        .text("ot_subnets", "not-a-cidr");
    let resp = client
        .post(format!("{base}/runs"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("invalid OT subnet"));
}

#[tokio::test]
async fn viewing_or_downloading_an_unknown_run_is_404() {
    let (base, _dir) = spawn_app().await;
    let resp = reqwest::get(format!("{base}/runs/does-not-exist"))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);

    let resp = reqwest::get(format!("{base}/runs/does-not-exist/download/json"))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn download_with_unknown_kind_is_bad_request() {
    let (base, _dir) = spawn_app().await;
    let resp = reqwest::get(format!("{base}/runs/whatever/download/exe"))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// The full happy path: upload the real committed fixture, follow the
/// redirect to the rendered report, confirm it looks like a real otsniff
/// report, confirm the JSON sidecar downloads and parses, and confirm the
/// run now shows up on the dashboard.
#[tokio::test]
async fn full_upload_view_download_round_trip() {
    let pcap = fixture_pcap();
    if !pcap.exists() {
        assert!(
            std::env::var("CI").is_err(),
            "tests/fixtures/synthetic-1mb.pcap missing in CI"
        );
        eprintln!("skipping: fixture not present");
        return;
    }
    let (base, _dir) = spawn_app().await;
    let client = reqwest::Client::new();

    let bytes = std::fs::read(&pcap).unwrap();
    let part = reqwest::multipart::Part::bytes(bytes).file_name("synthetic-1mb.pcap");
    let form = reqwest::multipart::Form::new().part("pcap", part);
    let resp = client
        .post(format!("{base}/runs"))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success() || resp.status().is_redirection(),
        "unexpected status: {}",
        resp.status()
    );
    let run_url = resp.url().clone();
    assert!(
        run_url.path().starts_with("/runs/"),
        "expected reqwest to have followed the redirect to /runs/<id>, landed on {run_url}"
    );

    let html = resp.text().await.unwrap();
    assert!(html.contains("<html"));
    assert!(html.contains("Asset inventory"));

    // JSON sidecar downloads and parses.
    let download_url = format!("{run_url}/download/json");
    let resp = client.get(&download_url).send().await.unwrap();
    assert!(resp.status().is_success(), "GET {download_url}");
    let json_text = resp.text().await.unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    assert!(parsed.get("inventory").is_some());
    assert!(parsed.get("findings").is_some());

    // Dashboard now lists the run.
    let dash = reqwest::get(format!("{base}/")).await.unwrap();
    let dash_body = dash.text().await.unwrap();
    assert!(dash_body.contains("synthetic-1mb.pcap"));
    assert!(!dash_body.contains("No runs yet"));
}
