//! `otsniff-web` — local web companion app (ADR-0018).
//!
//! Binds to 127.0.0.1 only (no auth — that's the security boundary for
//! v1). Upload a PCAP, get the same `analyze` report otsniff's CLI
//! produces, rendered in the browser; past runs are listed on the
//! dashboard. See the ADR for what's deliberately deferred (AI analysis,
//! diff between runs, non-localhost deployment).
//!
//! Split into a lib + thin `main.rs` (mirroring the root `otsniff` crate)
//! so `build_router`/`AppState` are reachable from integration tests
//! without spawning the real binary.

pub mod pipeline;
pub mod store;

use std::path::PathBuf;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Multipart, Path as AxPath, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use ipnet::IpNet;

pub use store::{RunMeta, Store};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Store>,
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/runs", post(create_run))
        .route("/runs/{id}", get(view_run))
        .route("/runs/{id}/download/{kind}", get(download_run))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

pub struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(msg: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }

    fn internal(msg: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }

    fn not_found(msg: impl Into<String>) -> Self {
        AppError {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.status, format!("error: {}", self.message)).into_response()
    }
}

impl From<otsniff::OtError> for AppError {
    fn from(e: otsniff::OtError) -> Self {
        // otsniff's own exit-code taxonomy doesn't map cleanly onto HTTP
        // status; every pipeline failure here is "the uploaded input
        // couldn't be processed," which is a client-facing 400.
        AppError::bad_request(e.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::internal(e.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::internal(e.to_string())
    }
}

/// Flattens a `spawn_blocking` result: a `JoinError` (panic in the blocking
/// task) becomes a 500; the inner `Result<T, AppError>` passes through.
async fn run_blocking<T, F>(f: F) -> Result<T, AppError>
where
    F: FnOnce() -> Result<T, AppError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AppError::internal(format!("background task panicked: {e}")))?
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    runs: Vec<RunRow>,
}

struct RunRow {
    id: String,
    created_at: String,
    input_filenames: String,
    finding_count: usize,
    host_count: usize,
}

impl From<RunMeta> for RunRow {
    fn from(r: RunMeta) -> Self {
        RunRow {
            id: r.id,
            created_at: r.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            input_filenames: r.input_filenames.join(", "),
            finding_count: r.finding_count,
            host_count: r.host_count,
        }
    }
}

async fn dashboard(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let store = state.store.clone();
    let runs = run_blocking(move || Ok(store.list_runs())).await?;
    let tpl = DashboardTemplate {
        runs: runs.into_iter().map(RunRow::from).collect(),
    };
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::internal(e.to_string()))
}

// ---------------------------------------------------------------------------
// Create run (upload + analyze)
// ---------------------------------------------------------------------------

async fn create_run(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Redirect, AppError> {
    let mut pcap: Option<(String, Vec<u8>)> = None;
    let mut ot_subnets_raw = String::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(e.to_string()))?
    {
        match field.name().unwrap_or("") {
            "pcap" => {
                let filename = field
                    .file_name()
                    .map(safe_filename)
                    .unwrap_or_else(|| "capture.pcap".to_string());
                let data = field
                    .bytes()
                    .await
                    .map_err(|e| AppError::bad_request(e.to_string()))?;
                pcap = Some((filename, data.to_vec()));
            }
            "ot_subnets" => {
                ot_subnets_raw = field.text().await.unwrap_or_default();
            }
            _ => {}
        }
    }

    let (filename, data) =
        pcap.ok_or_else(|| AppError::bad_request("no PCAP file was uploaded"))?;
    if data.is_empty() {
        return Err(AppError::bad_request("uploaded file is empty"));
    }

    let ot_subnets: Vec<IpNet> = ot_subnets_raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>()
                .map_err(|e| AppError::bad_request(format!("invalid OT subnet '{s}': {e}")))
        })
        .collect::<Result<_, _>>()?;

    let store = state.store.clone();
    let run_id = store.new_run_id();
    let run_dir = store.run_dir(&run_id);

    let saved_id = run_blocking(move || -> Result<String, AppError> {
        std::fs::create_dir_all(&run_dir)?;
        let input_path = run_dir.join(&filename);
        std::fs::write(&input_path, &data)?;

        let subnets = if ot_subnets.is_empty() {
            pipeline::default_ot_subnets()
        } else {
            ot_subnets
        };
        let output = pipeline::run_analyze(&[input_path], &subnets, &filename)?;

        std::fs::write(run_dir.join("report.html"), &output.html)?;
        std::fs::write(run_dir.join("report.json"), &output.json)?;

        let meta = RunMeta {
            id: run_id.clone(),
            created_at: chrono::Utc::now(),
            input_filenames: vec![filename],
            finding_count: output.finding_count,
            host_count: output.host_count,
        };
        store.record_run(meta)?;
        Ok(run_id)
    })
    .await?;

    Ok(Redirect::to(&format!("/runs/{saved_id}")))
}

/// Takes just the file-name component of a client-supplied upload name,
/// discarding any path separators or `..` traversal — the same defensive
/// pattern `basename_of` uses throughout the core `otsniff` crate.
fn safe_filename(name: &str) -> String {
    let base = std::path::Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if base.is_empty() {
        "capture.pcap".to_string()
    } else {
        base.to_string()
    }
}

// ---------------------------------------------------------------------------
// View / download a run
// ---------------------------------------------------------------------------

async fn view_run(
    State(state): State<AppState>,
    AxPath(id): AxPath<String>,
) -> Result<Html<String>, AppError> {
    let store = state.store.clone();
    let html = run_blocking(move || {
        std::fs::read_to_string(store.run_dir(&id).join("report.html"))
            .map_err(|_| AppError::not_found(format!("run '{id}' not found")))
    })
    .await?;
    Ok(Html(html))
}

async fn download_run(
    State(state): State<AppState>,
    AxPath((id, kind)): AxPath<(String, String)>,
) -> Result<Response, AppError> {
    let (filename, content_type) = match kind.as_str() {
        "html" => ("report.html", "text/html; charset=utf-8"),
        "json" => ("report.json", "application/json"),
        other => {
            return Err(AppError::bad_request(format!(
                "unknown download kind '{other}' (expected html or json)"
            )))
        }
    };
    let store = state.store.clone();
    let bytes = run_blocking(move || {
        std::fs::read(store.run_dir(&id).join(filename))
            .map_err(|_| AppError::not_found(format!("run '{id}' has no {filename}")))
    })
    .await?;

    Ok(([(header::CONTENT_TYPE, content_type)], bytes).into_response())
}

/// Opens the data directory and builds an [`AppState`] — the one bit of
/// setup shared between the real `main.rs` and integration tests.
pub fn open_state(data_dir: PathBuf) -> std::io::Result<AppState> {
    let store = Store::open(data_dir)?;
    Ok(AppState {
        store: Arc::new(store),
    })
}
