//! Run storage: a data directory holding one subdirectory per analyze run,
//! plus a flat JSON index for the dashboard listing (ADR-0018 D4 — no
//! database for a single-operator, low-write-volume local tool).

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMeta {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub input_filenames: Vec<String>,
    pub finding_count: usize,
    pub host_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Index {
    runs: Vec<RunMeta>,
}

pub struct Store {
    data_dir: PathBuf,
}

impl Store {
    /// Opens (creating if needed) the data directory and its `runs/`
    /// subdirectory. Synchronous — called once at startup, and the store's
    /// own read/write methods are also sync (called from inside
    /// `spawn_blocking` by the handlers that use them), matching the rest
    /// of otsniff's core pipeline (ADR-0008 stays true even in this crate
    /// for the actual file I/O; only the HTTP layer is async).
    pub fn open(data_dir: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir.join("runs"))?;
        Ok(Store { data_dir })
    }

    fn index_path(&self) -> PathBuf {
        self.data_dir.join("index.json")
    }

    pub fn run_dir(&self, id: &str) -> PathBuf {
        self.data_dir.join("runs").join(id)
    }

    fn read_index(&self) -> Index {
        std::fs::read_to_string(self.index_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn write_index(&self, index: &Index) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(index).expect("Index serializes");
        std::fs::write(self.index_path(), json)
    }

    /// Newest-first list of all runs.
    pub fn list_runs(&self) -> Vec<RunMeta> {
        let mut runs = self.read_index().runs;
        runs.sort_by_key(|r| std::cmp::Reverse(r.created_at));
        runs
    }

    /// Persists a new run's artifacts under `<data_dir>/runs/<id>/` and
    /// appends its metadata to the index. `id` must already be a directory
    /// created by the caller (via [`Store::run_dir`]) containing the
    /// files named in `artifacts`.
    pub fn record_run(&self, meta: RunMeta) -> std::io::Result<()> {
        let mut index = self.read_index();
        index.runs.push(meta);
        self.write_index(&index)
    }

    /// Generates a run id unique within this store: nanosecond timestamp
    /// hex, which is practically collision-free for a tool handling one
    /// upload at a time (and re-checked against the on-disk index as a
    /// belt-and-braces guard).
    pub fn new_run_id(&self) -> String {
        loop {
            let nanos = Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_else(|| Utc::now().timestamp());
            let id = format!("{nanos:x}");
            if !self.run_dir(&id).exists() {
                return id;
            }
        }
    }
}
