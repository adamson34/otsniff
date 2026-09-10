use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "otsniff-web", about = "Local web companion app for otsniff")]
struct Args {
    /// Port to bind on 127.0.0.1.
    #[arg(long, default_value_t = 7878)]
    port: u16,
    /// Directory to store uploaded captures and generated reports.
    #[arg(long, default_value = "otsniff-web-data")]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let state = otsniff_web::open_state(args.data_dir.clone()).expect("could not open --data-dir");
    let app = otsniff_web::build_router(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("could not bind {addr}: {e}"));
    eprintln!(
        "otsniff-web listening on http://{addr}  (data dir: {})",
        args.data_dir.display()
    );
    axum::serve(listener, app).await.expect("server error");
}
