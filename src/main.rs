use std::process::ExitCode;

fn main() -> ExitCode {
    match otsniff::cli::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("otsniff: {e}");
            let mut source = std::error::Error::source(&e);
            while let Some(s) = source {
                eprintln!("  caused by: {s}");
                source = s.source();
            }
            ExitCode::from(e.exit_code() as u8)
        }
    }
}
