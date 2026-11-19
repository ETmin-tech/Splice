//! Thin entry point: init tracing, parse CLI, dispatch.

use clap::Parser;

fn main() {
    splice_core::init_tracing();

    let cli = splice::cli::Cli::parse();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    if let Err(err) = rt.block_on(splice::cli::run(cli)) {
        // Errors are already logged via tracing; print a user-facing message.
        eprintln!("Gagal: {err}");
        std::process::exit(1);
    }
}
