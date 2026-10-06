mod cli;

use anyhow::anyhow;
use clap::Parser;
use cli::Cli;
use std::time::Duration;
use tracing::level_filters::LevelFilter;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install the default rustls crypto provider"))?;
    cli.validate()?;
    init_logging(&cli);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(cli.run());
    // Command-specific cleanup has finished. Do not wait indefinitely for
    // blocking quote generation when tearing down the runtime.
    runtime.shutdown_timeout(Duration::ZERO);
    result
}

fn init_logging(cli: &Cli) {
    let crate_name = env!("CARGO_CRATE_NAME");
    let level = if cli.log_debug { "debug" } else { "info" };
    let filter = format!("{crate_name}={level},attested_tls={level}");

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into()) // global default
        .parse_lossy(filter);

    let subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr);

    if cli.log_json {
        subscriber.json().init();
    } else {
        subscriber.pretty().init();
    }
}
