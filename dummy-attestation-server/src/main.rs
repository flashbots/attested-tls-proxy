use attested_tls_proxy::attestation::AttestationType;
use clap::{Parser, Subcommand};
use dummy_attestation_server::{dummy_attestation_client, dummy_attestation_server};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;

#[derive(Parser, Debug, Clone)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Log debug messages
    #[arg(long, global = true)]
    log_debug: bool,
    /// Log in JSON format
    #[arg(long, global = true)]
    log_json: bool,
}
#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    Server {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// Type of attestation to present (defaults to none)
        #[arg(long)]
        server_attestation_type: Option<String>,
    },
    Client {
        /// Socket address of a dummy attestation server
        server_addr: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let level_filter = if cli.log_debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::WARN
    };

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(level_filter.into())
        .from_env_lossy();

    let subscriber = tracing_subscriber::fmt::Subscriber::builder().with_env_filter(env_filter);

    if cli.log_json {
        subscriber.json().init();
    } else {
        subscriber.pretty().init();
    }

    match cli.command {
        CliCommand::Server {
            listen_addr,
            server_attestation_type,
        } => {
            let server_attestation_type: AttestationType = serde_json::from_value(
                serde_json::Value::String(server_attestation_type.unwrap_or("none".to_string())),
            )?;

            let attestation_generator = server_attestation_type.get_quote_generator()?;

            let listener = TcpListener::bind(listen_addr).await?;
            dummy_attestation_server(listener, attestation_generator).await?;
        }
        CliCommand::Client { server_addr } => dummy_attestation_client(server_addr).await?,
    }

    Ok(())
}
