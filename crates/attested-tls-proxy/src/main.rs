use anyhow::{anyhow, ensure};
use attested_tls::attestation::measurements::MultiMeasurements;
use clap::{Parser, Subcommand};
use std::{
    fs::File,
    net::{IpAddr, SocketAddr},
    num::{NonZeroU64, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::level_filters::LevelFilter;

use attested_tls_proxy::{
    AttestationGenerator, ProxyClient, ProxyClientOptions, ProxyServer,
    attested_get::{attested_get, split_target_and_path},
    attested_tls::{
        TlsCertAndKey,
        attestation::{
            AttestationType, AttestationVerifier, PccsMode, measurements::MeasurementPolicy,
        },
    },
    file_server::attested_file_server,
    get_tls_cert, health_check,
};

const GIT_REV: &str = match option_env!("GIT_REV") {
    Some(rev) => rev,
    None => "unknown",
};

#[derive(Parser, Debug, Clone)]
#[command(version = GIT_REV, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: CliCommand,
    /// Path to file, or URL, containing JSON measurements to be enforced on the remote party
    #[arg(long, global = true, env = "MEASUREMENTS_FILE")]
    measurements_file: Option<String>,
    /// If no measurements file is specified, a single attestion type to allow
    #[arg(long, global = true)]
    allowed_remote_attestation_type: Option<String>,
    /// The URL of a PCCS to use when verifying DCAP attestations. Defaults to Intel PCS.
    #[arg(long, global = true)]
    pccs_url: Option<String>,
    /// Log debug messages
    #[arg(long, global = true)]
    log_debug: bool,
    /// Log in JSON format
    #[arg(long, global = true)]
    log_json: bool,
    /// Log DCAP quotes to folder `quotes/`
    #[arg(long, global = true)]
    log_dcap_quote: bool,
    /// Overrides Azure outdated TCB info
    #[arg(long, global = true, env = "OVERRIDE_AZURE_OUTDATED_TCB")]
    override_azure_outdated_tcb: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum CliCommand {
    /// Run a proxy client
    Client {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        target_addr: String,
        /// Request deadline in seconds, including queueing and waiting for response headers
        #[arg(long, default_value = "60")]
        request_timeout_secs: NonZeroU64,
        /// Close a source connection if its response body makes no write progress for this many seconds
        #[arg(long, default_value = "60")]
        response_body_idle_timeout_secs: NonZeroU64,
        /// Maximum in-flight requests, including streaming responses
        #[arg(long, default_value = "64", value_parser = parse_max_in_flight_requests)]
        max_in_flight_requests: NonZeroUsize,
        /// Type of attestation to present (dafaults to 'auto' for automatic detection)
        /// If other than None, a TLS key and certicate must also be given
        #[arg(long, env = "CLIENT_ATTESTATION_TYPE")]
        client_attestation_type: Option<String>,
        /// The path to a PEM encoded private key for client authentication
        #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
        tls_private_key_path: Option<PathBuf>,
        /// The path to a PEM encoded certificate chain for client authentication
        #[arg(long, env = "TLS_CERTIFICATE_PATH")]
        tls_certificate_path: Option<PathBuf>,
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        #[arg(long)]
        tls_ca_certificate: Option<PathBuf>,
        /// URL of the remote dummy attestation service. Only use with --client-attestation-type
        /// dummy
        #[arg(long)]
        dev_dummy_dcap: Option<String>,
        // Address to listen on for health checks
        #[arg(long)]
        listen_addr_healthcheck: Option<SocketAddr>,
        /// Enables verification of self-signed TLS certificates
        #[arg(long)]
        allow_self_signed: bool,
    },
    /// Run a proxy server
    Server {
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// The hostname:port or ip:port of the target service to forward traffic to
        target_addr: String,
        /// Type of attestation to present (dafaults to 'auto' for automatic detection)
        /// If other than None, a TLS key and certicate must also be given
        #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
        server_attestation_type: Option<String>,
        /// The path to a PEM encoded private key
        #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
        tls_private_key_path: Option<PathBuf>,
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        #[arg(long, env = "TLS_CERTIFICATE_PATH")]
        tls_certificate_path: Option<PathBuf>,
        /// Whether to use client authentication. If the client is running in a CVM this must be
        /// enabled.
        #[arg(long)]
        client_auth: bool,
        /// URL of the remote dummy attestation service. Only use with --server-attestation-type
        /// dummy
        #[arg(long)]
        dev_dummy_dcap: Option<String>,
        // Address to listen on for health checks
        #[arg(long)]
        listen_addr_healthcheck: Option<SocketAddr>,
    },
    /// Retrieve the attested TLS certificate from a proxy server
    GetTlsCert {
        /// The hostname:port or ip:port of the proxy server (port defaults to 443)
        server: String,
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        #[arg(long)]
        tls_ca_certificate: Option<PathBuf>,
        /// Enables verification of self-signed TLS certificates
        #[arg(long)]
        allow_self_signed: bool,
        /// Filename to write measurements as JSON to
        #[arg(long)]
        out_measurements: Option<PathBuf>,
    },
    /// Serve a filesystem path over an attested channel
    AttestedFileServer {
        /// Filesystem path to statically serve
        path_to_serve: PathBuf,
        /// Socket address to listen on
        #[arg(short, long, default_value = "0.0.0.0:0", env = "LISTEN_ADDR")]
        listen_addr: SocketAddr,
        /// Type of attestation to present (dafaults to none)
        /// If other than None, a TLS key and certicate must also be given
        #[arg(long, env = "SERVER_ATTESTATION_TYPE")]
        server_attestation_type: Option<String>,
        /// The path to a PEM encoded private key
        #[arg(long, env = "TLS_PRIVATE_KEY_PATH")]
        tls_private_key_path: PathBuf,
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        #[arg(long, env = "TLS_CERTIFICATE_PATH")]
        tls_certificate_path: PathBuf,
        /// URL of the remote dummy attestation service. Only use with --server-attestation-type
        /// dummy
        #[arg(long)]
        dev_dummy_dcap: Option<String>,
    },
    /// Start a proxy-client, send a single HTTP GET request to the given path and print the
    /// response to standard output
    AttestedGet {
        /// The hostname:port or ip:port of the proxy server (port defaults to 443) together
        /// with the URL path to GET from the target service, eg: 127.0.0.1:3000/foobar
        target_addr: String,
        /// Additional CA certificate to verify against (PEM) Defaults to no additional TLS certs.
        #[arg(long)]
        tls_ca_certificate: Option<PathBuf>,
        /// Enables verification of self-signed TLS certificates
        #[arg(long)]
        allow_self_signed: bool,
        /// Optional path to GET (defaults to '/') - this takes precedence over giving the path
        /// as part of the target address.
        #[arg(long)]
        url_path: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install the default rustls crypto provider"))?;

    let cli = Cli::parse();

    ensure!(
        cli.allowed_remote_attestation_type.is_some() != cli.measurements_file.is_some(),
        "Exactly one of --measurements-file or --allowed-remote-attestation-type must be provided"
    );

    let crate_name = env!("CARGO_CRATE_NAME");

    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into()) // global default
        .parse_lossy(format!(
            "{crate_name}={}",
            if cli.log_debug { "debug" } else { "warn" }
        ));

    let subscriber = tracing_subscriber::fmt::Subscriber::builder().with_env_filter(env_filter);

    if cli.log_json {
        subscriber.json().init();
    } else {
        subscriber.pretty().init();
    }

    if cli.log_dcap_quote {
        tokio::fs::create_dir_all("quotes").await?;
    }

    let measurement_policy = match cli.measurements_file {
        Some(server_measurements) => {
            MeasurementPolicy::from_file_or_url(server_measurements).await?
        }
        None => {
            match cli
                .allowed_remote_attestation_type
                .ok_or(anyhow!(
                    "Either a measurements file or an allowed attestation type must be provided"
                ))?
                .to_lowercase()
                .as_str()
            {
                "tdx" => MeasurementPolicy::tdx(),
                attestation_type => {
                    let allowed_server_attestation_type: AttestationType = serde_json::from_value(
                        serde_json::Value::String(attestation_type.to_string()),
                    )?;
                    MeasurementPolicy::single_attestation_type(allowed_server_attestation_type)
                }
            }
        }
    };

    let mut attestation_verifier_builder = AttestationVerifier::builder(measurement_policy)
        .with_pccs_mode(PccsMode::Lazy)
        .with_dump_dcap_quotes(cli.log_dcap_quote)
        .with_override_azure_outdated_tcb(cli.override_azure_outdated_tcb);
    if let Some(pccs_url) = cli.pccs_url {
        attestation_verifier_builder = attestation_verifier_builder.with_pccs_url(pccs_url);
    }
    let attestation_verifier = attestation_verifier_builder.build();

    match cli.command {
        CliCommand::Client {
            listen_addr,
            target_addr,
            request_timeout_secs,
            response_body_idle_timeout_secs,
            max_in_flight_requests,
            client_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            tls_ca_certificate,
            dev_dummy_dcap,
            listen_addr_healthcheck,
            allow_self_signed,
        } => {
            let target_addr = target_addr
                .strip_prefix("https://")
                .unwrap_or(&target_addr)
                .to_string();

            if let Some(listen_addr_healthcheck) = listen_addr_healthcheck {
                health_check::server(listen_addr_healthcheck).await?;
            }

            let tls_cert_and_chain = if let Some(private_key) = tls_private_key_path {
                Some(load_tls_cert_and_key(
                    tls_certificate_path
                        .ok_or(anyhow!("Private key given but no certificate chain"))?,
                    private_key,
                )?)
            } else {
                ensure!(
                    tls_certificate_path.is_none(),
                    "Certificate chain given but no private key"
                );
                None
            };

            let remote_tls_cert = match tls_ca_certificate {
                Some(remote_cert_filename) => Some(
                    load_certs_pem(remote_cert_filename)?
                        .first()
                        .ok_or(anyhow!("Filename given but no ceritificates found"))?
                        .clone(),
                ),
                None => None,
            };

            let client_attestation_generator =
                AttestationGenerator::new_with_detection(client_attestation_type, dev_dummy_dcap)?;

            let client = if allow_self_signed {
                let client_tls_config =
                    attested_tls_proxy::self_signed::client_tls_config_allow_self_signed(
                        tls_cert_and_chain.as_ref(),
                    )?;
                ProxyClient::new_with_tls_config(
                    client_tls_config,
                    listen_addr,
                    target_addr,
                    client_attestation_generator,
                    attestation_verifier,
                    tls_cert_and_chain.map(|identity| identity.cert_chain),
                )
                .await?
            } else {
                ProxyClient::new(
                    tls_cert_and_chain,
                    listen_addr,
                    target_addr,
                    client_attestation_generator,
                    attestation_verifier,
                    remote_tls_cert,
                )
                .await?
            }
            .with_request_options(ProxyClientOptions {
                request_timeout: Duration::from_secs(request_timeout_secs.get()),
                response_body_idle_timeout: Duration::from_secs(
                    response_body_idle_timeout_secs.get(),
                ),
                max_in_flight_requests,
            });

            loop {
                if let Err(err) = client.accept().await {
                    tracing::error!("Failed to handle connection: {err}");
                }
            }
        }
        CliCommand::Server {
            listen_addr,
            target_addr,
            tls_private_key_path,
            tls_certificate_path,
            client_auth,
            server_attestation_type,
            dev_dummy_dcap,
            listen_addr_healthcheck,
        } => {
            if let Some(listen_addr_healthcheck) = listen_addr_healthcheck {
                health_check::server(listen_addr_healthcheck).await?;
            }

            let tls_cert_and_chain = load_tls_cert_and_key_server(
                tls_certificate_path,
                tls_private_key_path,
                listen_addr.ip(),
            )?;

            let local_attestation_generator =
                AttestationGenerator::new_with_detection(server_attestation_type, dev_dummy_dcap)?;

            let server = ProxyServer::new(
                tls_cert_and_chain,
                listen_addr,
                target_addr,
                local_attestation_generator,
                attestation_verifier,
                client_auth,
            )
            .await?;

            loop {
                if let Err(err) = server.accept().await {
                    tracing::error!("Failed to handle connection: {err}");
                }
            }
        }
        CliCommand::GetTlsCert {
            server,
            tls_ca_certificate,
            allow_self_signed,
            out_measurements,
        } => {
            let remote_tls_cert = match tls_ca_certificate {
                Some(remote_cert_filename) => Some(
                    load_certs_pem(remote_cert_filename)?
                        .first()
                        .ok_or(anyhow!("Filename given but no ceritificates found"))?
                        .clone(),
                ),
                None => None,
            };
            let (cert_chain, measurements) = get_tls_cert(
                server,
                attestation_verifier,
                remote_tls_cert,
                allow_self_signed,
            )
            .await?;

            // If the user chose to write measurements to a file as JSON
            if let Some(path_to_write_measurements) = out_measurements {
                std::fs::write(
                    path_to_write_measurements,
                    measurements
                        .unwrap_or(MultiMeasurements::NoAttestation)
                        .to_header_format()?
                        .as_bytes(),
                )?;
            }
            println!("{}", certs_to_pem_string(&cert_chain)?);
        }
        CliCommand::AttestedFileServer {
            path_to_serve,
            listen_addr,
            server_attestation_type,
            tls_private_key_path,
            tls_certificate_path,
            dev_dummy_dcap,
        } => {
            let tls_cert_and_chain =
                load_tls_cert_and_key(tls_certificate_path, tls_private_key_path)?;

            let server_attestation_type: AttestationType = serde_json::from_value(
                serde_json::Value::String(server_attestation_type.unwrap_or("none".to_string())),
            )?;

            let attestation_generator =
                AttestationGenerator::new(server_attestation_type, dev_dummy_dcap)?;

            attested_file_server(
                path_to_serve,
                tls_cert_and_chain,
                listen_addr,
                attestation_generator,
                attestation_verifier,
                false,
            )
            .await?;
        }
        CliCommand::AttestedGet {
            target_addr,
            url_path,
            tls_ca_certificate,
            allow_self_signed,
        } => {
            let remote_tls_cert = match tls_ca_certificate {
                Some(remote_cert_filename) => Some(
                    load_certs_pem(remote_cert_filename)?
                        .first()
                        .ok_or(anyhow!("Filename given but no ceritificates found"))?
                        .clone(),
                ),
                None => None,
            };

            let (target_addr, embedded_url_path) = split_target_and_path(&target_addr);
            let url_path = url_path.or(embedded_url_path);

            let mut response = attested_get(
                target_addr,
                url_path.as_deref().unwrap_or("/"),
                attestation_verifier,
                remote_tls_cert,
                allow_self_signed,
            )
            .await?;

            ensure!(
                !response.status().is_redirection(),
                "Attested GET returned {}; redirects are not followed because the destination has not been attested",
                response.status()
            );

            // Write response body to standard output
            let mut stdout = tokio::io::stdout();

            while let Some(chunk) = response.chunk().await? {
                stdout.write_all(&chunk).await?;
            }

            stdout.flush().await?;
        }
    }

    Ok(())
}

fn load_tls_cert_and_key_server(
    cert_chain: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ip: IpAddr,
) -> anyhow::Result<TlsCertAndKey> {
    if let Some(private_key) = private_key {
        load_tls_cert_and_key(
            cert_chain.ok_or(anyhow!("Private key given but no certificate chain"))?,
            private_key,
        )
    } else {
        if cert_chain.is_some() {
            return Err(anyhow!("Certificate chain provided but no private key"));
        }
        tracing::warn!("No TLS ceritifcate provided - generating self-signed");
        Ok(attested_tls_proxy::self_signed::generate_self_signed_cert(
            ip,
        )?)
    }
}

/// Load TLS details from storage
fn load_tls_cert_and_key(
    cert_chain: PathBuf,
    private_key: PathBuf,
) -> anyhow::Result<TlsCertAndKey> {
    let key = load_private_key_pem(private_key)?;
    let cert_chain = load_certs_pem(cert_chain)?;
    Ok(TlsCertAndKey { key, cert_chain })
}

/// load certificates from a PEM-encoded file
fn load_certs_pem(path: PathBuf) -> std::io::Result<Vec<CertificateDer<'static>>> {
    rustls_pemfile::certs(&mut std::io::BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
}

/// load TLS private key from a PEM-encoded file
fn load_private_key_pem(path: PathBuf) -> anyhow::Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut std::io::BufReader::new(File::open(path)?))?
        .ok_or_else(|| anyhow!("No private key found in PEM"))
}

/// Given a certificate chain, convert it to a PEM encoded string
fn certs_to_pem_string(certs: &[CertificateDer<'_>]) -> Result<String, pem_rfc7468::Error> {
    let mut out = String::new();
    for cert in certs {
        let block =
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, cert.as_ref())?;
        out.push_str(&block);
        out.push('\n');
    }
    Ok(out)
}

/// Parses an admission limit within Tokio's supported semaphore range.
fn parse_max_in_flight_requests(value: &str) -> Result<NonZeroUsize, String> {
    let count = value
        .parse::<NonZeroUsize>()
        .map_err(|error| error.to_string())?;
    if count.get() > tokio::sync::Semaphore::MAX_PERMITS {
        return Err(format!(
            "must not exceed {}",
            tokio::sync::Semaphore::MAX_PERMITS,
        ));
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::{SignatureScheme, crypto::aws_lc_rs};

    fn load_pem_fixture(pem: &[u8]) -> anyhow::Result<PrivateKeyDer<'static>> {
        let file = tempfile::NamedTempFile::new()?;
        std::fs::write(file.path(), pem)?;
        load_private_key_pem(file.path().to_owned())
    }

    // Public test fixtures only; never use these keys in a deployment.
    const RSA_PKCS1_PEM: &str = r#"
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsvbL9Jh5+CRiwD4rdixOmHcI/vpwUD0j8PDpDStTTICGpSqN
l7WlSMaFJn5Tc9aXgSftKDiBnPQzPEBBBVxnbJ8MgIY4YilBehoGBY035CPZ+C8P
8wZN7+VoRATUYPYzFdq/cdyCPqB+ZpnJjIRy5WXDlPO8fuGlx5+IvUwEeVIQAXsE
AkXg0Ky3PnB5gyDinCGTM3eM77SzFuWU5LptZjPa9Aap9/QoCrXkC+sbX7pOsWYe
U8JJErIfqBdBT4s/1tVqRmll2Fljr0O65O348zjqkZiQJvRpWvRtSQHK4VurUhHj
7sO6qmdbXD4P9I9Vrug+pAO1J0YDemKpcnO/WQIDAQABAoIBABDOwuru4w2eBTQ+
4oAPuzXwgATKan/urhBz379f4UvfCkY6z99+rM4/7sNlu9q2PbZglJJhdDLUcHdp
JXImcoQuD9OGR4dYjpC0Hvqof6ZKg68eZGYTooA0UG2K8pNErBmSWMaNyiGtmxFx
wg8TZWMMAqlblsln0dUEs6frmsP1+3AQ8BKyJFCV2TOipf/ja9TcNu9n6ukSwJml
mmDxJS3gTLWxfB0dQs1V+zgLDvqQqjLlgXRXQ8tIualvYY6+tHNJuxeVhyevarGy
lQ1p7GqNFedKQpqMwaXrI/rMY8q75/C0ajKBO7TJZMPRnD5airTNiZ1VG9J+OQrh
Kshdyc0CgYEA92yozUCyY0ns8qs97ixZc3SuKMA6wcmxZEiLv64M64MdKoBM3wfm
wDQGQodg1T3H3Rzw1fZRbaJ4KweG7TKQuey5CY1j7uZyNVNMbGF12Z5HjJhvC88/
lIpB44aYgmOerqrQczX8KVak8kttw+DoQYGbEyubJ/LXfGu1NCnFZ7MCgYEAuSq0
LbRMneV9RVMG4z4Y7MrdXBM1C1NcyUdK5nOhUNlWDSlPKIltxznvHoBT6XsYDYb+
mwPc6Hm6ui75RBhPMlsmoqIeriumnT1Cbr9nk2VZ0+nEKUN6QuG3qH+j8flnh0vc
39wIJs8I2DuYr5EaiUlIaTLWDrKphk3uOzLyNsMCgYEAhuhyaef63HR0hCSm0fTQ
mUlnpMSbxQpKdRmxSUSHuup0vrXSNFHEmcxEFYZnYB4dmgyrrJ5v682IpD2objEC
BL50bibv9FUmtLjElNvXPF83OAvtkIziaAWyw3KiOYZEAY0Vt5wZ8BhUO+Cw6vr4
6K7YdW1zXiblI+w+k0CraE0CgYAZEF25PgmM6e5t/tIU2mf3TXJvLy5j7RHHMP5D
eW1hizmpqGjNnOSeLgpe/5HcLcxQsHAwPXKeiTOsVgVpoTy/HTV6mCU9AC2aZRtj
8Eat3e8tzxu9ViPrf7Ajf7uKWm8YEj3Ak4EK98VDt7VwNlz4LlI94yK0dJyb0Fqp
6rh8jwKBgQCRq5Ot6bClmTPzQo1T52BGtHZBhVGqFc/76J0knZHL/Qper6TG5IP9
L4yOiMqxV7mUGWsDBEAi/sisVSLCZvsdWUFvJ4Bp9YBOSWyZlRK59gsOGzS6Qjw7
fCW7RLfTr0dg2eU3oUTI4B8SHULOhGjSjQ4KCGnbbdIUW2NlFdDkVQ==
-----END RSA PRIVATE KEY-----
"#;

    const RSA_PKCS8_PEM: &str = r#"
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQChw1TJMP2aYJnY
0wG4ElBAXVyFkQvgsx7Sh7yQjbs/WlSE7VOBOJIwKGhVWJk9vJpRWYl6WhiQn/ui
msd06YPkZhvoIotiESyQI7RRpv4YHWj5n8Gomwphj28ttLx3u7AiUWq9uK7mIsFT
Cf6YzUIYQf6FlQu+mYDObtSOtZWmSW69NtZWi2YyXNHPcooPnol8Y0OOd+V6XZrK
Qq8hGfj/7B6HjGbNUH02sKSWC7H7pn+BglNNpX0Znrx+oeEVH4pycYarolixVC0p
N7aK/v+jWiSc3U3Nz6lWALVuzsl2hOC10ie0kVNgheh4bP78YoglKiLHMVO/CRo6
IzjXeuWTAgMBAAECggEAGarj5jS22OshHk2FBU8qmrv1tV/pkZL6fg95tTo4Dvpn
VNxPlr6CO8/9liVD0478sZHSha6MHU61X/zNT1jKS9CD9xacJUhyWMDBmP81bGAm
Sw21beqEAC0BSDBYg2strJRcqpQGdI/pOyLn2hkftreqCko3Hdw/mwHtCmP3xfW6
QrmmSOQVq7hKSVCRSs6Do+SW+BLJLb/7ZoU4V8g8nakGh9oXmVKl5CDn/w9f+NSc
VUatPt2+7GMCnUKmQ9qodcuz/EINkimmZY1L2e9WhF9ETm/l292j9Vo2bU7KNoBB
E+9Cn+wMh23mmacSmY7S9SDBkQgVKmRMAyoFxTPmAQKBgQDXwXZLyhYDrtBMOKED
IgFeXMSQj5JZZ10suXYd3nX7iapiNimm5Febe/b4UinhwTzne6WanSvs92vPR5xN
XbJOcep4+YLFt30ZyAb8tyekkdC13rbKNraFWV1+wBs6yT3lfal5JF7Ko7TezYuG
E+nJdrzndLeV8o0yZy8zxT9FAQKBgQC/76rBFpqxBlHCVLLjPEwKvbvsgtRIrqfg
TeKUPS+QHMezYnrQkOiODyUA0/Xs4NBrDI7XuA6tjG0ZLPJWbjckNcvdka0bFQmN
jXXqnTwBsEcFlUFdXVt3EmuIn0K++EBemLndFhn0Wscwn7AO6cQWTA+qy+xuP0Pj
5gGo30hGkwKBgDk3kQugWB456fuMuQZ/qiVALNC5gnI7OzZ1KKHbMSa353uMKZec
zq7pPSG1iG3aNTCeVdie/dsl8m1R7F2ID5VGGIxkfw24D3Ea3t9+IwE9uj/BBHCz
+ct7W5QVliMM42FM5fi+cHUE3R6JHAs+lK1c09P93AHkBRXsz1PHZ3QBAoGAbWgD
MG9fHBtbDWfUVH0xZ0oBze5BbXDJVq1uw0shSodtOg6frTV8qkVttUwdObpocyzE
W6iaDUkngxtAxA2tNuHHZHQ+dVqHiH2jQmoAI4JE6aTLjpnBol0ImOcXV94Qaxup
jqGjh8sbEddktwt/b6pJn/T/v1QmsciRF563BysCgYB7t1HngCHE6zCGQdxDDp5A
Vb9rJaarKKy5TIX0svK4iGxmoD/qCf9o5LwKwoQLPf4K2F8fhEZZGes+62M5HzmZ
FCKYluqG2/M/gs/AE9K+btrpuIbZZB5Prris+THkBBxHTt49WFxwkVK+CbQxg0VC
32K3vJkhe2O33oHoyzQRfw==
-----END PRIVATE KEY-----
"#;

    const P256_SEC1_PEM: &str = r#"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIP37GKC//8GKtvmYmf62bpDsD8vlhlxLZ1PNbTICsvo9oAoGCCqGSM49
AwEHoUQDQgAEoCwAV5jHuPli5xYkmgQiGsa+MsZLXXmqrUR5Wu0S5Xgsm5lv/wy3
JSUC8mADyuZZsVyaFkSgSGkyyJfwSvVLNg==
-----END EC PRIVATE KEY-----
"#;

    #[test]
    fn original_key_formats_work_with_tls_provider() {
        let provider = aws_lc_rs::default_provider();
        for (pem, scheme) in [
            (RSA_PKCS1_PEM, SignatureScheme::RSA_PSS_SHA256),
            (RSA_PKCS8_PEM, SignatureScheme::RSA_PSS_SHA256),
            (P256_SEC1_PEM, SignatureScheme::ECDSA_NISTP256_SHA256),
        ] {
            let key = load_pem_fixture(pem.as_bytes()).unwrap();
            match pem {
                RSA_PKCS1_PEM => assert!(matches!(&key, PrivateKeyDer::Pkcs1(_))),
                RSA_PKCS8_PEM => assert!(matches!(&key, PrivateKeyDer::Pkcs8(_))),
                P256_SEC1_PEM => assert!(matches!(&key, PrivateKeyDer::Sec1(_))),
                _ => unreachable!(),
            }
            let signing_key = provider.key_provider.load_private_key(key).unwrap();
            let signer = signing_key.choose_scheme(&[scheme]).unwrap();
            assert!(
                !signer
                    .sign(b"TLS key loading regression test")
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn missing_and_malformed_keys_fail_and_other_pem_blocks_are_skipped() {
        let certificate = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n";
        for pem in [
            "",
            "not PEM",
            certificate,
            "-----BEGIN PRIVATE KEY-----\ninvalid base64!\n-----END PRIVATE KEY-----\n",
        ] {
            assert!(load_pem_fixture(pem.as_bytes()).is_err());
        }
        let bundle = format!("{certificate}{RSA_PKCS1_PEM}{P256_SEC1_PEM}");
        assert!(matches!(
            load_pem_fixture(bundle.as_bytes()).unwrap(),
            PrivateKeyDer::Pkcs1(_)
        ));
    }

    /// Checks that CLI parsing rejects invalid limits before starting the proxy.
    #[test]
    fn max_in_flight_requests_validates_semaphore_limit() {
        for count in [
            0,
            1,
            tokio::sync::Semaphore::MAX_PERMITS,
            tokio::sync::Semaphore::MAX_PERMITS + 1,
        ] {
            let result = Cli::try_parse_from([
                "attested-tls-proxy",
                "client",
                "localhost:443",
                "--max-in-flight-requests",
                &count.to_string(),
            ]);
            if (1..=tokio::sync::Semaphore::MAX_PERMITS).contains(&count) {
                let CliCommand::Client {
                    max_in_flight_requests,
                    ..
                } = result.unwrap().command
                else {
                    panic!("expected client command");
                };
                assert_eq!(max_in_flight_requests.get(), count);
            } else {
                assert_eq!(
                    result.unwrap_err().kind(),
                    clap::error::ErrorKind::ValueValidation
                );
            }
        }
    }
}
