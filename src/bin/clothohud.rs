use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Body, Method, Request, Response, StatusCode},
    rustls, HttpContext, HttpHandler, Proxy, RequestOrResponse,
};

use clap::Parser;
use clotho::AWSCredential;
use rustls_pemfile as pemfile;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct ClothoHandler {
    config_path: PathBuf,
}

fn build_forbidden<'a>(msg: String) -> Response<Body> {
    return Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(msg))
        .expect("Failed to create response");
}

/// A proxy that will listen to CONNECT requests and parse and validate SigV4 signatures based on a
/// Config
#[derive(Parser, Debug)]
#[command(version, about="Clotho standalone proxy, based on hudsucker proxy.", long_about = None)]
struct CliArgs {
    /// Location of Clotho config file
    #[clap(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Location of Private Key
    #[clap(long)]
    private_key: PathBuf,

    /// Location of Certificate
    #[clap(long)]
    certificate: PathBuf,

    /// Listening IP Address
    #[clap(long)]
    ipaddr: String,

    /// Listening Port
    #[clap(long)]
    port: u16,
}

#[hudsucker::async_trait::async_trait]
impl HttpHandler for ClothoHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            return RequestOrResponse::Request(req);
        }

        let Some(authz) = req.headers().get("authorization") else {
            return hudsucker::RequestOrResponse::Response(build_forbidden(
                "Missing Authorization Header".to_string(),
            ));
        };

        let authz = match authz.to_str() {
            Ok(authz) => authz,
            Err(e) => {
                return hudsucker::RequestOrResponse::Response(build_forbidden(e.to_string()))
            }
        };
        let aws_cred = match AWSCredential::new_from_http_authz(authz) {
            Ok(aws_cred) => aws_cred,
            Err(e) => {
                return hudsucker::RequestOrResponse::Response(build_forbidden(e.to_string()));
            }
        };

        let config = match aws_cred.read_config(self.config_path.clone()) {
            Ok(config) => config,
            Err(e) => {
                return hudsucker::RequestOrResponse::Response(build_forbidden(e.to_string()));
            }
        };
        if aws_cred.is_request_allowed(&config) {
            req.into()
        } else {
            return hudsucker::RequestOrResponse::Response(build_forbidden(
                "Forbidden".to_string(),
            ));
        }
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        res
    }
}

fn read_file(path: PathBuf) -> io::Result<Vec<u8>> {
    fs::read(path)
}

#[tokio::main]
async fn main() {
    let args = CliArgs::parse();
    let private_key = read_file(args.private_key).expect("Failed reading private key");
    let certificate = read_file(args.certificate).expect("Failed reading certificate");
    let ipaddr = IpAddr::from_str(&args.ipaddr).expect("Could not parse IP Address");

    run(args.config, &private_key, &certificate, ipaddr, args.port).await;
}

async fn run(
    config: PathBuf,
    mut private_key_bytes: &[u8],
    mut ca_cert_bytes: &[u8],
    ipaddr: IpAddr,
    port: u16,
) {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new("debug"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed setting tracing");

    let private_key = rustls::PrivateKey(
        pemfile::pkcs8_private_keys(&mut private_key_bytes)
            .next()
            .unwrap()
            .expect("Failed to parse private key")
            .secret_pkcs8_der()
            .to_vec(),
    );
    let ca_cert = rustls::Certificate(
        pemfile::certs(&mut ca_cert_bytes)
            .next()
            .unwrap()
            .expect("Failed to parse CA certificate")
            .to_vec(),
    );

    let ca = RcgenAuthority::new(private_key, ca_cert, 1_000)
        .expect("Failed to create Certificate Authority");

    let proxy = Proxy::builder()
        .with_addr(SocketAddr::from((ipaddr, port)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(ClothoHandler {
            config_path: config,
        })
        .build();

    proxy.start(shutdown_signal()).await.unwrap();
}
