//use async_trait::async_trait;

use hudsucker::{
    certificate_authority::RcgenAuthority,
    hyper::{Body, Method, Request, Response, StatusCode},
    rustls,
    //rustls::Certificate,
    HttpContext,
    HttpHandler,
    Proxy,
    RequestOrResponse,
};

use clotho::AWSCredential;
use rustls_pemfile as pemfile;
use std::net::SocketAddr;
use std::path::PathBuf;

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler");
}

#[derive(Clone)]
struct ClothoHandler;

fn build_forbidden<'a>(msg: String) -> Response<Body> {
    return Response::builder()
        .status(StatusCode::FORBIDDEN)
        .body(Body::from(msg))
        .expect("Failed to create response");
}

#[async_trait::async_trait]
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

        let file_path = PathBuf::from("config.yaml.example");
        let config = match aws_cred.read_config(file_path) {
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let mut private_key_bytes: &[u8] = include_bytes!("ca/hudsucker.key");
    let mut ca_cert_bytes: &[u8] = include_bytes!("ca/hudsucker.cer");

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
        .with_addr(SocketAddr::from(([127, 0, 0, 1], 3000)))
        .with_rustls_client()
        .with_ca(ca)
        .with_http_handler(ClothoHandler)
        .build();

    proxy.start(shutdown_signal()).await.unwrap();
}
