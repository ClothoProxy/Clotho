use clotho::AWSCredential;
use httparse::{Request as HTTPRequest, EMPTY_HEADER};
use icaparse::{Request as ICAPRequest, EMPTY_HEADER as ICAP_EMPTY_HEADER};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::error;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

const OPTIONS: &[u8] = r#"ICAP/1.0 200 OK
Methods: REQMOD
Service: Rust ICAP Server
Allow: 204
ISTag: RustICAPServer
Encapsulated: null-body=0

"#
.as_bytes();

const DENY: &[u8] = r#"ICAP/1.0 200 OK
ISTag: RustICAPServer
Encapsulated: res-hdr=0, null-body=24

HTTP/1.1 403 Forbidden";

"#
.as_bytes();

const ALLOW: &[u8] = r#"ICAP/1.0 204 No Content

"#
.as_bytes();

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:1344").await?;
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new("debug"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed setting tracing");

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut temp_buf = [0; 1024]; // Buffer, we don't expect more than 1024 bytes

            loop {
                match socket.read(&mut temp_buf).await {
                    Ok(0) => break, // End of stream
                    Ok(n) => buf.extend_from_slice(&temp_buf[..n]),
                    Err(_) => return, // Handle read error
                };
                let mut icap_headers = [ICAP_EMPTY_HEADER; 16];
                let mut icap_request = ICAPRequest::new(&mut icap_headers);

                // We parse the ICAP request first
                match icap_request.parse(&buf) {
                    Ok(icaparse::Status::Complete(_)) => {
                        if icap_request.method == Some("OPTIONS") {
                            let _ = socket.write_all(OPTIONS).await;
                            break;
                        }

                        let Some(icap_encap) = icap_request.encapsulated_sections else {
                            error!("Expected encapsulated sections found none");
                            let _ = socket.write_all(DENY).await;
                            break;
                        };
                        let Some(icap_parsed_http) =
                            icap_encap.get(&icaparse::SectionType::RequestHeader)
                        else {
                            error!("Expected request headers inside the encapsulated sections");
                            let _ = socket.write_all(DENY).await;
                            break;
                        };

                        // We start parsing the HTTP Request
                        let mut http_headers = [EMPTY_HEADER; 16];
                        let mut http_request = HTTPRequest::new(&mut http_headers);

                        match http_request.parse(icap_parsed_http) {
                            Ok(httparse::Status::Complete(_)) => {
                                let Some(authz_header) = http_request
                                    .headers
                                    .iter()
                                    .find(|&header| {
                                        header.name.eq_ignore_ascii_case("Authorization")
                                    })
                                    .and_then(|header| {
                                        String::from_utf8(header.value.to_vec()).ok()
                                    })
                                else {
                                    let _ = socket.write_all(DENY).await;
                                    break;
                                };
                                let aws_cred =
                                    match AWSCredential::new_from_http_authz(&authz_header) {
                                        Ok(aws_cred) => aws_cred,
                                        Err(e) => {
                                            error!("{e:?}");
                                            break;
                                        }
                                    };

                                let file_path = PathBuf::from("./config.yaml");
                                let config = match aws_cred.read_config(file_path) {
                                    Ok(config) => config,
                                    Err(e) => {
                                        error!("Error {e:?}");
                                        let _ = socket.write_all(DENY).await;
                                        break;
                                    }
                                };

                                if aws_cred.is_request_allowed(&config) {
                                    let _ = socket.write_all(ALLOW).await;
                                    break;
                                } else {
                                    let _ = socket.write_all(DENY).await;
                                    break;
                                }
                            }

                            Ok(httparse::Status::Partial) => {
                                error!("We don't deal with partial HTTP requests");
                                let _ = socket.write_all(DENY).await;
                                break;
                            }
                            Err(e) => {
                                error!("Something went wrong parsing the encapsulated HTTP {e}");
                                let _ = socket.write_all(DENY).await;
                                break;
                            }
                        }
                    }
                    Ok(icaparse::Status::Partial) => {
                        error!("We don't deal with partial ICAP requests");
                        let _ = socket.write_all(DENY).await;
                        break;
                    }
                    Err(e) => {
                        error!("Something went wrong when parsing the ICAP request {e}");
                        let _ = socket.write_all(DENY).await;
                        break;
                    }
                }
            }
        });
    }
}
