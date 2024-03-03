use clotho::AWSCredential;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Parse and validate a SigV4 signature based on a config
fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new("debug"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed setting tracing");

    let aws_cred =
        match AWSCredential::new("AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request") {
            Ok(aws_cred) => aws_cred,
            Err(e) => {
                println!("{e}");
                std::process::exit(1);
            }
        };

    let file_path = PathBuf::from("config.yaml.example");
    let config = match aws_cred.read_config(file_path) {
        Ok(config) => config,
        Err(e) => {
            println!("Error {:?}", e);
            std::process::exit(1);
        }
    };

    let allowed = aws_cred.is_request_allowed(&config);
    println!(
        "The request is allowed: {allowed}. Request has Account: {0}, Service: {1}, Region: {2}",
        aws_cred.account_id, aws_cred.service, aws_cred.region
    );
}
