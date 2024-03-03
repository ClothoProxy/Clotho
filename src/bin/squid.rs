use clotho::AWSCredential;
use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

/// Parse and validate a `Sigv4` signature based on a config
#[derive(Parser, Debug)]
#[command(author="costaskou", version, about="A sigv4 command line", long_about = None)]
struct CliArgs {
    /// Config file location
    #[clap(short, long)]
    config: PathBuf,

    /// Credentials value from Sigv4
    #[clap(long)]
    credential: String,
}

fn main() {
    let args = CliArgs::parse();
    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new("debug"))
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("failed setting tracing");

    let aws_cred = match AWSCredential::new(&args.credential) {
        Ok(aws_cred) => aws_cred,
        Err(e) => {
            println!("{e:?}");
            std::process::exit(1);
        }
    };

    let file_path = args.config;
    let config = match aws_cred.read_config(file_path) {
        Ok(config) => config,
        Err(e) => {
            println!("Error {e:?}");
            std::process::exit(1);
        }
    };

    if aws_cred.is_request_allowed(&config) {
        println!("OK");
    } else {
        println!("ERR");
    }
}
