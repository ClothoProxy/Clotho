use clotho::AWSCredential;
use std::path::PathBuf;

use clap::Parser;

/// Parse and validate a `Sigv4` signature based on a config
#[derive(Parser, Debug)]
#[command(author="costasko", version, about="A clotho command line example", long_about = None)]
struct CliArgs {
    /// Config file location
    #[clap(short, long)]
    config: PathBuf,

    /// Credential value from Sigv4
    #[clap(long)]
    credential: String,
}

fn main() {
    let args = CliArgs::parse();

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

    let allowed = aws_cred.is_request_allowed(&config);
    println!(
        "The request is allowed: {allowed}. Request has Account: {0}, Service: {1}, Region: {2}",
        aws_cred.account_id, aws_cred.service, aws_cred.region
    );
}
