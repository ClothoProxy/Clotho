use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};

fn main() {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs.log")
        .expect("Failed to open or create file");

    loop {
        let mut input = String::new();

        match handle.read_line(&mut input) {
            Ok(0) => break, // EOF reached or input closed
            Ok(_) => {
                println!("OK");

                file.write_all(input.as_bytes())
                    .expect("Failed to write to file");
            }
            Err(_error) => {
                println!("ERR");
                break;
            }
        }
    }
}
