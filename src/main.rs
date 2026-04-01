use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: unwraped <file>");
        std::process::exit(1);
    }

    let file_path = &args[1];
    println!("File: {}", file_path);
}
