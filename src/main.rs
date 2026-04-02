mod color;
mod dump;
mod pe;

use colored::Colorize;
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    let all_flags = args.iter().any(|a| a == "--all-flags");
    let positional: Vec<&String> = args
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with("--"))
        .collect();

    if positional.is_empty() {
        eprintln!("Usage: unwraped [--all-flags] <file>");
        std::process::exit(1);
    }

    let file_path = positional[0];

    let pe = match pe::PeFile::open(Path::new(file_path)) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    println!(r#" _   _                                        _"#);
    println!(r#"| | | |_ ____      ___ __ __ _ _ __   ___  __| |"#);
    println!(r#"| | | | '_ \ \ /\ / / '__/ _` | '_ \ / _ \/ _` |"#);
    println!(r#"| |_| | | | \ V  V /| | | (_| | |_) |  __/ (_| |"#);
    println!(r#" \___/|_| |_|\_/\_/ |_|  \__,_| .__/ \___|\__,_|"#);
    println!(r#"                              |_|"#);
    println!();

    println!("{} {}", "[FILE]".bright_yellow(), file_path.white());

    let dos = pe.dos_header();
    let e_lfanew = dos.e_lfanew as usize;

    dump::dump_dos_header(&dos);
    println!("          {}", "│".bright_black());

    dump::dump_coff_header(&pe.coff_header(), e_lfanew + 4, all_flags);
    println!("          {}", "│".bright_black());

    let (dd_base, dirs) = pe.data_directories();
    dump::dump_optional_header(
        &pe.optional_header(),
        e_lfanew + 4 + 20,
        dd_base,
        &dirs,
        all_flags,
    );
}
