mod color;
mod dump;
mod pe;

use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: unwraped <file>");
        std::process::exit(1);
    }

    let file_path = &args[1];

    let pe = match pe::PeFile::open(Path::new(file_path)) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let dos = pe.dos_header();
    let e_lfanew = dos.e_lfanew as usize;

    dump::dump_dos_header(&dos);
    println!();

    dump::dump_coff_header(&pe.coff_header(), e_lfanew + 4);
    println!();

    dump::dump_optional_header(&pe.optional_header(), e_lfanew + 4 + 20);
}
