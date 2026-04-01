mod color;
mod pe;

use color::*;
use colored::*;
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: unwraped <file>");
        std::process::exit(1);
    }

    let file_path = &args[1];

    // --- Step 3: PEファイル読み込み・バリデーション ---
    print_section("PE Validation");
    println!("  {}  {}", fmt_key("File:"), fmt_value(file_path));

    match pe::PeFile::open(Path::new(file_path)) {
        Ok(pe) => {
            println!("  {}  {}", fmt_key("MZ signature:"), "[OK]".green());
            let e_lfanew = u32::from_le_bytes(pe.data[0x3C..0x40].try_into().unwrap());
            println!(
                "  {}  {}",
                fmt_key("e_lfanew:"),
                fmt_addr(&format!("0x{:08X}", e_lfanew))
            );
            println!("  {}  {}", fmt_key("PE signature:"), "[OK]".green());
            println!(
                "  {}  {}",
                fmt_key("File size:"),
                fmt_value(&format!("{} bytes", pe.data.len()))
            );
            println!();
            println!("  {}", "Valid PE file.".green().bold());
        }
        Err(e) => {
            println!("  {}", format!("[ERROR] {}", e).red().bold());
        }
    }
}
