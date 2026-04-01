mod color;
mod pe;

use color::*;
use colored::Colorize;
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

    // --- Step 4: DOS Header パース ---
    let dos = pe.dos_header();

    print_section("DOS Header");
    println!("  {:<42} {}", fmt_key("Magic:"), fmt_addr(&format!("0x{:04X}", dos.e_magic)));
    println!(
        "  {:<42} {}",
        fmt_key("Bytes on last page (e_cblp):"),
        fmt_value(&format!("0x{:04X}", dos.e_cblp))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Pages in file (e_cp):"),
        fmt_value(&format!("0x{:04X}", dos.e_cp))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Relocations (e_crlc):"),
        fmt_value(&format!("0x{:04X}", dos.e_crlc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Size of header in paragraphs (e_cparhdr):"),
        fmt_value(&format!("0x{:04X}", dos.e_cparhdr))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Min extra paragraphs (e_minalloc):"),
        fmt_value(&format!("0x{:04X}", dos.e_minalloc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Max extra paragraphs (e_maxalloc):"),
        fmt_value(&format!("0x{:04X}", dos.e_maxalloc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial SS (e_ss):"),
        fmt_addr(&format!("0x{:04X}", dos.e_ss))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial SP (e_sp):"),
        fmt_addr(&format!("0x{:04X}", dos.e_sp))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Checksum (e_csum):"),
        fmt_value(&format!("0x{:04X}", dos.e_csum))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial IP (e_ip):"),
        fmt_addr(&format!("0x{:04X}", dos.e_ip))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial CS (e_cs):"),
        fmt_addr(&format!("0x{:04X}", dos.e_cs))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Reloc table offset (e_lfarlc):"),
        fmt_addr(&format!("0x{:04X}", dos.e_lfarlc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Overlay number (e_ovno):"),
        fmt_value(&format!("0x{:04X}", dos.e_ovno))
    );
    {
        let vals: Vec<String> = dos.e_res.iter().map(|v| format!("0x{:04X}", v)).collect();
        let joined = vals.join("  ");
        if dos.e_res.iter().any(|&v| v != 0) {
            println!("  {:<42} {}", fmt_key("Reserved (e_res):"), joined.yellow());
        } else {
            println!("  {:<42} {}", fmt_key("Reserved (e_res):"), fmt_gray(&joined));
        }
    }
    println!(
        "  {:<42} {}",
        fmt_key("OEM identifier (e_oemid):"),
        fmt_value(&format!("0x{:04X}", dos.e_oemid))
    );
    println!(
        "  {:<42} {}",
        fmt_key("OEM information (e_oeminfo):"),
        fmt_value(&format!("0x{:04X}", dos.e_oeminfo))
    );
    {
        let vals: Vec<String> = dos.e_res2.iter().map(|v| format!("0x{:04X}", v)).collect();
        let joined = vals.join("  ");
        if dos.e_res2.iter().any(|&v| v != 0) {
            println!("  {:<42} {}", fmt_key("Reserved (e_res2):"), joined.yellow());
        } else {
            println!("  {:<42} {}", fmt_key("Reserved (e_res2):"), fmt_gray(&joined));
        }
    }
    println!(
        "  {:<42} {}",
        fmt_key("Offset to PE Header (e_lfanew):"),
        fmt_addr(&format!("0x{:08X}", dos.e_lfanew))
    );
}
