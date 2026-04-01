mod color;

use std::env;
use color::*;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: unwraped <file>");
        std::process::exit(1);
    }

    let file_path = &args[1];
    println!("File: {}", file_path);

    // --- Step 2: カラー表示・レイアウト確認 ---
    println!();
    print_section("DOS Header");
    println!("  {}  {}", fmt_key("Magic:"), fmt_value("MZ"));
    println!("  {}  {}", fmt_key("e_lfanew:"), fmt_addr("0x00000100"));

    println!();
    print_section("Import Table");
    println!("  DLL: {}", fmt_dll("kernel32.dll"));
    println!("  {}  Hint={}  Name={}", fmt_gray("[00]"), fmt_value("0x0001"), fmt_key("ExitProcess"));

    println!();
    print_section("Characteristics");
    println!("  {}  IMAGE_FILE_EXECUTABLE_IMAGE", fmt_flag_on("[x]"));
    println!("  {}  IMAGE_FILE_DLL", fmt_gray("[ ]"));

    println!();
    print_section("Section Entropy");
    println!("  {}  entropy=5.23  {}", fmt_key(".text "), fmt_entropy(5.23));
    println!("  {}  entropy=6.50  {}", fmt_key(".data "), fmt_entropy(6.50));
    println!("  {}  entropy=7.94  {}", fmt_key(".upx0 "), fmt_entropy(7.94));
}
