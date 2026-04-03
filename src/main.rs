mod color;
mod dump;
mod pe;

use crate::color::fmt_tree;
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

    println!("{} {}", "[FILE]".bright_green(), file_path.white());

    let dos = pe.dos_header();
    let e_lfanew = dos.e_lfanew as usize;

    let export = pe.export_table();
    let import = pe.import_table();
    let has_export = export.is_some();
    let has_import = import.is_some();

    dump::dump_dos_header(&dos);
    println!("              {}", fmt_tree("│"));

    dump::dump_coff_header(&pe.coff_header(), e_lfanew + 4, all_flags);
    println!("              {}", fmt_tree("│"));

    let (dd_base, dirs) = pe.data_directories();
    dump::dump_optional_header(
        &pe.optional_header(),
        e_lfanew + 4 + 20,
        dd_base,
        &dirs,
        all_flags,
        false, // Optional Header は最後ではない（Section Headers が後続）
    );
    println!("              {}", fmt_tree("│"));

    let (sh_base, sections) = pe.section_headers();
    dump::dump_section_headers(sh_base, &sections, all_flags, !has_export && !has_import);

    if let Some(exp) = export {
        println!("              {}", fmt_tree("│"));
        dump::dump_export_table(&exp, !has_import);
    }

    if let Some(descriptors) = import {
        println!("              {}", fmt_tree("│"));
        dump::dump_import_table(&descriptors);
    }
}
