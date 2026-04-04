mod cli;
mod pe;
mod render;

use crate::render::fmt_tree;
use colored::Colorize;
use std::path::Path;

fn main() {
    let args = cli::Args::parse();
    let all_flags = args.all_flags;
    let file_path = &args.file_path;

    let pe = match pe::PeFile::open(Path::new(file_path)) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    println!(r#" _   _                                              _"#);
    println!(r#"| | | |_ ____      ___ __ __ _ _ __  _ __   ___  __| |"#);
    println!(r#"| | | | '_ \ \ /\ / / '__/ _` | '_ \| '_ \ / _ \/ _` |"#);
    println!(r#"| |_| | | | \ V  V /| | | (_| | |_) | |_) |  __/ (_| |"#);
    println!(r#" \___/|_| |_|\_/\_/ |_|  \__,_| .__/| .__/ \___|\__,_|"#);
    println!(r#"                              |_|   |_|"#);
    println!();

    println!("{} {}", "[FILE]".bright_green(), file_path.white());

    let dos = pe.dos_header();
    let e_lfanew = dos.e_lfanew as usize;

    let export = pe.export_table();
    let import = pe.import_table();
    let reloc = pe.relocation_table();
    let has_export = export.is_some();
    let has_import = import.is_some();
    let has_reloc = reloc.is_some();

    pe::dump_dos_header(&dos);
    println!("              {}", fmt_tree("│"));

    pe::dump_coff_header(&pe.coff_header(), e_lfanew + 4, all_flags);
    println!("              {}", fmt_tree("│"));

    let (dd_base, dirs) = pe.data_directories();
    pe::dump_optional_header(
        &pe.optional_header(),
        e_lfanew + 4 + 20,
        dd_base,
        &dirs,
        all_flags,
        false,
    );
    println!("              {}", fmt_tree("│"));

    let (sh_base, sections) = pe.section_headers();
    pe::dump_section_headers(
        sh_base,
        &sections,
        all_flags,
        !has_export && !has_import && !has_reloc,
    );

    if let Some(exp) = export {
        println!("              {}", fmt_tree("│"));
        pe::dump_export_table(&exp, !has_import && !has_reloc);
    }

    if let Some(descriptors) = import {
        println!("              {}", fmt_tree("│"));
        pe::dump_import_table(&descriptors, !has_reloc);
    }

    if let Some(blocks) = reloc {
        println!("              {}", fmt_tree("│"));
        pe::dump_relocation_table(&blocks);
    }
}
