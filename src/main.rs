mod cli;
mod pe;
mod render;

use crate::render::{fmt_dim, fmt_tree, fmt_value, print_field, print_section_header};
use colored::Colorize;
use pe::{
    debug::{CodeViewInfo, DebugDirectory},
    exports::ExportTable,
    imports::ImportDescriptor,
    relocations::RelocationBlock,
};
use std::path::Path;

enum ParsedTable {
    Export(ExportTable),
    Import(Vec<ImportDescriptor>),
    Reloc(Vec<RelocationBlock>),
    Debug(Vec<DebugDirectory>, Vec<Option<CodeViewInfo>>),
}

impl ParsedTable {
    fn file_offset(&self) -> usize {
        match self {
            ParsedTable::Export(e) => e.offset,
            ParsedTable::Import(ds) => ds.first().map(|d| d.offset).unwrap_or(usize::MAX),
            ParsedTable::Reloc(bs) => bs.first().map(|b| b.file_offset).unwrap_or(usize::MAX),
            ParsedTable::Debug(es, _) => es.first().map(|e| e.file_offset).unwrap_or(usize::MAX),
        }
    }
}

fn main() {
    let args = cli::Args::parse();
    let all_flags = args.all_flags;
    let expand_reloc = args.expand_reloc;
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

    let (sh_base, sections) = pe.section_headers();

    let mut tables: Vec<ParsedTable> = Vec::new();
    if let Some(exp) = pe.export_table() {
        tables.push(ParsedTable::Export(exp));
    }
    if let Some(imp) = pe.import_table() {
        tables.push(ParsedTable::Import(imp));
    }
    if let Some(reloc) = pe.relocation_table() {
        tables.push(ParsedTable::Reloc(reloc));
    }
    if let Some((entries, cv_infos)) = pe.debug_directory(&sections) {
        tables.push(ParsedTable::Debug(entries, cv_infos));
    }
    tables.sort_by_key(|t| t.file_offset());

    let has_tables = !tables.is_empty();

    pe::dump_dos_header(&dos);
    println!("              {}", fmt_tree("│"));

    // NT Headers
    print_section_header("├─ ", "NT Headers");
    print_field(
        Some(e_lfanew),
        "│  ├─ ",
        "Signature",
        32,
        format!("{} {}", fmt_value("PE"), fmt_dim("(0x00004550)")),
    );

    pe::dump_coff_header(&pe.coff_header(), e_lfanew + 4, all_flags);
    println!("              {}", fmt_tree("│  │"));

    let (dd_base, dirs) = pe.data_directories();
    pe::dump_optional_header(
        &pe.optional_header(),
        e_lfanew + 4 + 20,
        dd_base,
        &dirs,
        all_flags,
    );
    println!("              {}", fmt_tree("│"));

    pe::dump_section_headers(sh_base, &sections, all_flags, !has_tables);

    let n = tables.len();
    for (i, table) in tables.into_iter().enumerate() {
        let is_last = i + 1 >= n;
        println!("              {}", fmt_tree("│"));
        match table {
            ParsedTable::Export(exp) => pe::dump_export_table(&exp, is_last),
            ParsedTable::Import(ds) => pe::dump_import_table(&ds, is_last),
            ParsedTable::Reloc(bs) => pe::dump_relocation_table(&bs, is_last, expand_reloc),
            ParsedTable::Debug(es, cvs) => pe::dump_debug_directory(&es, &cvs, is_last),
        }
    }
}
