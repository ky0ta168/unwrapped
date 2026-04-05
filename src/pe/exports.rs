use std::collections::HashMap;

use super::{PeFile, read_u16, read_u32, rva_to_file_offset};
use crate::render::*;

pub struct ExportFunction {
    pub eat_offset: usize,
    pub ordinal: u32,
    pub name: Option<String>,
    pub rva: u32,
    pub forwarder: Option<String>,
}

pub struct ExportTable {
    pub offset: usize,
    pub export_flags: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name_rva: u32,
    pub dll_name: String,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub eat_rva: u32,
    pub name_ptr_rva: u32,
    pub name_ord_rva: u32,
    pub functions: Vec<ExportFunction>,
}

impl PeFile {
    pub fn export_table(&self) -> Option<ExportTable> {
        let (_, dirs) = self.data_directories();
        let export_dir = &dirs[0];
        if export_dir.virtual_address == 0 {
            return None;
        }

        let (_, sections) = self.section_headers();
        let d = &self.data;

        let dir_offset = rva_to_file_offset(export_dir.virtual_address, &sections)?;
        if dir_offset + 40 > d.len() {
            return None;
        }

        let export_flags = read_u32(d, dir_offset);
        let time_date_stamp = read_u32(d, dir_offset + 4);
        let major_version = read_u16(d, dir_offset + 8);
        let minor_version = read_u16(d, dir_offset + 10);
        let name_rva = read_u32(d, dir_offset + 12);
        let base = read_u32(d, dir_offset + 16);
        let number_of_functions = read_u32(d, dir_offset + 20);
        let number_of_names = read_u32(d, dir_offset + 24);
        let eat_rva = read_u32(d, dir_offset + 28);
        let name_ptr_rva = read_u32(d, dir_offset + 32);
        let name_ord_rva = read_u32(d, dir_offset + 36);

        let dll_name = rva_to_file_offset(name_rva, &sections)
            .map(|o| super::read_cstring(d, o))
            .unwrap_or_default();

        let eat_base = rva_to_file_offset(eat_rva, &sections)?;

        let mut name_map: HashMap<usize, String> = HashMap::new();
        if number_of_names > 0
            && let (Some(name_ptr_base), Some(name_ord_base)) = (
                rva_to_file_offset(name_ptr_rva, &sections),
                rva_to_file_offset(name_ord_rva, &sections),
            )
        {
            for i in 0..number_of_names as usize {
                let name_ptr = read_u32(d, name_ptr_base + i * 4);
                let name_ord = read_u16(d, name_ord_base + i * 2) as usize;
                if let Some(name_off) = rva_to_file_offset(name_ptr, &sections) {
                    name_map.insert(name_ord, super::read_cstring(d, name_off));
                }
            }
        }

        let export_dir_start = export_dir.virtual_address;
        let export_dir_end = export_dir_start + export_dir.size;

        let mut functions = Vec::new();
        for idx in 0..number_of_functions as usize {
            let eat_offset = eat_base + idx * 4;
            if eat_offset + 4 > d.len() {
                break;
            }
            let rva = read_u32(d, eat_offset);
            if rva == 0 {
                continue;
            }
            let forwarder = if rva >= export_dir_start && rva < export_dir_end {
                rva_to_file_offset(rva, &sections).map(|o| super::read_cstring(d, o))
            } else {
                None
            };
            functions.push(ExportFunction {
                eat_offset,
                ordinal: base + idx as u32,
                name: name_map.remove(&idx),
                rva,
                forwarder,
            });
        }

        if functions.is_empty() && dll_name.is_empty() {
            None
        } else {
            Some(ExportTable {
                offset: dir_offset,
                export_flags,
                time_date_stamp,
                major_version,
                minor_version,
                name_rva,
                dll_name,
                base,
                number_of_functions,
                number_of_names,
                eat_rva,
                name_ptr_rva,
                name_ord_rva,
                functions,
            })
        }
    }
}

fn digit_count(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    (n.ilog10() + 1) as usize
}

pub fn dump_export_table(exp: &ExportTable, is_last: bool) {
    let connector = if is_last { "└─ " } else { "├─ " };
    let pc = if is_last { "   " } else { "│  " };

    print_section_header(connector, "Export Table");

    let has_funcs = !exp.functions.is_empty();
    let f = format!("{}├─ ", pc);
    let fl = format!("{}└─ ", pc);

    let last = if has_funcs { &f } else { &fl };

    print_field(
        Some(exp.offset),
        &f,
        "Characteristics",
        32,
        fmt_value(&format!("{:#010X}", exp.export_flags)),
    );
    print_field(
        Some(exp.offset + 4),
        &f,
        "TimeDateStamp",
        32,
        fmt_value(&format!("{:#010X}", exp.time_date_stamp)),
    );
    print_field(
        Some(exp.offset + 8),
        &f,
        "MajorVersion",
        32,
        fmt_num(&format!("{}", exp.major_version)),
    );
    print_field(
        Some(exp.offset + 10),
        &f,
        "MinorVersion",
        32,
        fmt_num(&format!("{}", exp.minor_version)),
    );
    print_field(
        Some(exp.offset + 12),
        &f,
        "Name",
        32,
        format!(
            "{} {}",
            fmt_addr(&format!("{:#010X}", exp.name_rva)),
            fmt_dim(&format!("({})", exp.dll_name))
        ),
    );
    print_field(
        Some(exp.offset + 16),
        &f,
        "Base",
        32,
        fmt_num(&format!("{}", exp.base)),
    );
    print_field(
        Some(exp.offset + 20),
        &f,
        "NumberOfFunctions",
        32,
        fmt_num(&format!("{}", exp.number_of_functions)),
    );
    print_field(
        Some(exp.offset + 24),
        &f,
        "NumberOfNames",
        32,
        fmt_num(&format!("{}", exp.number_of_names)),
    );
    print_field(
        Some(exp.offset + 28),
        &f,
        "AddressOfFunctions",
        32,
        fmt_addr(&format!("{:#010X}", exp.eat_rva)),
    );
    print_field(
        Some(exp.offset + 32),
        &f,
        "AddressOfNames",
        32,
        fmt_addr(&format!("{:#010X}", exp.name_ptr_rva)),
    );
    print_field(
        Some(exp.offset + 36),
        last,
        "AddressOfNameOrdinals",
        32,
        fmt_addr(&format!("{:#010X}", exp.name_ord_rva)),
    );

    if !has_funcs {
        return;
    }

    let n = exp.functions.len();
    let digit = digit_count(n);
    for (i, func) in exp.functions.iter().enumerate() {
        let is_last_fn = i + 1 >= n;
        let fn_conn = if is_last_fn {
            format!("{}└─ ", pc)
        } else {
            format!("{}├─ ", pc)
        };

        let name_str = match &func.name {
            Some(name) => fmt_func(name).to_string(),
            None => fmt_dim("(unnamed)").to_string(),
        };

        match &func.forwarder {
            Some(fwd) => println!(
                "{}{}{}{} {} {} {}",
                fmt_offset(func.eat_offset),
                fmt_tree(&fn_conn),
                fmt_dim(&format!("[{:0>width$}] ", func.ordinal, width = digit)),
                name_str,
                fmt_dim("→"),
                fmt_func(fwd),
                fmt_dim(&format!("(forwarder, RVA: {:#010X})", func.rva))
            ),
            None => println!(
                "{}{}{}{} {} {}",
                fmt_offset(func.eat_offset),
                fmt_tree(&fn_conn),
                fmt_dim(&format!("[{:0>width$}] ", func.ordinal, width = digit)),
                name_str,
                fmt_label("RVA:"),
                fmt_addr(&format!("{:#010X}", func.rva))
            ),
        }
    }
}
