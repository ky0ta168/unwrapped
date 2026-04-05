use super::{PeFile, read_u16, read_u32, read_u64, rva_to_file_offset};
use crate::render::*;

pub struct ImportFunction {
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

pub struct ImportDescriptor {
    pub offset: usize,
    pub dll_name: String,
    pub original_first_thunk_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub functions: Vec<ImportFunction>,
}

impl PeFile {
    pub fn import_table(&self) -> Option<Vec<ImportDescriptor>> {
        let (_, dirs) = self.data_directories();
        let import_dir = &dirs[1];
        if import_dir.virtual_address == 0 {
            return None;
        }

        let (_, sections) = self.section_headers();
        let is_pe32plus = self.is_pe32plus();
        let d = &self.data;

        let import_base = rva_to_file_offset(import_dir.virtual_address, &sections)?;
        let mut descriptors = Vec::new();
        let mut i = 0;

        loop {
            let off = import_base + i * 20;
            if off + 20 > d.len() {
                break;
            }

            let original_first_thunk = read_u32(d, off);
            let time_date_stamp = read_u32(d, off + 4);
            let forwarder_chain = read_u32(d, off + 8);
            let name_rva = read_u32(d, off + 12);
            let first_thunk = read_u32(d, off + 16);

            if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
                break;
            }

            let dll_name = rva_to_file_offset(name_rva, &sections)
                .map(|o| super::read_cstring(d, o))
                .unwrap_or_else(|| "(unknown)".to_string());

            let thunk_rva = if original_first_thunk != 0 {
                original_first_thunk
            } else {
                first_thunk
            };

            let mut functions = Vec::new();
            if let Some(thunk_base) = rva_to_file_offset(thunk_rva, &sections) {
                let entry_size = if is_pe32plus { 8 } else { 4 };
                let mut j = 0;

                loop {
                    let thunk_off = thunk_base + j * entry_size;
                    if thunk_off + entry_size > d.len() {
                        break;
                    }

                    if is_pe32plus {
                        let entry = read_u64(d, thunk_off);
                        if entry == 0 {
                            break;
                        }
                        if entry & 0x8000_0000_0000_0000 != 0 {
                            functions.push(ImportFunction {
                                hint: None,
                                name: None,
                                ordinal: Some((entry & 0xFFFF) as u16),
                            });
                        } else if let Some(ibn_off) =
                            rva_to_file_offset((entry & 0xFFFF_FFFF) as u32, &sections)
                            && ibn_off + 2 <= d.len()
                        {
                            functions.push(ImportFunction {
                                hint: Some(read_u16(d, ibn_off)),
                                name: Some(super::read_cstring(d, ibn_off + 2)),
                                ordinal: None,
                            });
                        }
                    } else {
                        let entry = read_u32(d, thunk_off);
                        if entry == 0 {
                            break;
                        }
                        if entry & 0x8000_0000 != 0 {
                            functions.push(ImportFunction {
                                hint: None,
                                name: None,
                                ordinal: Some((entry & 0xFFFF) as u16),
                            });
                        } else if let Some(ibn_off) = rva_to_file_offset(entry, &sections)
                            && ibn_off + 2 <= d.len()
                        {
                            functions.push(ImportFunction {
                                hint: Some(read_u16(d, ibn_off)),
                                name: Some(super::read_cstring(d, ibn_off + 2)),
                                ordinal: None,
                            });
                        }
                    }
                    j += 1;
                }
            }

            descriptors.push(ImportDescriptor {
                offset: off,
                dll_name,
                original_first_thunk_rva: thunk_rva,
                time_date_stamp,
                forwarder_chain,
                functions,
            });
            i += 1;
        }

        if descriptors.is_empty() {
            None
        } else {
            Some(descriptors)
        }
    }
}

pub fn dump_import_table(descriptors: &[ImportDescriptor], is_last: bool) {
    let connector = if is_last { "└─ " } else { "├─ " };
    let pc = if is_last { "   " } else { "│  " };

    let n = descriptors.len();
    println!(
        "              {}{} {}",
        fmt_tree(connector),
        fmt_section("Import Table"),
        fmt_dim(&format!("({} DLLs)", n))
    );

    for (i, desc) in descriptors.iter().enumerate() {
        let is_last_dll = i + 1 >= n;
        let dll_conn = if is_last_dll {
            format!("{}└─ ", pc)
        } else {
            format!("{}├─ ", pc)
        };
        let dll_pc = if is_last_dll {
            format!("{}   ", pc)
        } else {
            format!("{}│  ", pc)
        };

        println!(
            "              {}{} {}",
            fmt_tree(&dll_conn),
            fmt_dll(&desc.dll_name),
            fmt_dim(&format!("({} functions)", desc.functions.len())),
        );

        // OriginalFirstThunk → INT
        let oft_conn = format!("{}├─ ", dll_pc);
        let oft_pc = format!("{}│  ", dll_pc);
        println!(
            "{}{}{} {} {} {}",
            fmt_offset(desc.offset),
            fmt_tree(&oft_conn),
            fmt_field("OriginalFirstThunk"),
            fmt_dim("→"),
            fmt_label("INT:"),
            fmt_addr(&format!("{:#010X}", desc.original_first_thunk_rva))
        );

        // IMAGE_IMPORT_BY_NAME entries
        let m = desc.functions.len();
        for (j, func) in desc.functions.iter().enumerate() {
            let is_last_fn = j + 1 >= m;
            let ibn_conn = if is_last_fn {
                format!("{}└─ ", oft_pc)
            } else {
                format!("{}├─ ", oft_pc)
            };
            let ibn_pc = if is_last_fn {
                format!("{}   ", oft_pc)
            } else {
                format!("{}│  ", oft_pc)
            };

            match func.ordinal {
                Some(ord) => {
                    println!(
                        "              {}{}",
                        fmt_tree(&ibn_conn),
                        fmt_dim(&format!("(ordinal 0x{:04X})", ord))
                    );
                }
                None => {
                    println!(
                        "              {}{}",
                        fmt_tree(&ibn_conn),
                        fmt_section_name("IMAGE_IMPORT_BY_NAME"),
                    );
                    let hint_str = func
                        .hint
                        .map(|h| format!("{:#06X}", h))
                        .unwrap_or_else(|| "(none)".to_string());
                    let name = func.name.as_deref().unwrap_or("(unknown)");
                    println!(
                        "              {}{}  {}",
                        fmt_tree(&format!("{}├─ ", ibn_pc)),
                        fmt_field("Hint"),
                        fmt_value(&hint_str),
                    );
                    println!(
                        "              {}{}  {}",
                        fmt_tree(&format!("{}└─ ", ibn_pc)),
                        fmt_field("Name"),
                        fmt_func(name),
                    );
                }
            }
        }

        // TimeDateStamp
        let tds_label = format!("{:<16}", "TimeDateStamp");
        let tds_value = match desc.time_date_stamp {
            0 => format!(
                "{} {}",
                fmt_value(&format!("0x{:08X}", 0u32)),
                fmt_dim("(not bound)")
            ),
            0xFFFF_FFFF => format!(
                "{} {}",
                fmt_value(&format!("0x{:08X}", 0xFFFF_FFFFu32)),
                fmt_dim("(bound)")
            ),
            v => format!("{}", fmt_value(&format!("0x{:08X}", v))),
        };
        println!(
            "{}{}{}  {}",
            fmt_offset(desc.offset + 4),
            fmt_tree(&format!("{}├─ ", dll_pc)),
            fmt_field(&tds_label),
            tds_value
        );

        // ForwarderChain
        let fc_label = format!("{:<16}", "ForwarderChain");
        let fc_value = match desc.forwarder_chain {
            0xFFFF_FFFF => format!(
                "{} {}",
                fmt_value(&format!("0x{:08X}", 0xFFFF_FFFFu32)),
                fmt_dim("(no forwarders)")
            ),
            0 => format!(
                "{} {}",
                fmt_value(&format!("0x{:08X}", 0u32)),
                fmt_dim("(no forwarders)")
            ),
            v => format!(
                "{} {}",
                fmt_value(&format!("0x{:08X}", v)),
                fmt_dim("(forwarder chain)")
            ),
        };
        println!(
            "{}{}{}  {}",
            fmt_offset(desc.offset + 8),
            fmt_tree(&format!("{}└─ ", dll_pc)),
            fmt_field(&fc_label),
            fc_value
        );
    }
}
