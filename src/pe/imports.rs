use super::{PeFile, read_u16, read_u32, read_u64, rva_to_file_offset};
use crate::render::*;

pub struct ImportFunction {
    pub thunk_offset: usize,
    pub hint: Option<u16>,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

pub struct ImportDescriptor {
    pub offset: usize,
    pub dll_name: String,
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
                                thunk_offset: thunk_off,
                                hint: None,
                                name: None,
                                ordinal: Some((entry & 0xFFFF) as u16),
                            });
                        } else if let Some(ibn_off) =
                            rva_to_file_offset((entry & 0xFFFF_FFFF) as u32, &sections)
                            && ibn_off + 2 <= d.len()
                        {
                            functions.push(ImportFunction {
                                thunk_offset: thunk_off,
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
                                thunk_offset: thunk_off,
                                hint: None,
                                name: None,
                                ordinal: Some((entry & 0xFFFF) as u16),
                            });
                        } else if let Some(ibn_off) = rva_to_file_offset(entry, &sections)
                            && ibn_off + 2 <= d.len()
                        {
                            functions.push(ImportFunction {
                                thunk_offset: thunk_off,
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
            "{}{}{} {}",
            fmt_offset(desc.offset),
            fmt_tree(&dll_conn),
            fmt_identifier(&desc.dll_name),
            fmt_dim(&format!("({} functions)", desc.functions.len()))
        );

        let m = desc.functions.len();
        for (j, func) in desc.functions.iter().enumerate() {
            let is_last_fn = j + 1 >= m;
            let fn_conn = if is_last_fn {
                format!("{}└─ ", dll_pc)
            } else {
                format!("{}├─ ", dll_pc)
            };

            let entry_str = match func.ordinal {
                Some(ord) => format!("{}", fmt_dim(&format!("(ordinal 0x{:04X})", ord))),
                None => {
                    let hint = func
                        .hint
                        .map(|h| format!("{} ", fmt_dim(&format!("[0x{:04X}]", h))))
                        .unwrap_or_default();
                    let name = func.name.as_deref().unwrap_or("(unknown)");
                    format!("{}{}", hint, fmt_identifier(name))
                }
            };

            println!(
                "{}{}{}",
                fmt_offset(func.thunk_offset),
                fmt_tree(&fn_conn),
                entry_str
            );
        }
    }
}
