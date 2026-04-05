use super::{PeFile, read_u16, read_u32, rva_to_file_offset};
use crate::render::*;

pub struct RelocationEntry {
    pub reloc_type: u8,
    pub offset: u16,
}

pub struct RelocationBlock {
    pub file_offset: usize,
    pub virtual_address: u32,
    pub size_of_block: u32,
    pub entries: Vec<(usize, RelocationEntry)>,
}

const RELOC_TYPE_NAMES: &[(u8, &str)] = &[
    (0, "IMAGE_REL_BASED_ABSOLUTE"),
    (1, "IMAGE_REL_BASED_HIGH"),
    (2, "IMAGE_REL_BASED_LOW"),
    (3, "IMAGE_REL_BASED_HIGHLOW"),
    (4, "IMAGE_REL_BASED_HIGHADJ"),
    (5, "IMAGE_REL_BASED_MIPS_JMPADDR"),
    (7, "IMAGE_REL_BASED_THUMB_MOV32"),
    (8, "IMAGE_REL_BASED_RISCV_LOW12S"),
    (9, "IMAGE_REL_BASED_IA64_IMM64"),
    (10, "IMAGE_REL_BASED_DIR64"),
    (11, "IMAGE_REL_BASED_HIGH3ADJ"),
];

fn reloc_type_name(t: u8) -> &'static str {
    RELOC_TYPE_NAMES
        .iter()
        .find(|&&(v, _)| v == t)
        .map(|&(_, n)| n)
        .unwrap_or("UNKNOWN")
}

impl PeFile {
    pub fn relocation_table(&self) -> Option<Vec<RelocationBlock>> {
        let (_, dirs) = self.data_directories();
        let reloc_dir = &dirs[5];
        if reloc_dir.virtual_address == 0 {
            return None;
        }

        let (_, sections) = self.section_headers();
        let d = &self.data;

        let mut base = rva_to_file_offset(reloc_dir.virtual_address, &sections)?;
        let end = base + reloc_dir.size as usize;
        let mut blocks = Vec::new();

        while base + 8 <= end.min(d.len()) {
            let virtual_address = read_u32(d, base);
            let size_of_block = read_u32(d, base + 4);

            if size_of_block < 8 || base + size_of_block as usize > d.len() {
                break;
            }

            let entry_count = (size_of_block as usize - 8) / 2;
            let mut entries = Vec::new();

            for i in 0..entry_count {
                let entry_off = base + 8 + i * 2;
                let raw = read_u16(d, entry_off);
                let reloc_type = (raw >> 12) as u8;
                let offset = raw & 0x0FFF;
                entries.push((entry_off, RelocationEntry { reloc_type, offset }));
            }

            blocks.push(RelocationBlock {
                file_offset: base,
                virtual_address,
                size_of_block,
                entries,
            });

            base += size_of_block as usize;
        }

        if blocks.is_empty() {
            None
        } else {
            Some(blocks)
        }
    }
}

pub fn dump_relocation_table(blocks: &[RelocationBlock], is_last: bool, expand: bool) {
    let total_entries: usize = blocks.iter().map(|b| b.entries.len()).sum();
    let connector = if is_last { "└─ " } else { "├─ " };
    let pc = if is_last { "   " } else { "│  " };

    let hint = if !expand {
        fmt_dim("  [use -r to expand entries]").to_string()
    } else {
        String::new()
    };
    println!(
        "              {}{} {}{}",
        fmt_tree(connector),
        fmt_section("Base Relocations"),
        fmt_dim(&format!(
            "({} blocks, {} entries)",
            blocks.len(),
            total_entries
        )),
        hint,
    );

    let n = blocks.len();
    for (i, block) in blocks.iter().enumerate() {
        let is_last_block = i + 1 >= n;
        let blk_conn = if is_last_block {
            format!("{}└─ ", pc)
        } else {
            format!("{}├─ ", pc)
        };
        let blk_pc = if is_last_block {
            format!("{}   ", pc)
        } else {
            format!("{}│  ", pc)
        };

        let non_abs = block
            .entries
            .iter()
            .filter(|(_, e)| e.reloc_type != 0)
            .count();
        let abs = block.entries.len() - non_abs;

        println!(
            "{}{}{} {} {}  {} {}",
            fmt_offset(block.file_offset),
            fmt_tree(&blk_conn),
            fmt_label("VirtualAddress:"),
            fmt_addr(&format!("{:#010X}", block.virtual_address)),
            fmt_dim(&format!("SizeOfBlock: {:#010X}", block.size_of_block)),
            fmt_dim(&format!("({} entries", block.entries.len())),
            fmt_dim(&format!(
                "{} absolute)",
                if abs > 0 {
                    format!("{} ", abs)
                } else {
                    String::new()
                }
            ))
        );

        if !expand {
            continue;
        }

        for (j, (entry_off, entry)) in block.entries.iter().enumerate() {
            if entry.reloc_type == 0 {
                continue;
            }
            let remaining_non_abs = block
                .entries
                .iter()
                .skip(j + 1)
                .filter(|(_, e)| e.reloc_type != 0)
                .count();
            let is_last_entry = remaining_non_abs == 0;

            let ent_conn = if is_last_entry {
                format!("{}└─ ", blk_pc)
            } else {
                format!("{}├─ ", blk_pc)
            };

            let type_name = reloc_type_name(entry.reloc_type);

            println!(
                "{}{}{} {}  {} {}",
                fmt_offset(*entry_off),
                fmt_tree(&ent_conn),
                fmt_label("Type:"),
                fmt_identifier(type_name),
                fmt_dim("Offset:"),
                fmt_addr(&format!("{:#05X}", entry.offset)),
            );
        }
    }
}
