use super::{PeFile, read_u16, read_u32};
use crate::render::*;

const KW: usize = 32;
const NL_F: &str = "│  ├─ ";
const NL_FL: &str = "│  └─ ";
const NL_FLG: &str = "│     ├─ ";
const NL_FLGL: &str = "│     └─ ";
const NL_FLGA: &str = "│        ";

pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

pub const MACHINES: &[(u16, &str)] = &[
    (0x0000, "IMAGE_FILE_MACHINE_UNKNOWN"),
    (0x014C, "IMAGE_FILE_MACHINE_I386"),
    (0x0200, "IMAGE_FILE_MACHINE_IA64"),
    (0x8664, "IMAGE_FILE_MACHINE_AMD64"),
    (0xAA64, "IMAGE_FILE_MACHINE_ARM64"),
    (0x01C4, "IMAGE_FILE_MACHINE_ARMNT"),
];

pub const CHARACTERISTICS_FLAGS: &[(u32, &str)] = &[
    (0x0001, "IMAGE_FILE_RELOCS_STRIPPED"),
    (0x0002, "IMAGE_FILE_EXECUTABLE_IMAGE"),
    (0x0004, "IMAGE_FILE_LINE_NUMS_STRIPPED"),
    (0x0008, "IMAGE_FILE_LOCAL_SYMS_STRIPPED"),
    (0x0010, "IMAGE_FILE_AGGRESIVE_WS_TRIM"),
    (0x0020, "IMAGE_FILE_LARGE_ADDRESS_AWARE"),
    (0x0080, "IMAGE_FILE_BYTES_REVERSED_LO"),
    (0x0100, "IMAGE_FILE_32BIT_MACHINE"),
    (0x0200, "IMAGE_FILE_DEBUG_STRIPPED"),
    (0x0400, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "IMAGE_FILE_NET_RUN_FROM_SWAP"),
    (0x1000, "IMAGE_FILE_SYSTEM"),
    (0x2000, "IMAGE_FILE_DLL"),
    (0x4000, "IMAGE_FILE_UP_SYSTEM_ONLY"),
    (0x8000, "IMAGE_FILE_BYTES_REVERSED_HI"),
];

impl PeFile {
    pub fn coff_header(&self) -> CoffHeader {
        let d = &self.data;
        let base = self.pe_offset() + 4;
        CoffHeader {
            machine: read_u16(d, base),
            number_of_sections: read_u16(d, base + 2),
            time_date_stamp: read_u32(d, base + 4),
            pointer_to_symbol_table: read_u32(d, base + 8),
            number_of_symbols: read_u32(d, base + 12),
            size_of_optional_header: read_u16(d, base + 16),
            characteristics: read_u16(d, base + 18),
        }
    }
}

pub fn dump_coff_header(coff: &CoffHeader, base: usize, all_flags: bool) {
    let machine_name = MACHINES
        .iter()
        .find(|&&(v, _)| v == coff.machine)
        .map(|&(_, n)| n)
        .unwrap_or("UNKNOWN");

    print_section_header("├─ ", "COFF File Header");

    print_field(
        Some(base),
        NL_F,
        "Machine",
        KW,
        fmt_symbol(machine_name, coff.machine),
    );
    print_field(
        Some(base + 2),
        NL_F,
        "NumberOfSections",
        KW,
        fmt_value(&format!("{}", coff.number_of_sections)),
    );
    print_field(
        Some(base + 4),
        NL_F,
        "TimeDateStamp",
        KW,
        fmt_value(&format!("{:#010X}", coff.time_date_stamp)),
    );
    print_field(
        Some(base + 8),
        NL_F,
        "PointerToSymbolTable",
        KW,
        fmt_addr(&format!("{:#010X}", coff.pointer_to_symbol_table)),
    );
    print_field(
        Some(base + 12),
        NL_F,
        "NumberOfSymbols",
        KW,
        fmt_value(&format!("{}", coff.number_of_symbols)),
    );
    print_field(
        Some(base + 16),
        NL_F,
        "SizeOfOptionalHeader",
        KW,
        fmt_value(&format!("{:#06X}", coff.size_of_optional_header)),
    );
    print_field(
        Some(base + 18),
        NL_FL,
        "Characteristics",
        KW,
        fmt_value(&format!("{:#06X}", coff.characteristics)),
    );
    print_flags(
        CHARACTERISTICS_FLAGS,
        coff.characteristics as u32,
        NL_FLG,
        NL_FLGL,
        NL_FLGA,
        all_flags,
    );
}
