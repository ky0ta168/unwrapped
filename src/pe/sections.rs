use super::{PeFile, read_u16, read_u32};
use crate::render::*;

const KW: usize = 29;

pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

pub const SECTION_CHARACTERISTICS_FLAGS: &[(u32, &str)] = &[
    (0x00000008, "IMAGE_SCN_TYPE_NO_PAD"),
    (0x00000020, "IMAGE_SCN_CNT_CODE"),
    (0x00000040, "IMAGE_SCN_CNT_INITIALIZED_DATA"),
    (0x00000080, "IMAGE_SCN_CNT_UNINITIALIZED_DATA"),
    (0x00000100, "IMAGE_SCN_LNK_OTHER"),
    (0x00000200, "IMAGE_SCN_LNK_INFO"),
    (0x00000800, "IMAGE_SCN_LNK_REMOVE"),
    (0x00001000, "IMAGE_SCN_LNK_COMDAT"),
    (0x00008000, "IMAGE_SCN_GPREL"),
    (0x00020000, "IMAGE_SCN_MEM_PURGEABLE"),
    (0x00040000, "IMAGE_SCN_MEM_16BIT"),
    (0x00080000, "IMAGE_SCN_MEM_LOCKED"),
    (0x00100000, "IMAGE_SCN_MEM_PRELOAD"),
    (0x01000000, "IMAGE_SCN_LNK_NRELOC_OVFL"),
    (0x02000000, "IMAGE_SCN_MEM_DISCARDABLE"),
    (0x04000000, "IMAGE_SCN_MEM_NOT_CACHED"),
    (0x08000000, "IMAGE_SCN_MEM_NOT_PAGED"),
    (0x10000000, "IMAGE_SCN_MEM_SHARED"),
    (0x20000000, "IMAGE_SCN_MEM_EXECUTE"),
    (0x40000000, "IMAGE_SCN_MEM_READ"),
    (0x80000000, "IMAGE_SCN_MEM_WRITE"),
];

impl PeFile {
    pub fn section_headers(&self) -> (usize, Vec<SectionHeader>) {
        let d = &self.data;
        let opt_base = self.pe_offset() + 4 + 20;
        let opt_size = self.coff_header().size_of_optional_header as usize;
        let sh_base = opt_base + opt_size;

        let count = self.coff_header().number_of_sections as usize;
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let off = sh_base + i * 40;
            let raw_name = &d[off..off + 8];
            let name = std::str::from_utf8(raw_name)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            sections.push(SectionHeader {
                name,
                virtual_size: read_u32(d, off + 8),
                virtual_address: read_u32(d, off + 12),
                size_of_raw_data: read_u32(d, off + 16),
                pointer_to_raw_data: read_u32(d, off + 20),
                pointer_to_relocations: read_u32(d, off + 24),
                pointer_to_linenumbers: read_u32(d, off + 28),
                number_of_relocations: read_u16(d, off + 32),
                number_of_linenumbers: read_u16(d, off + 34),
                characteristics: read_u32(d, off + 36),
            });
        }
        (sh_base, sections)
    }
}

pub fn dump_section_headers(
    sh_base: usize,
    sections: &[SectionHeader],
    all_flags: bool,
    is_last: bool,
) {
    let pc_top = if is_last { "   " } else { "│  " };
    let connector = if is_last { "└─ " } else { "├─ " };

    let n = sections.len();
    println!(
        "              {}{} {}",
        fmt_tree(connector),
        fmt_section("Section Headers"),
        fmt_dim(&format!("({} sections)", n))
    );

    for (i, sec) in sections.iter().enumerate() {
        let sec_base = sh_base + i * 40;
        let is_last_sec = i + 1 >= n;

        let sec_conn = if is_last_sec {
            format!("{}└─ ", pc_top)
        } else {
            format!("{}├─ ", pc_top)
        };
        let name_str = if sec.name.is_empty() {
            fmt_dim("(unnamed)").to_string()
        } else {
            fmt_section_name(&sec.name).to_string()
        };
        println!(
            "{}{}{}",
            fmt_offset(sec_base),
            fmt_tree(&sec_conn),
            name_str
        );

        let sec_pc = if is_last_sec {
            format!("{}   ", pc_top)
        } else {
            format!("{}│  ", pc_top)
        };
        let f_pfx = format!("{}├─ ", sec_pc);
        let fl_pfx = format!("{}└─ ", sec_pc);
        let char_cont = format!("{}   ", sec_pc);
        let flg_pfx = format!("{}├─ ", char_cont);
        let flgl_pfx = format!("{}└─ ", char_cont);
        let flga_pfx = format!("{}   ", char_cont);

        print_field(
            Some(sec_base + 8),
            &f_pfx,
            "VirtualSize",
            KW,
            fmt_value(&format!("{:#010X}", sec.virtual_size)),
        );
        print_field(
            Some(sec_base + 12),
            &f_pfx,
            "VirtualAddress",
            KW,
            fmt_addr(&format!("{:#010X}", sec.virtual_address)),
        );
        print_field(
            Some(sec_base + 16),
            &f_pfx,
            "SizeOfRawData",
            KW,
            fmt_value(&format!("{:#010X}", sec.size_of_raw_data)),
        );
        print_field(
            Some(sec_base + 20),
            &f_pfx,
            "PointerToRawData",
            KW,
            fmt_addr(&format!("{:#010X}", sec.pointer_to_raw_data)),
        );
        print_field(
            Some(sec_base + 24),
            &f_pfx,
            "PointerToRelocations",
            KW,
            fmt_addr(&format!("{:#010X}", sec.pointer_to_relocations)),
        );
        print_field(
            Some(sec_base + 28),
            &f_pfx,
            "PointerToLinenumbers",
            KW,
            fmt_addr(&format!("{:#010X}", sec.pointer_to_linenumbers)),
        );
        print_field(
            Some(sec_base + 32),
            &f_pfx,
            "NumberOfRelocations",
            KW,
            fmt_num(&format!("{}", sec.number_of_relocations)),
        );
        print_field(
            Some(sec_base + 34),
            &f_pfx,
            "NumberOfLinenumbers",
            KW,
            fmt_num(&format!("{}", sec.number_of_linenumbers)),
        );
        print_field(
            Some(sec_base + 36),
            &fl_pfx,
            "Characteristics",
            KW,
            fmt_value(&format!("{:#010X}", sec.characteristics)),
        );
        print_flags(
            SECTION_CHARACTERISTICS_FLAGS,
            sec.characteristics,
            &flg_pfx,
            &flgl_pfx,
            &flga_pfx,
            all_flags,
        );
    }
}
