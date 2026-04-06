use super::{PeFile, read_u16, read_u32};
use crate::render::*;

const KW: usize = 32;
const NL_F: &str = "│  ├─ ";
const NL_FL: &str = "│  └─ ";

pub struct DosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32,
}

impl PeFile {
    pub fn dos_header(&self) -> DosHeader {
        let d = &self.data;
        DosHeader {
            e_magic: read_u16(d, 0x00),
            e_cblp: read_u16(d, 0x02),
            e_cp: read_u16(d, 0x04),
            e_crlc: read_u16(d, 0x06),
            e_cparhdr: read_u16(d, 0x08),
            e_minalloc: read_u16(d, 0x0A),
            e_maxalloc: read_u16(d, 0x0C),
            e_ss: read_u16(d, 0x0E),
            e_sp: read_u16(d, 0x10),
            e_csum: read_u16(d, 0x12),
            e_ip: read_u16(d, 0x14),
            e_cs: read_u16(d, 0x16),
            e_lfarlc: read_u16(d, 0x18),
            e_ovno: read_u16(d, 0x1A),
            e_res: [
                read_u16(d, 0x1C),
                read_u16(d, 0x1E),
                read_u16(d, 0x20),
                read_u16(d, 0x22),
            ],
            e_oemid: read_u16(d, 0x24),
            e_oeminfo: read_u16(d, 0x26),
            e_res2: [
                read_u16(d, 0x28),
                read_u16(d, 0x2A),
                read_u16(d, 0x2C),
                read_u16(d, 0x2E),
                read_u16(d, 0x30),
                read_u16(d, 0x32),
                read_u16(d, 0x34),
                read_u16(d, 0x36),
                read_u16(d, 0x38),
                read_u16(d, 0x3A),
            ],
            e_lfanew: read_u32(d, 0x3C),
        }
    }
}

pub fn dump_dos_header(dos: &DosHeader) {
    print_section_header("├─ ", "DOS Header");

    print_field(
        Some(0x00),
        NL_F,
        "e_magic",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_magic)),
    );
    print_field(
        Some(0x02),
        NL_F,
        "e_cblp",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_cblp)),
    );
    print_field(
        Some(0x04),
        NL_F,
        "e_cp",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_cp)),
    );
    print_field(
        Some(0x06),
        NL_F,
        "e_crlc",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_crlc)),
    );
    print_field(
        Some(0x08),
        NL_F,
        "e_cparhdr",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_cparhdr)),
    );
    print_field(
        Some(0x0A),
        NL_F,
        "e_minalloc",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_minalloc)),
    );
    print_field(
        Some(0x0C),
        NL_F,
        "e_maxalloc",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_maxalloc)),
    );
    print_field(
        Some(0x0E),
        NL_F,
        "e_ss",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_ss)),
    );
    print_field(
        Some(0x10),
        NL_F,
        "e_sp",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_sp)),
    );
    print_field(
        Some(0x12),
        NL_F,
        "e_csum",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_csum)),
    );
    print_field(
        Some(0x14),
        NL_F,
        "e_ip",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_ip)),
    );
    print_field(
        Some(0x16),
        NL_F,
        "e_cs",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_cs)),
    );
    print_field(
        Some(0x18),
        NL_F,
        "e_lfarlc",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_lfarlc)),
    );
    print_field(
        Some(0x1A),
        NL_F,
        "e_ovno",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_ovno)),
    );

    if dos.e_res.iter().all(|&v| v == 0) {
        print_field(
            Some(0x1C),
            NL_F,
            "e_res[0..3]",
            KW,
            format!("{} {}", fmt_value("0x0000"), fmt_dim("(all zero)")),
        );
    } else {
        for (i, &v) in dos.e_res.iter().enumerate() {
            print_field(
                Some(0x1C + i * 2),
                NL_F,
                &format!("e_res[{}]", i),
                KW,
                fmt_value(&format!("0x{:04X}", v)),
            );
        }
    }

    print_field(
        Some(0x24),
        NL_F,
        "e_oemid",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_oemid)),
    );
    print_field(
        Some(0x26),
        NL_F,
        "e_oeminfo",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_oeminfo)),
    );

    if dos.e_res2.iter().all(|&v| v == 0) {
        print_field(
            Some(0x28),
            NL_F,
            "e_res2[0..9]",
            KW,
            format!("{} {}", fmt_value("0x0000"), fmt_dim("(all zero)")),
        );
    } else {
        for (i, &v) in dos.e_res2.iter().enumerate() {
            print_field(
                Some(0x28 + i * 2),
                NL_F,
                &format!("e_res2[{}]", i),
                KW,
                fmt_value(&format!("0x{:04X}", v)),
            );
        }
    }

    print_field(
        Some(0x3C),
        NL_FL,
        "e_lfanew",
        KW,
        format!(
            "{} {}",
            fmt_addr(&format!("0x{:08X}", dos.e_lfanew)),
            fmt_dim(&format!("→ NT Headers @{:#010X}", dos.e_lfanew))
        ),
    );
}
