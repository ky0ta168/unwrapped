use std::fs;
use std::path::Path;

pub struct PeFile {
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum PeError {
    Io(std::io::Error),
    TooSmall,
    InvalidMz,
    InvalidPe,
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeError::Io(e) => write!(f, "IO error: {}", e),
            PeError::TooSmall => write!(f, "File too small"),
            PeError::InvalidMz => write!(f, "Invalid MZ signature"),
            PeError::InvalidPe => write!(f, "Invalid PE signature"),
        }
    }
}

pub struct DosHeader {
    pub e_magic: u16, // MZ
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
    pub e_lfanew: u32, // PE ヘッダへのオフセット
}

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

pub const CHARACTERISTICS_FLAGS: &[(u16, &str)] = &[
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

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

impl PeFile {
    pub fn open(path: &Path) -> Result<Self, PeError> {
        let data = fs::read(path).map_err(PeError::Io)?;

        if data.len() < 0x40 {
            return Err(PeError::TooSmall);
        }

        if &data[0..2] != b"MZ" {
            return Err(PeError::InvalidMz);
        }

        let e_lfanew = read_u32(&data, 0x3C) as usize;

        if data.len() < e_lfanew + 4 {
            return Err(PeError::InvalidPe);
        }

        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(PeError::InvalidPe);
        }

        Ok(PeFile { data })
    }

    pub fn coff_header(&self) -> CoffHeader {
        let d = &self.data;
        let base = read_u32(d, 0x3C) as usize + 4; // PE\0\0 の直後
        CoffHeader {
            machine:                  read_u16(d, base),
            number_of_sections:       read_u16(d, base + 2),
            time_date_stamp:          read_u32(d, base + 4),
            pointer_to_symbol_table:  read_u32(d, base + 8),
            number_of_symbols:        read_u32(d, base + 12),
            size_of_optional_header:  read_u16(d, base + 16),
            characteristics:          read_u16(d, base + 18),
        }
    }

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
