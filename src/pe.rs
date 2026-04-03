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

pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>, // PE32 のみ
    pub image_base: u64,           // PE32=u32, PE32+=u64
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_os_version: u16,
    pub minor_os_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
}

pub const SUBSYSTEMS: &[(u16, &str)] = &[
    (0, "IMAGE_SUBSYSTEM_UNKNOWN"),
    (1, "IMAGE_SUBSYSTEM_NATIVE"),
    (2, "IMAGE_SUBSYSTEM_WINDOWS_GUI"),
    (3, "IMAGE_SUBSYSTEM_WINDOWS_CUI"),
    (5, "IMAGE_SUBSYSTEM_OS2_CUI"),
    (7, "IMAGE_SUBSYSTEM_POSIX_CUI"),
    (9, "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"),
    (10, "IMAGE_SUBSYSTEM_EFI_APPLICATION"),
    (11, "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"),
    (12, "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"),
    (13, "IMAGE_SUBSYSTEM_EFI_ROM"),
    (14, "IMAGE_SUBSYSTEM_XBOX"),
    (16, "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"),
];

pub const DLL_CHARACTERISTICS_FLAGS: &[(u32, &str)] = &[
    (0x0020, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA"),
    (0x0040, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"),
    (0x0080, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY"),
    (0x0100, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT"),
    (0x0200, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"),
    (0x0400, "IMAGE_DLLCHARACTERISTICS_NO_SEH"),
    (0x0800, "IMAGE_DLLCHARACTERISTICS_NO_BIND"),
    (0x1000, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER"),
    (0x2000, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER"),
    (0x4000, "IMAGE_DLLCHARACTERISTICS_GUARD_CF"),
    (0x8000, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"),
];

pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

pub const DATA_DIRECTORY_NAMES: &[&str] = &[
    "Export Table",
    "Import Table",
    "Resource Table",
    "Exception Table",
    "Certificate Table",
    "Base Relocation Table",
    "Debug",
    "Architecture",
    "Global Ptr",
    "TLS Table",
    "Load Config Table",
    "Bound Import",
    "IAT",
    "Delay Import Descriptor",
    "CLR Runtime Header",
    "Reserved",
];

pub struct SectionHeader {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
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

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

impl PeFile {
    /// PE署名のファイルオフセット（e_lfanew の値）
    fn pe_offset(&self) -> usize {
        read_u32(&self.data, 0x3C) as usize
    }

    /// Optional Header の magic 値が PE32+（0x020B）かどうか
    fn is_pe32plus(&self) -> bool {
        let opt_base = self.pe_offset() + 4 + 20;
        read_u16(&self.data, opt_base) == 0x020B
    }

    pub fn open(path: &Path) -> Result<Self, PeError> {
        let data = fs::read(path).map_err(PeError::Io)?;

        if data.len() < 0x40 {
            return Err(PeError::TooSmall);
        }

        if &data[0..2] != b"MZ" {
            return Err(PeError::InvalidMz);
        }

        let e_lfanew = read_u32(&data, 0x3C) as usize; // open() 内なので self がまだない

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
        let base = self.pe_offset() + 4; // PE\0\0 の直後
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

    pub fn optional_header(&self) -> OptionalHeader {
        let d = &self.data;
        // Optional Header は COFF Header (20 bytes) の直後
        let base = self.pe_offset() + 4 + 20;
        let magic = read_u16(d, base);
        let is_pe32plus = self.is_pe32plus();

        // PE32 と PE32+ でレイアウトが異なる部分を処理
        let (base_of_data, image_base, subsystem_off, dll_char_off) = if is_pe32plus {
            // PE32+: BaseOfData なし、ImageBase が u64 (base+24)
            (None, read_u64(d, base + 24), base + 68, base + 70)
        } else {
            // PE32: BaseOfData あり (base+24)、ImageBase が u32 (base+28)
            (
                Some(read_u32(d, base + 24)),
                read_u32(d, base + 28) as u64,
                base + 68,
                base + 70,
            )
        };

        OptionalHeader {
            magic,
            major_linker_version: d[base + 2],
            minor_linker_version: d[base + 3],
            size_of_code: read_u32(d, base + 4),
            size_of_initialized_data: read_u32(d, base + 8),
            size_of_uninitialized_data: read_u32(d, base + 12),
            address_of_entry_point: read_u32(d, base + 16),
            base_of_code: read_u32(d, base + 20),
            base_of_data,
            image_base,
            section_alignment: read_u32(d, base + 32),
            file_alignment: read_u32(d, base + 36),
            major_os_version: read_u16(d, base + 40),
            minor_os_version: read_u16(d, base + 42),
            major_image_version: read_u16(d, base + 44),
            minor_image_version: read_u16(d, base + 46),
            major_subsystem_version: read_u16(d, base + 48),
            minor_subsystem_version: read_u16(d, base + 50),
            win32_version_value: read_u32(d, base + 52),
            size_of_image: read_u32(d, base + 56),
            size_of_headers: read_u32(d, base + 60),
            check_sum: read_u32(d, base + 64),
            subsystem: read_u16(d, subsystem_off),
            dll_characteristics: read_u16(d, dll_char_off),
        }
    }

    pub fn data_directories(&self) -> (usize, Vec<DataDirectory>) {
        let d = &self.data;
        let opt_base = self.pe_offset() + 4 + 20;

        // Data Directory の開始オフセット
        // PE32:  opt_base + 96
        // PE32+: opt_base + 112
        let dd_base = if self.is_pe32plus() {
            opt_base + 112
        } else {
            opt_base + 96
        };

        let mut dirs = Vec::new();
        for i in 0..16 {
            let off = dd_base + i * 8;
            dirs.push(DataDirectory {
                virtual_address: read_u32(d, off),
                size: read_u32(d, off + 4),
            });
        }
        (dd_base, dirs)
    }

    pub fn section_headers(&self) -> (usize, Vec<SectionHeader>) {
        let d = &self.data;
        let opt_base = self.pe_offset() + 4 + 20;
        let opt_size = self.coff_header().size_of_optional_header as usize;
        // セクションヘッダは Optional Header の直後
        let sh_base = opt_base + opt_size;

        let count = self.coff_header().number_of_sections as usize;
        let mut sections = Vec::with_capacity(count);
        for i in 0..count {
            let off = sh_base + i * 40;
            // Name: 8バイト、ヌル終端のASCII文字列
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
                characteristics: read_u32(d, off + 36),
            });
        }
        (sh_base, sections)
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
