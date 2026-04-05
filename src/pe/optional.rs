use super::{PeFile, read_u16, read_u32, read_u64};
use crate::render::*;

const KW: usize = 32;

pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: Option<u32>,
    pub image_base: u64,
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
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
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

impl PeFile {
    pub fn optional_header(&self) -> OptionalHeader {
        let d = &self.data;
        let base = self.pe_offset() + 4 + 20;
        let magic = read_u16(d, base);
        let is_pe32plus = self.is_pe32plus();

        let (
            base_of_data,
            image_base,
            subsystem_off,
            dll_char_off,
            stack_reserve,
            stack_commit,
            heap_reserve,
            heap_commit,
            loader_flags_off,
            rva_sizes_off,
        ) = if is_pe32plus {
            (
                None,
                read_u64(d, base + 24),
                base + 68,
                base + 70,
                read_u64(d, base + 72),
                read_u64(d, base + 80),
                read_u64(d, base + 88),
                read_u64(d, base + 96),
                base + 104,
                base + 108,
            )
        } else {
            (
                Some(read_u32(d, base + 24)),
                read_u32(d, base + 28) as u64,
                base + 68,
                base + 70,
                read_u32(d, base + 72) as u64,
                read_u32(d, base + 76) as u64,
                read_u32(d, base + 80) as u64,
                read_u32(d, base + 84) as u64,
                base + 88,
                base + 92,
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
            size_of_stack_reserve: stack_reserve,
            size_of_stack_commit: stack_commit,
            size_of_heap_reserve: heap_reserve,
            size_of_heap_commit: heap_commit,
            loader_flags: read_u32(d, loader_flags_off),
            number_of_rva_and_sizes: read_u32(d, rva_sizes_off),
        }
    }

    pub fn data_directories(&self) -> (usize, Vec<DataDirectory>) {
        let d = &self.data;
        let opt_base = self.pe_offset() + 4 + 20;
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
}

pub fn dump_optional_header(
    opt: &OptionalHeader,
    base: usize,
    dd_base: usize,
    dirs: &[DataDirectory],
    all_flags: bool,
    is_last: bool,
) {
    let pc = if is_last { "   " } else { "│  " };
    let connector = if is_last { "└─ " } else { "├─ " };

    let f = format!("{}├─ ", pc);
    let flg = format!("{}│  ├─ ", pc);
    let flgl = format!("{}│  └─ ", pc);
    let flga = format!("{}│     ", pc);
    let sep = format!("{}│", pc);

    let is_pe32plus = opt.magic == 0x020B;
    let magic_label = match opt.magic {
        0x010B => "PE32",
        0x020B => "PE32+",
        _ => "Unknown",
    };
    let subsystem_name = SUBSYSTEMS
        .iter()
        .find(|&&(v, _)| v == opt.subsystem)
        .map(|&(_, n)| n)
        .unwrap_or("UNKNOWN");

    let image_base_off = if is_pe32plus { base + 24 } else { base + 28 };

    print_section_header(connector, "Optional Header");

    print_field(
        Some(base),
        &f,
        "Magic",
        KW,
        fmt_symbol(magic_label, opt.magic),
    );
    print_field(
        Some(base + 2),
        &f,
        "MajorLinkerVersion",
        KW,
        fmt_num(&format!("{}", opt.major_linker_version)),
    );
    print_field(
        Some(base + 3),
        &f,
        "MinorLinkerVersion",
        KW,
        fmt_num(&format!("{}", opt.minor_linker_version)),
    );
    print_field(
        Some(base + 4),
        &f,
        "SizeOfCode",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_code)),
    );
    print_field(
        Some(base + 8),
        &f,
        "SizeOfInitializedData",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_initialized_data)),
    );
    print_field(
        Some(base + 12),
        &f,
        "SizeOfUninitializedData",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_uninitialized_data)),
    );
    print_field(
        Some(base + 16),
        &f,
        "AddressOfEntryPoint",
        KW,
        fmt_addr(&format!("{:#010X}", opt.address_of_entry_point)),
    );
    print_field(
        Some(base + 20),
        &f,
        "BaseOfCode",
        KW,
        fmt_addr(&format!("{:#010X}", opt.base_of_code)),
    );

    if let Some(bod) = opt.base_of_data {
        print_field(
            Some(base + 24),
            &f,
            "BaseOfData",
            KW,
            fmt_addr(&format!("{:#010X}", bod)),
        );
    }

    print_field(
        Some(image_base_off),
        &f,
        "ImageBase",
        KW,
        fmt_addr(&format!("{:#018X}", opt.image_base)),
    );
    print_field(
        Some(base + 32),
        &f,
        "SectionAlignment",
        KW,
        fmt_value(&format!("{:#010X}", opt.section_alignment)),
    );
    print_field(
        Some(base + 36),
        &f,
        "FileAlignment",
        KW,
        fmt_value(&format!("{:#010X}", opt.file_alignment)),
    );
    print_field(
        Some(base + 40),
        &f,
        "MajorOperatingSystemVersion",
        KW,
        fmt_num(&format!("{}", opt.major_os_version)),
    );
    print_field(
        Some(base + 42),
        &f,
        "MinorOperatingSystemVersion",
        KW,
        fmt_num(&format!("{}", opt.minor_os_version)),
    );
    print_field(
        Some(base + 44),
        &f,
        "MajorImageVersion",
        KW,
        fmt_num(&format!("{}", opt.major_image_version)),
    );
    print_field(
        Some(base + 46),
        &f,
        "MinorImageVersion",
        KW,
        fmt_num(&format!("{}", opt.minor_image_version)),
    );
    print_field(
        Some(base + 48),
        &f,
        "MajorSubsystemVersion",
        KW,
        fmt_num(&format!("{}", opt.major_subsystem_version)),
    );
    print_field(
        Some(base + 50),
        &f,
        "MinorSubsystemVersion",
        KW,
        fmt_num(&format!("{}", opt.minor_subsystem_version)),
    );
    print_field(
        Some(base + 52),
        &f,
        "Win32VersionValue",
        KW,
        fmt_value(&format!("{:#010X}", opt.win32_version_value)),
    );
    print_field(
        Some(base + 56),
        &f,
        "SizeOfImage",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_image)),
    );
    print_field(
        Some(base + 60),
        &f,
        "SizeOfHeaders",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_headers)),
    );
    print_field(
        Some(base + 64),
        &f,
        "CheckSum",
        KW,
        fmt_value(&format!("{:#010X}", opt.check_sum)),
    );
    print_field(
        Some(base + 68),
        &f,
        "Subsystem",
        KW,
        fmt_symbol(subsystem_name, opt.subsystem),
    );

    print_field(
        Some(base + 70),
        &f,
        "DllCharacteristics",
        KW,
        fmt_value(&format!("{:#06X}", opt.dll_characteristics)),
    );
    print_flags(
        DLL_CHARACTERISTICS_FLAGS,
        opt.dll_characteristics as u32,
        &flg,
        &flgl,
        &flga,
        all_flags,
    );

    let (ssr_off, ssc_off, shr_off, shc_off, lf_off, nrs_off) = if is_pe32plus {
        (
            base + 72,
            base + 80,
            base + 88,
            base + 96,
            base + 104,
            base + 108,
        )
    } else {
        (
            base + 72,
            base + 76,
            base + 80,
            base + 84,
            base + 88,
            base + 92,
        )
    };

    let size_fmt = if is_pe32plus { 18 } else { 10 };
    let stack_reserve_str = format!("{:#0width$X}", opt.size_of_stack_reserve, width = size_fmt);
    let stack_commit_str = format!("{:#0width$X}", opt.size_of_stack_commit, width = size_fmt);
    let heap_reserve_str = format!("{:#0width$X}", opt.size_of_heap_reserve, width = size_fmt);
    let heap_commit_str = format!("{:#0width$X}", opt.size_of_heap_commit, width = size_fmt);

    print_field(
        Some(ssr_off),
        &f,
        "SizeOfStackReserve",
        KW,
        fmt_value(&stack_reserve_str),
    );
    print_field(
        Some(ssc_off),
        &f,
        "SizeOfStackCommit",
        KW,
        fmt_value(&stack_commit_str),
    );
    print_field(
        Some(shr_off),
        &f,
        "SizeOfHeapReserve",
        KW,
        fmt_value(&heap_reserve_str),
    );
    print_field(
        Some(shc_off),
        &f,
        "SizeOfHeapCommit",
        KW,
        fmt_value(&heap_commit_str),
    );
    print_field(
        Some(lf_off),
        &f,
        "LoaderFlags",
        KW,
        fmt_value(&format!("{:#010X}", opt.loader_flags)),
    );
    print_field(
        Some(nrs_off),
        &f,
        "NumberOfRvaAndSizes",
        KW,
        fmt_num(&format!("{}", opt.number_of_rva_and_sizes)),
    );

    print_separator(&sep);

    dump_data_directories(dd_base, dirs, pc);
}

fn dump_data_directories(dd_base: usize, dirs: &[DataDirectory], pc: &str) {
    const NAME_W: usize = 25;

    let active = dirs
        .iter()
        .filter(|d| d.virtual_address != 0 || d.size != 0)
        .count();
    let empty = dirs.len() - active;

    println!(
        "              {}{} {}",
        fmt_tree(&format!("{}└─ ", pc)),
        fmt_section("Data Directories"),
        fmt_dim(&format!("({} active, {} empty)", active, empty))
    );

    let conn_mid = format!("{}   ├─", pc);
    let conn_last = format!("{}   └─", pc);

    let n = dirs.len();
    for (i, dir) in dirs.iter().enumerate() {
        let name = DATA_DIRECTORY_NAMES.get(i).copied().unwrap_or("Unknown");
        let is_last = i + 1 >= n;
        let is_empty = dir.virtual_address == 0 && dir.size == 0;

        let conn = if is_last { &conn_last } else { &conn_mid };
        let idx_and_name = format!("[{:02}] {:<NAME_W$}", i, name);
        let rva_hex = format!("{:#010X}", dir.virtual_address);
        let size_hex = format!("{:#010X}", dir.size);

        if is_empty {
            let row = format!(
                "{} {}RVA: {}  Size: {}",
                conn, idx_and_name, rva_hex, size_hex
            );
            println!("{}{}", fmt_offset(dd_base + i * 8), fmt_dim(&row));
        } else {
            println!(
                "{}{} {}{}{} {}  {} {}",
                fmt_offset(dd_base + i * 8),
                fmt_tree(conn),
                fmt_field(&idx_and_name[..5]),
                fmt_field(&idx_and_name[5..]),
                fmt_label("RVA:"),
                fmt_addr(&rva_hex),
                fmt_label("Size:"),
                fmt_addr(&size_hex)
            );
        }
    }
}
