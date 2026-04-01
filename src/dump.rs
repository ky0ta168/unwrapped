use crate::color::*;
use crate::pe;
use colored::Colorize;

const FLAG_INDENT: &str = "       ";
const KW: usize = 30;

fn print_flags(flags: &[(u16, &str)], value: u16) {
    for &(flag, name) in flags {
        if value & flag != 0 {
            println!(
                "{}{}  {}",
                FLAG_INDENT,
                fmt_flag_on("[x]"),
                fmt_flag_on(name)
            );
        } else {
            println!("{}{}  {}", FLAG_INDENT, fmt_gray("[ ]"), fmt_gray(name));
        }
    }
}

pub fn dump_dos_header(dos: &pe::DosHeader) {
    print_section("DOS Header");
    print_field(
        0x00,
        "e_magic:",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_magic)),
    );
    print_field(
        0x02,
        "e_cblp:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_cblp)),
    );
    print_field(0x04, "e_cp:", KW, fmt_value(&format!("0x{:04X}", dos.e_cp)));
    print_field(
        0x06,
        "e_crlc:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_crlc)),
    );
    print_field(
        0x08,
        "e_cparhdr:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_cparhdr)),
    );
    print_field(
        0x0A,
        "e_minalloc:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_minalloc)),
    );
    print_field(
        0x0C,
        "e_maxalloc:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_maxalloc)),
    );
    print_field(0x0E, "e_ss:", KW, fmt_addr(&format!("0x{:04X}", dos.e_ss)));
    print_field(0x10, "e_sp:", KW, fmt_addr(&format!("0x{:04X}", dos.e_sp)));
    print_field(
        0x12,
        "e_csum:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_csum)),
    );
    print_field(0x14, "e_ip:", KW, fmt_addr(&format!("0x{:04X}", dos.e_ip)));
    print_field(0x16, "e_cs:", KW, fmt_addr(&format!("0x{:04X}", dos.e_cs)));
    print_field(
        0x18,
        "e_lfarlc:",
        KW,
        fmt_addr(&format!("0x{:04X}", dos.e_lfarlc)),
    );
    print_field(
        0x1A,
        "e_ovno:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_ovno)),
    );
    {
        let anomaly = dos.e_res.iter().any(|&v| v != 0);
        for (i, &v) in dos.e_res.iter().enumerate() {
            let val_str = format!("0x{:04X}", v);
            let val = if anomaly {
                val_str.yellow()
            } else {
                fmt_gray(&val_str)
            };
            print_field(0x1C + i * 2, &format!("e_res[{}]:", i), KW, val);
        }
    }
    print_field(
        0x24,
        "e_oemid:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_oemid)),
    );
    print_field(
        0x26,
        "e_oeminfo:",
        KW,
        fmt_value(&format!("0x{:04X}", dos.e_oeminfo)),
    );
    {
        let anomaly = dos.e_res2.iter().any(|&v| v != 0);
        for (i, &v) in dos.e_res2.iter().enumerate() {
            let val_str = format!("0x{:04X}", v);
            let val = if anomaly {
                val_str.yellow()
            } else {
                fmt_gray(&val_str)
            };
            print_field(0x28 + i * 2, &format!("e_res2[{}]:", i), KW, val);
        }
    }
    print_field(
        0x3C,
        "e_lfanew:",
        KW,
        fmt_addr(&format!("0x{:08X}", dos.e_lfanew)),
    );
}

pub fn dump_coff_header(coff: &pe::CoffHeader, base: usize) {
    let machine_name = pe::MACHINES
        .iter()
        .find(|&&(v, _)| v == coff.machine)
        .map(|&(_, n)| n)
        .unwrap_or("UNKNOWN");

    print_section("COFF File Header");
    print_field(
        base,
        "Machine:",
        KW,
        fmt_value(&format!("{} ({:#06X})", machine_name, coff.machine)),
    );
    print_field(
        base + 2,
        "NumberOfSections:",
        KW,
        fmt_value(&format!("{}", coff.number_of_sections)),
    );
    print_field(
        base + 4,
        "TimeDateStamp:",
        KW,
        fmt_value(&format!("{:#010X}", coff.time_date_stamp)),
    );
    print_field(
        base + 8,
        "PointerToSymbolTable:",
        KW,
        fmt_addr(&format!("{:#010X}", coff.pointer_to_symbol_table)),
    );
    print_field(
        base + 12,
        "NumberOfSymbols:",
        KW,
        fmt_value(&format!("{}", coff.number_of_symbols)),
    );
    print_field(
        base + 16,
        "SizeOfOptionalHeader:",
        KW,
        fmt_value(&format!("{:#06X}", coff.size_of_optional_header)),
    );
    print_field(
        base + 18,
        "Characteristics:",
        KW,
        fmt_value(&format!("{:#06X}", coff.characteristics)),
    );
    print_flags(pe::CHARACTERISTICS_FLAGS, coff.characteristics);
}

pub fn dump_optional_header(opt: &pe::OptionalHeader, base: usize) {
    let is_pe32plus = opt.magic == 0x020B;
    let magic_label = match opt.magic {
        0x010B => "PE32",
        0x020B => "PE32+ (64-bit)",
        0x0107 => "ROM",
        _ => "Unknown",
    };
    let subsystem_name = pe::SUBSYSTEMS
        .iter()
        .find(|&&(v, _)| v == opt.subsystem)
        .map(|&(_, n)| n)
        .unwrap_or("UNKNOWN");

    let (image_base_off, common_off) = if is_pe32plus { (24, 32) } else { (28, 32) };
    let subsystem_off = base + 68;

    print_section("Optional Header");
    print_field(
        base,
        "Magic:",
        KW,
        fmt_value(&format!("{} ({:#06X})", magic_label, opt.magic)),
    );
    print_field(
        base + 2,
        "MajorLinkerVersion:",
        KW,
        fmt_value(&format!("{}", opt.major_linker_version)),
    );
    print_field(
        base + 3,
        "MinorLinkerVersion:",
        KW,
        fmt_value(&format!("{}", opt.minor_linker_version)),
    );
    print_field(
        base + 4,
        "SizeOfCode:",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_code)),
    );
    print_field(
        base + 8,
        "SizeOfInitializedData:",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_initialized_data)),
    );
    print_field(
        base + 12,
        "SizeOfUninitializedData:",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_uninitialized_data)),
    );
    print_field(
        base + 16,
        "AddressOfEntryPoint:",
        KW,
        fmt_addr(&format!("{:#010X}", opt.address_of_entry_point)),
    );
    print_field(
        base + 20,
        "BaseOfCode:",
        KW,
        fmt_addr(&format!("{:#010X}", opt.base_of_code)),
    );
    if let Some(bod) = opt.base_of_data {
        print_field(
            base + 24,
            "BaseOfData:",
            KW,
            fmt_addr(&format!("{:#010X}", bod)),
        );
    }
    print_field(
        base + image_base_off,
        "ImageBase:",
        KW,
        fmt_addr(&format!("{:#018X}", opt.image_base)),
    );
    print_field(
        base + common_off,
        "SectionAlignment:",
        KW,
        fmt_value(&format!("{:#010X}", opt.section_alignment)),
    );
    print_field(
        base + common_off + 4,
        "FileAlignment:",
        KW,
        fmt_value(&format!("{:#010X}", opt.file_alignment)),
    );
    print_field(
        base + common_off + 8,
        "MajorOperatingSystemVersion:",
        KW,
        fmt_value(&format!("{}", opt.major_os_version)),
    );
    print_field(
        base + common_off + 10,
        "MinorOperatingSystemVersion:",
        KW,
        fmt_value(&format!("{}", opt.minor_os_version)),
    );
    print_field(
        base + common_off + 12,
        "MajorImageVersion:",
        KW,
        fmt_value(&format!("{}", opt.major_image_version)),
    );
    print_field(
        base + common_off + 14,
        "MinorImageVersion:",
        KW,
        fmt_value(&format!("{}", opt.minor_image_version)),
    );
    print_field(
        base + common_off + 16,
        "MajorSubsystemVersion:",
        KW,
        fmt_value(&format!("{}", opt.major_subsystem_version)),
    );
    print_field(
        base + common_off + 18,
        "MinorSubsystemVersion:",
        KW,
        fmt_value(&format!("{}", opt.minor_subsystem_version)),
    );
    print_field(
        base + common_off + 20,
        "Win32VersionValue:",
        KW,
        fmt_value(&format!("{:#010X}", opt.win32_version_value)),
    );
    print_field(
        base + common_off + 24,
        "SizeOfImage:",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_image)),
    );
    print_field(
        base + common_off + 28,
        "SizeOfHeaders:",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_headers)),
    );
    print_field(
        base + common_off + 32,
        "CheckSum:",
        KW,
        fmt_value(&format!("{:#010X}", opt.check_sum)),
    );
    print_field(
        subsystem_off,
        "Subsystem:",
        KW,
        fmt_value(&format!("{} ({:#06X})", subsystem_name, opt.subsystem)),
    );
    print_field(
        subsystem_off + 2,
        "DllCharacteristics:",
        KW,
        fmt_value(&format!("{:#06X}", opt.dll_characteristics)),
    );
    print_flags(pe::DLL_CHARACTERISTICS_FLAGS, opt.dll_characteristics);
}
