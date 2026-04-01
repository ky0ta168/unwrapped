mod color;
mod pe;

use color::*;
use colored::Colorize;
use std::env;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: unwraped <file>");
        std::process::exit(1);
    }

    let file_path = &args[1];

    let pe = match pe::PeFile::open(Path::new(file_path)) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    // --- Step 4: DOS Header パース ---
    let dos = pe.dos_header();

    print_section("DOS Header");
    println!(
        "  {:<42} {}",
        fmt_key("Magic:"),
        fmt_addr(&format!("0x{:04X}", dos.e_magic))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Bytes on last page (e_cblp):"),
        fmt_value(&format!("0x{:04X}", dos.e_cblp))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Pages in file (e_cp):"),
        fmt_value(&format!("0x{:04X}", dos.e_cp))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Relocations (e_crlc):"),
        fmt_value(&format!("0x{:04X}", dos.e_crlc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Size of header in paragraphs (e_cparhdr):"),
        fmt_value(&format!("0x{:04X}", dos.e_cparhdr))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Min extra paragraphs (e_minalloc):"),
        fmt_value(&format!("0x{:04X}", dos.e_minalloc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Max extra paragraphs (e_maxalloc):"),
        fmt_value(&format!("0x{:04X}", dos.e_maxalloc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial SS (e_ss):"),
        fmt_addr(&format!("0x{:04X}", dos.e_ss))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial SP (e_sp):"),
        fmt_addr(&format!("0x{:04X}", dos.e_sp))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Checksum (e_csum):"),
        fmt_value(&format!("0x{:04X}", dos.e_csum))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial IP (e_ip):"),
        fmt_addr(&format!("0x{:04X}", dos.e_ip))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Initial CS (e_cs):"),
        fmt_addr(&format!("0x{:04X}", dos.e_cs))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Reloc table offset (e_lfarlc):"),
        fmt_addr(&format!("0x{:04X}", dos.e_lfarlc))
    );
    println!(
        "  {:<42} {}",
        fmt_key("Overlay number (e_ovno):"),
        fmt_value(&format!("0x{:04X}", dos.e_ovno))
    );
    {
        let anomaly = dos.e_res.iter().any(|&v| v != 0);
        for (i, &v) in dos.e_res.iter().enumerate() {
            let key = format!("Reserved (e_res[{}]):", i);
            let val_str = format!("0x{:04X}", v);
            let colored_val = if anomaly {
                val_str.yellow()
            } else {
                fmt_gray(&val_str)
            };
            println!("  {:<42} {}", fmt_key(&key), colored_val);
        }
    }
    println!(
        "  {:<42} {}",
        fmt_key("OEM identifier (e_oemid):"),
        fmt_value(&format!("0x{:04X}", dos.e_oemid))
    );
    println!(
        "  {:<42} {}",
        fmt_key("OEM information (e_oeminfo):"),
        fmt_value(&format!("0x{:04X}", dos.e_oeminfo))
    );
    {
        let anomaly = dos.e_res2.iter().any(|&v| v != 0);
        for (i, &v) in dos.e_res2.iter().enumerate() {
            let key = format!("Reserved (e_res2[{}]):", i);
            let val_str = format!("0x{:04X}", v);
            let colored_val = if anomaly {
                val_str.yellow()
            } else {
                fmt_gray(&val_str)
            };
            println!("  {:<42} {}", fmt_key(&key), colored_val);
        }
    }
    println!(
        "  {:<42} {}",
        fmt_key("Offset to PE Header (e_lfanew):"),
        fmt_addr(&format!("0x{:08X}", dos.e_lfanew))
    );

    println!();

    // --- Step 5: COFF File Header パース ---
    let coff = pe.coff_header();

    let machine_name = pe::MACHINES
        .iter()
        .find(|&&(v, _)| v == coff.machine)
        .map(|&(_, name)| name)
        .unwrap_or("UNKNOWN");

    print_section("COFF File Header");
    println!(
        "  {:<36} {}",
        fmt_key("Machine:"),
        fmt_value(&format!("{} ({:#06X})", machine_name, coff.machine))
    );
    println!(
        "  {:<36} {}",
        fmt_key("Number of Sections:"),
        fmt_value(&format!("{}", coff.number_of_sections))
    );
    println!(
        "  {:<36} {}",
        fmt_key("TimeDateStamp:"),
        fmt_value(&format!("{:#010X}", coff.time_date_stamp))
    );
    println!(
        "  {:<36} {}",
        fmt_key("PointerToSymbolTable:"),
        fmt_addr(&format!("{:#010X}", coff.pointer_to_symbol_table))
    );
    println!(
        "  {:<36} {}",
        fmt_key("NumberOfSymbols:"),
        fmt_value(&format!("{}", coff.number_of_symbols))
    );
    println!(
        "  {:<36} {}",
        fmt_key("SizeOfOptionalHeader:"),
        fmt_value(&format!("{:#06X}", coff.size_of_optional_header))
    );
    println!(
        "  {:<36} {}",
        fmt_key("Characteristics:"),
        fmt_value(&format!("{:#06X}", coff.characteristics))
    );
    for &(flag, name) in pe::CHARACTERISTICS_FLAGS {
        if coff.characteristics & flag != 0 {
            println!("    {}  {}", fmt_flag_on("[x]"), fmt_flag_on(name));
        } else {
            println!("    {}  {}", fmt_gray("[ ]"), fmt_gray(name));
        }
    }

    println!();

    // --- Step 6: Optional Header パース ---
    let opt = pe.optional_header();

    let magic_label = match opt.magic {
        0x010B => "PE32",
        0x020B => "PE32+ (64-bit)",
        0x0107 => "ROM",
        _ => "Unknown",
    };
    let subsystem_name = pe::SUBSYSTEMS
        .iter()
        .find(|&&(v, _)| v == opt.subsystem)
        .map(|&(_, name)| name)
        .unwrap_or("UNKNOWN");

    print_section("Optional Header");
    println!(
        "  {:<40} {}",
        fmt_key("Magic:"),
        fmt_value(&format!("{} ({:#06X})", magic_label, opt.magic))
    );
    println!(
        "  {:<40} {}",
        fmt_key("LinkerVersion:"),
        fmt_value(&format!(
            "{}.{}",
            opt.major_linker_version, opt.minor_linker_version
        ))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SizeOfCode:"),
        fmt_value(&format!("{:#010X}", opt.size_of_code))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SizeOfInitializedData:"),
        fmt_value(&format!("{:#010X}", opt.size_of_initialized_data))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SizeOfUninitializedData:"),
        fmt_value(&format!("{:#010X}", opt.size_of_uninitialized_data))
    );
    println!(
        "  {:<40} {}",
        fmt_key("AddressOfEntryPoint:"),
        fmt_addr(&format!("{:#010X}", opt.address_of_entry_point))
    );
    println!(
        "  {:<40} {}",
        fmt_key("BaseOfCode:"),
        fmt_addr(&format!("{:#010X}", opt.base_of_code))
    );
    if let Some(bod) = opt.base_of_data {
        println!(
            "  {:<40} {}",
            fmt_key("BaseOfData:"),
            fmt_addr(&format!("{:#010X}", bod))
        );
    }
    println!(
        "  {:<40} {}",
        fmt_key("ImageBase:"),
        fmt_addr(&format!("{:#018X}", opt.image_base))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SectionAlignment:"),
        fmt_value(&format!("{:#010X}", opt.section_alignment))
    );
    println!(
        "  {:<40} {}",
        fmt_key("FileAlignment:"),
        fmt_value(&format!("{:#010X}", opt.file_alignment))
    );
    println!(
        "  {:<40} {}",
        fmt_key("OperatingSystemVersion:"),
        fmt_value(&format!(
            "{}.{}",
            opt.major_os_version, opt.minor_os_version
        ))
    );
    println!(
        "  {:<40} {}",
        fmt_key("ImageVersion:"),
        fmt_value(&format!(
            "{}.{}",
            opt.major_image_version, opt.minor_image_version
        ))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SubsystemVersion:"),
        fmt_value(&format!(
            "{}.{}",
            opt.major_subsystem_version, opt.minor_subsystem_version
        ))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SizeOfImage:"),
        fmt_value(&format!("{:#010X}", opt.size_of_image))
    );
    println!(
        "  {:<40} {}",
        fmt_key("SizeOfHeaders:"),
        fmt_value(&format!("{:#010X}", opt.size_of_headers))
    );
    println!(
        "  {:<40} {}",
        fmt_key("CheckSum:"),
        fmt_value(&format!("{:#010X}", opt.check_sum))
    );
    println!(
        "  {:<40} {}",
        fmt_key("Subsystem:"),
        fmt_value(&format!("{} ({:#06X})", subsystem_name, opt.subsystem))
    );
    println!(
        "  {:<40} {}",
        fmt_key("DllCharacteristics:"),
        fmt_value(&format!("{:#06X}", opt.dll_characteristics))
    );
    for &(flag, name) in pe::DLL_CHARACTERISTICS_FLAGS {
        if opt.dll_characteristics & flag != 0 {
            println!("    {}  {}", fmt_flag_on("[x]"), fmt_flag_on(name));
        } else {
            println!("    {}  {}", fmt_gray("[ ]"), fmt_gray(name));
        }
    }
}
