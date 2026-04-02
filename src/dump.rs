use crate::color::*;
use crate::pe;
use colored::Colorize;

const KW: usize = 30;

// ── ツリープレフィックス定数 ──────────────────────────────────────────────────
// NL = 非末尾セクション（DOS Header, COFF: 親パイプ "│  " が継続）
// LL = 末尾セクション  （Optional Header: 親が "   " でパイプなし）
//  _F   = フィールド（末尾以外）
//  _FL  = フィールド（末尾）
//  _FLG  = 末尾フィールド配下のフラグ（末尾以外）
//  _FLGL = 末尾フィールド配下のフラグ（末尾）
//
// LL フラグの場合、親フィールドは "├─ "（末尾以外）なので継続パイプは "│  "
//  LL_FLG  = "   " (opt終了) + "│  " (フィールド継続) + "├─ "
//  LL_FLGL = "   " + "│  " + "└─ "

const NL_F: &str = "│  ├─ ";
const NL_FL: &str = "│  └─ ";
const NL_FLG: &str = "│     ├─ ";
const NL_FLGL: &str = "│     └─ ";
const NL_FLGA: &str = "│        "; // 注釈インデント（└─ をスペースに置換）

const LL_F: &str = "   ├─ ";
const LL_FLG: &str = "   │  ├─ ";
const LL_FLGL: &str = "   │  └─ ";
const LL_FLGA: &str = "   │     "; // 注釈インデント（└─ をスペースに置換）

/// フィールド配下のフラグを出力する。
/// all_flags: true なら全フラグ表示、false ならセット済みフラグのみ + "(N flags not set)" 注釈。
fn print_flags(
    flags: &[(u16, &str)],
    value: u16,
    pfx_mid: &str,
    pfx_last: &str,
    pfx_annotation: &str,
    all_flags: bool,
) {
    if all_flags {
        let n = flags.len();
        for (i, &(flag, name)) in flags.iter().enumerate() {
            let pfx = if i + 1 < n { pfx_mid } else { pfx_last };
            if value & flag != 0 {
                println!(
                    "          {}{} {}",
                    pfx.bright_black(),
                    "[x]".green(),
                    name.green()
                );
            } else {
                println!(
                    "          {}{} {}",
                    pfx.bright_black(),
                    "[ ]".bright_black(),
                    name.bright_black()
                );
            }
        }
    } else {
        let set: Vec<&str> = flags
            .iter()
            .filter(|&&(f, _)| value & f != 0)
            .map(|&(_, n)| n)
            .collect();
        let unset_count = flags.len() - set.len();

        if set.is_empty() {
            // フラグが1件もセットされていない場合: └─ コネクタで1行のみ表示
            println!(
                "          {}{}",
                pfx_last.bright_black(),
                "(no flags set)".bright_black()
            );
        } else {
            // セット済みフラグのみ表示
            let n = set.len();
            for (i, &name) in set.iter().enumerate() {
                let pfx = if i + 1 < n { pfx_mid } else { pfx_last };
                println!(
                    "          {}{} {}",
                    pfx.bright_black(),
                    "[x]".green(),
                    name.green()
                );
            }
            // 注釈行
            if unset_count > 0 {
                println!(
                    "          {}{}",
                    pfx_annotation.bright_black(),
                    format!("({} flags not set)", unset_count).bright_black()
                );
            }
        }
    }
}

pub fn dump_dos_header(dos: &pe::DosHeader) {
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
        fmt_addr(&format!("0x{:08X}", dos.e_lfanew)),
    );
}

pub fn dump_coff_header(coff: &pe::CoffHeader, base: usize, all_flags: bool) {
    let machine_name = pe::MACHINES
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
    // Characteristics は最後のフィールド; フラグが子要素
    print_field(
        Some(base + 18),
        NL_FL,
        "Characteristics",
        KW,
        fmt_value(&format!("{:#06X}", coff.characteristics)),
    );
    print_flags(
        pe::CHARACTERISTICS_FLAGS,
        coff.characteristics,
        NL_FLG,
        NL_FLGL,
        NL_FLGA,
        all_flags,
    );
}

pub fn dump_optional_header(
    opt: &pe::OptionalHeader,
    base: usize,
    dd_base: usize,
    dirs: &[pe::DataDirectory],
    all_flags: bool,
) {
    let is_pe32plus = opt.magic == 0x020B;
    let magic_label = match opt.magic {
        0x010B => "PE32",
        0x020B => "PE32+",
        _ => "Unknown",
    };
    let subsystem_name = pe::SUBSYSTEMS
        .iter()
        .find(|&&(v, _)| v == opt.subsystem)
        .map(|&(_, n)| n)
        .unwrap_or("UNKNOWN");

    // PE32: ImageBase は base+28、PE32+: ImageBase は base+24（BaseOfData なし）
    let image_base_off = if is_pe32plus { base + 24 } else { base + 28 };

    print_section_header("└─ ", "Optional Header");

    print_field(
        Some(base),
        LL_F,
        "Magic",
        KW,
        fmt_symbol(magic_label, opt.magic),
    );
    print_field(
        Some(base + 2),
        LL_F,
        "MajorLinkerVersion",
        KW,
        fmt_value(&format!("{}", opt.major_linker_version)),
    );
    print_field(
        Some(base + 3),
        LL_F,
        "MinorLinkerVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_linker_version)),
    );
    print_field(
        Some(base + 4),
        LL_F,
        "SizeOfCode",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_code)),
    );
    print_field(
        Some(base + 8),
        LL_F,
        "SizeOfInitializedData",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_initialized_data)),
    );
    print_field(
        Some(base + 12),
        LL_F,
        "SizeOfUninitializedData",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_uninitialized_data)),
    );
    print_field(
        Some(base + 16),
        LL_F,
        "AddressOfEntryPoint",
        KW,
        fmt_addr(&format!("{:#010X}", opt.address_of_entry_point)),
    );
    print_field(
        Some(base + 20),
        LL_F,
        "BaseOfCode",
        KW,
        fmt_addr(&format!("{:#010X}", opt.base_of_code)),
    );

    if let Some(bod) = opt.base_of_data {
        print_field(
            Some(base + 24),
            LL_F,
            "BaseOfData",
            KW,
            fmt_addr(&format!("{:#010X}", bod)),
        );
    }

    print_field(
        Some(image_base_off),
        LL_F,
        "ImageBase",
        KW,
        fmt_addr(&format!("{:#018X}", opt.image_base)),
    );
    print_field(
        Some(base + 32),
        LL_F,
        "SectionAlignment",
        KW,
        fmt_value(&format!("{:#010X}", opt.section_alignment)),
    );
    print_field(
        Some(base + 36),
        LL_F,
        "FileAlignment",
        KW,
        fmt_value(&format!("{:#010X}", opt.file_alignment)),
    );
    print_field(
        Some(base + 40),
        LL_F,
        "MajorOperatingSystemVersion",
        KW,
        fmt_value(&format!("{}", opt.major_os_version)),
    );
    print_field(
        Some(base + 42),
        LL_F,
        "MinorOperatingSystemVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_os_version)),
    );
    print_field(
        Some(base + 44),
        LL_F,
        "MajorImageVersion",
        KW,
        fmt_value(&format!("{}", opt.major_image_version)),
    );
    print_field(
        Some(base + 46),
        LL_F,
        "MinorImageVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_image_version)),
    );
    print_field(
        Some(base + 48),
        LL_F,
        "MajorSubsystemVersion",
        KW,
        fmt_value(&format!("{}", opt.major_subsystem_version)),
    );
    print_field(
        Some(base + 50),
        LL_F,
        "MinorSubsystemVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_subsystem_version)),
    );
    print_field(
        Some(base + 52),
        LL_F,
        "Win32VersionValue",
        KW,
        fmt_value(&format!("{:#010X}", opt.win32_version_value)),
    );
    print_field(
        Some(base + 56),
        LL_F,
        "SizeOfImage",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_image)),
    );
    print_field(
        Some(base + 60),
        LL_F,
        "SizeOfHeaders",
        KW,
        fmt_value(&format!("{:#010X}", opt.size_of_headers)),
    );
    print_field(
        Some(base + 64),
        LL_F,
        "CheckSum",
        KW,
        fmt_value(&format!("{:#010X}", opt.check_sum)),
    );
    print_field(
        Some(base + 68),
        LL_F,
        "Subsystem",
        KW,
        fmt_symbol(subsystem_name, opt.subsystem),
    );

    // DllCharacteristics は末尾フィールドではない（Data Directories が後続）
    print_field(
        Some(base + 70),
        LL_F,
        "DllCharacteristics",
        KW,
        fmt_value(&format!("{:#06X}", opt.dll_characteristics)),
    );
    print_flags(
        pe::DLL_CHARACTERISTICS_FLAGS,
        opt.dll_characteristics,
        LL_FLG,
        LL_FLGL,
        LL_FLGA,
        all_flags,
    );

    // Data Directories の前にセパレータを挿入
    print_separator("   │");

    // Data Directories は Optional Header の最後の子要素
    dump_data_directories(dd_base, dirs);
}

fn dump_data_directories(dd_base: usize, dirs: &[pe::DataDirectory]) {
    const NAME_W: usize = 25;

    let active = dirs
        .iter()
        .filter(|d| d.virtual_address != 0 || d.size != 0)
        .count();
    let empty = dirs.len() - active;

    // Optional Header の最後の子として "Data Directories" ヘッダを出力（"   └─ "）
    println!(
        "          {}{}  {}",
        "   └─ ".bright_black(),
        "Data Directories".blue().bold(),
        format!("({} active, {} empty)", active, empty).bright_black()
    );

    let n = dirs.len();
    for (i, dir) in dirs.iter().enumerate() {
        let name = pe::DATA_DIRECTORY_NAMES
            .get(i)
            .copied()
            .unwrap_or("Unknown");
        let is_last = i + 1 >= n;
        let is_empty = dir.virtual_address == 0 && dir.size == 0;

        let off = format!("[{:#06X}]  ", dd_base + i * 8);
        let conn = if is_last {
            "      └─"
        } else {
            "      ├─"
        };
        // "[NN] {name:<NAME_W$}" — インデックス + スペース + パディング済み名前
        let idx_and_name = format!("[{:02}] {:<NAME_W$}", i, name);
        let rva_hex = format!("{:#010X}", dir.virtual_address);
        let size_hex = format!("{:#010X}", dir.size);

        if is_empty {
            // 行全体を暗グレーで表示
            let row = format!(
                "{}{}RVA: {}  Size: {}",
                conn, idx_and_name, rva_hex, size_hex
            );
            println!("{}{}", off.bright_black(), row.bright_black());
        } else {
            // "[NN] " は暗グレー、名前は白、ラベルは暗シアン、値はシアン
            // 形式: {off}{conn}{[NN] }{name}RVA: {rva}  Size: {size}
            // idx_and_name[..5] = "[NN] "、idx_and_name[5..] = パディング済み名前
            println!(
                "{}{}{}{}{} {}  {} {}",
                off.bright_black(),
                conn.bright_black(),
                idx_and_name[..5].bright_black(),
                idx_and_name[5..].white(),
                "RVA:".cyan().dimmed(),
                fmt_addr(&rva_hex),
                "Size:".cyan().dimmed(),
                fmt_addr(&size_hex)
            );
        }
    }
}
