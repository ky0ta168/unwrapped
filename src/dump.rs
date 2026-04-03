use crate::color::*;
use crate::pe;

const KW: usize = 32;

// ── ツリープレフィックス定数（非末尾セクション用）────────────────────────────
// NL = 非末尾セクション（DOS Header, COFF: 親パイプ "│  " が継続）
//  _F   = フィールド（末尾以外）
//  _FL  = フィールド（末尾）
//  _FLG  = 末尾フィールド配下のフラグ（末尾以外）
//  _FLGL = 末尾フィールド配下のフラグ（末尾）
//  _FLGA = フラグ注釈インデント

const NL_F: &str = "│  ├─ ";
const NL_FL: &str = "│  └─ ";
const NL_FLG: &str = "│     ├─ ";
const NL_FLGL: &str = "│     └─ ";
const NL_FLGA: &str = "│        ";

/// 数値の桁数を取得する。
fn digit_count(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    (n.ilog10() + 1) as usize
}

/// フィールド配下のフラグを出力する。
/// all_flags: true なら全フラグ表示、false ならセット済みフラグのみ + "(N flags not set)" 注釈。
fn print_flags(
    flags: &[(u32, &str)],
    value: u32,
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
                println!("              {}{}", fmt_tree(pfx), fmt_flag_on(name, flag));
            } else {
                println!(
                    "              {}{}",
                    fmt_tree(pfx),
                    fmt_flag_off(name, flag)
                );
            }
        }
    } else {
        let set: Vec<(u32, &str)> = flags
            .iter()
            .filter(|&&(f, _)| value & f != 0)
            .map(|&(f, n)| (f, n))
            .collect();
        let unset_count = flags.len() - set.len();

        if set.is_empty() {
            // フラグが1件もセットされていない場合: └─ コネクタで1行のみ表示
            println!(
                "              {}{}",
                fmt_tree(pfx_last),
                fmt_dim("(no flags set)")
            );
        } else {
            // セット済みフラグのみ表示
            let n = set.len();
            for (i, &(flag, name)) in set.iter().enumerate() {
                let pfx = if i + 1 < n { pfx_mid } else { pfx_last };
                println!("              {}{}", fmt_tree(pfx), fmt_flag_on(name, flag));
            }
            // 注釈行
            if unset_count > 0 {
                println!(
                    "              {}{}",
                    fmt_tree(pfx_annotation),
                    fmt_dim(&format!("({} flags not set)", unset_count))
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
        coff.characteristics as u32,
        NL_FLG,
        NL_FLGL,
        NL_FLGA,
        all_flags,
    );
}

/// Optional Header とその子要素（Data Directories を含む）を出力する。
/// is_last: true なら末尾セクション（└─）、false なら非末尾（├─）。
pub fn dump_optional_header(
    opt: &pe::OptionalHeader,
    base: usize,
    dd_base: usize,
    dirs: &[pe::DataDirectory],
    all_flags: bool,
    is_last: bool,
) {
    // 親継続文字: 末尾なら "   "、非末尾なら "│  "
    let pc = if is_last { "   " } else { "│  " };
    let connector = if is_last { "└─ " } else { "├─ " };

    // Optional Header 配下のフィールドプレフィックス
    let f = format!("{}├─ ", pc); // フィールド（末尾以外）
    let flg = format!("{}│  ├─ ", pc); // DllCharacteristics フラグ（末尾以外）
    let flgl = format!("{}│  └─ ", pc); // DllCharacteristics フラグ（末尾）
    let flga = format!("{}│     ", pc); // フラグ注釈インデント
    let sep = format!("{}│", pc); // 内部セパレータ

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
        fmt_value(&format!("{}", opt.major_linker_version)),
    );
    print_field(
        Some(base + 3),
        &f,
        "MinorLinkerVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_linker_version)),
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
        fmt_value(&format!("{}", opt.major_os_version)),
    );
    print_field(
        Some(base + 42),
        &f,
        "MinorOperatingSystemVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_os_version)),
    );
    print_field(
        Some(base + 44),
        &f,
        "MajorImageVersion",
        KW,
        fmt_value(&format!("{}", opt.major_image_version)),
    );
    print_field(
        Some(base + 46),
        &f,
        "MinorImageVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_image_version)),
    );
    print_field(
        Some(base + 48),
        &f,
        "MajorSubsystemVersion",
        KW,
        fmt_value(&format!("{}", opt.major_subsystem_version)),
    );
    print_field(
        Some(base + 50),
        &f,
        "MinorSubsystemVersion",
        KW,
        fmt_value(&format!("{}", opt.minor_subsystem_version)),
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

    // DllCharacteristics は末尾フィールドではない（Data Directories が後続）
    print_field(
        Some(base + 70),
        &f,
        "DllCharacteristics",
        KW,
        fmt_value(&format!("{:#06X}", opt.dll_characteristics)),
    );
    print_flags(
        pe::DLL_CHARACTERISTICS_FLAGS,
        opt.dll_characteristics as u32,
        &flg,
        &flgl,
        &flga,
        all_flags,
    );

    // Data Directories の前にセパレータを挿入
    print_separator(&sep);

    // Data Directories は Optional Header の最後の子要素
    dump_data_directories(dd_base, dirs, pc);
}

/// Data Directories を出力する。
/// pc: 親継続文字（"   " または "│  "）
fn dump_data_directories(dd_base: usize, dirs: &[pe::DataDirectory], pc: &str) {
    const NAME_W: usize = 25;

    let active = dirs
        .iter()
        .filter(|d| d.virtual_address != 0 || d.size != 0)
        .count();
    let empty = dirs.len() - active;

    // Optional Header の最後の子として "Data Directories" ヘッダを出力
    println!(
        "              {}{} {}",
        fmt_tree(&format!("{}└─ ", pc)),
        fmt_section("Data Directories"),
        fmt_dim(&format!("({} active, {} empty)", active, empty))
    );

    // DD エントリのコネクタ（pc の直後に 3スペース + ├─/└─）
    let conn_mid = format!("{}   ├─", pc);
    let conn_last = format!("{}   └─", pc);

    let n = dirs.len();
    for (i, dir) in dirs.iter().enumerate() {
        let name = pe::DATA_DIRECTORY_NAMES
            .get(i)
            .copied()
            .unwrap_or("Unknown");
        let is_last = i + 1 >= n;
        let is_empty = dir.virtual_address == 0 && dir.size == 0;

        let conn = if is_last { &conn_last } else { &conn_mid };
        // "[NN] {name:<NAME_W$}" — インデックス + スペース + パディング済み名前
        let idx_and_name = format!("[{:02}] {:<NAME_W$}", i, name);
        let rva_hex = format!("{:#010X}", dir.virtual_address);
        let size_hex = format!("{:#010X}", dir.size);

        if is_empty {
            // 行全体を暗グレーで表示
            let row = format!(
                "{} {}RVA: {}  Size: {}",
                conn, idx_and_name, rva_hex, size_hex
            );
            println!("{}{}", fmt_offset(dd_base + i * 8), fmt_dim(&row));
        } else {
            // "[NN] " は暗グレー、名前は白、ラベルは水色dim、値はシアン
            // idx_and_name[..5] = " [NN] "、idx_and_name[5..] = パディング済み名前
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

pub fn dump_section_headers(
    sh_base: usize,
    sections: &[pe::SectionHeader],
    all_flags: bool,
    is_last: bool,
) {
    // 親継続文字: 末尾なら "   "、非末尾なら "│  "
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

        // セクション名行のコネクタ
        let sec_conn = if is_last_sec {
            format!("{}└─ ", pc_top)
        } else {
            format!("{}├─ ", pc_top)
        };
        let name_str = if sec.name.is_empty() {
            fmt_dim("(unnamed)").to_string()
        } else {
            fmt_identifier(&sec.name).to_string()
        };
        println!(
            "{}{}{}",
            fmt_offset(sec_base),
            fmt_tree(&sec_conn),
            name_str
        );

        // このセクションの子要素の親継続文字
        let sec_pc = if is_last_sec {
            format!("{}   ", pc_top)
        } else {
            format!("{}│  ", pc_top)
        };
        // フィールドプレフィックス
        let f_pfx = format!("{}├─ ", sec_pc);
        let fl_pfx = format!("{}└─ ", sec_pc);
        // Characteristics は └─ なので、フラグの親継続は sec_pc + "   "
        let char_cont = format!("{}   ", sec_pc);
        let flg_pfx = format!("{}├─ ", char_cont);
        let flgl_pfx = format!("{}└─ ", char_cont);
        let flga_pfx = format!("{}   ", char_cont);

        print_field(
            Some(sec_base + 8),
            &f_pfx,
            "VirtualSize",
            KW - 3,
            fmt_value(&format!("{:#010X}", sec.virtual_size)),
        );
        print_field(
            Some(sec_base + 12),
            &f_pfx,
            "VirtualAddress",
            KW - 3,
            fmt_addr(&format!("{:#010X}", sec.virtual_address)),
        );
        print_field(
            Some(sec_base + 16),
            &f_pfx,
            "SizeOfRawData",
            KW - 3,
            fmt_value(&format!("{:#010X}", sec.size_of_raw_data)),
        );
        print_field(
            Some(sec_base + 20),
            &f_pfx,
            "PointerToRawData",
            KW - 3,
            fmt_addr(&format!("{:#010X}", sec.pointer_to_raw_data)),
        );
        print_field(
            Some(sec_base + 36),
            &fl_pfx,
            "Characteristics",
            KW - 3,
            fmt_value(&format!("{:#010X}", sec.characteristics)),
        );
        print_flags(
            pe::SECTION_CHARACTERISTICS_FLAGS,
            sec.characteristics,
            &flg_pfx,
            &flgl_pfx,
            &flga_pfx,
            all_flags,
        );
    }
}

pub fn dump_export_table(exp: &pe::ExportTable, is_last: bool) {
    let connector = if is_last { "└─ " } else { "├─ " };
    let pc = if is_last { "   " } else { "│  " };

    let n = exp.functions.len();
    println!(
        "              {}{} {}",
        fmt_tree(connector),
        fmt_section("Export Table"),
        fmt_dim(&format!("{} ({} exports)", exp.dll_name, n))
    );

    let digit = digit_count(n);
    for (i, func) in exp.functions.iter().enumerate() {
        let is_last_fn = i + 1 >= n;
        let fn_conn = if is_last_fn {
            format!("{}└─ ", pc)
        } else {
            format!("{}├─ ", pc)
        };

        let name_str = match &func.name {
            Some(name) => fmt_identifier(name).to_string(),
            None => fmt_dim("(unnamed)").to_string(),
        };

        println!(
            "{}{}{}{} {} {}",
            fmt_offset(func.eat_offset),
            fmt_tree(&fn_conn),
            fmt_dim(&format!("[{:0>width$}] ", func.ordinal, width = digit)),
            name_str,
            fmt_label("RVA:"),
            fmt_addr(&format!("{:#010X}", func.rva))
        );
    }
}

pub fn dump_import_table(descriptors: &[pe::ImportDescriptor]) {
    let n = descriptors.len();
    println!(
        "              {}{} {}",
        fmt_tree("└─ "),
        fmt_section("Import Table"),
        fmt_dim(&format!("({} DLLs)", n))
    );

    for (i, desc) in descriptors.iter().enumerate() {
        let is_last_dll = i + 1 >= n;
        let dll_conn = if is_last_dll {
            "   └─ "
        } else {
            "   ├─ "
        };
        let dll_pc = if is_last_dll { "      " } else { "   │  " };

        // DLL ヘッダ行
        println!(
            "{}{}{} {}",
            fmt_offset(desc.offset),
            fmt_tree(dll_conn),
            fmt_identifier(&desc.dll_name),
            fmt_dim(&format!("({} functions)", desc.functions.len()))
        );

        // 関数エントリ
        let m = desc.functions.len();
        for (j, func) in desc.functions.iter().enumerate() {
            let is_last_fn = j + 1 >= m;
            let fn_conn = if is_last_fn {
                format!("{}└─ ", dll_pc)
            } else {
                format!("{}├─ ", dll_pc)
            };

            let entry_str = match func.ordinal {
                Some(ord) => format!("{}", fmt_dim(&format!("(ordinal 0x{:04X})", ord))),
                None => {
                    let hint = func
                        .hint
                        .map(|h| format!("{} ", fmt_dim(&format!("[0x{:04X}]", h))))
                        .unwrap_or_default();
                    let name = func.name.as_deref().unwrap_or("(unknown)");
                    format!("{}{}", hint, fmt_identifier(name))
                }
            };

            println!(
                "{}{}{}",
                fmt_offset(func.thunk_offset),
                fmt_tree(&fn_conn),
                entry_str
            );
        }
    }
}
