use colored::*;

/// 16進数データ値: `0x5A4D`, `0x0090`
pub fn fmt_value(s: &str) -> ColoredString {
    s.bright_blue()
}

/// アドレス・RVA
pub fn fmt_addr(s: &str) -> ColoredString {
    s.bright_blue()
}

/// シンボル定数名: `IMAGE_FILE_MACHINE_AMD64`
pub fn fmt_identifier(s: &str) -> ColoredString {
    s.yellow()
}

/// 10進数の数値（白）: `6`, `14`, `30`
pub fn fmt_num(s: &str) -> ColoredString {
    s.white()
}

/// DLL名: `msvcrt.dll`
pub fn fmt_dll(s: &str) -> ColoredString {
    s.bright_magenta()
}

/// インポート/エクスポート関数名（明るい黄）: `malloc`, `MoveFileW`
pub fn fmt_func(s: &str) -> ColoredString {
    s.bright_yellow()
}

/// セクション名（水色）: `.text`, `.rdata`
pub fn fmt_section_name(s: &str) -> ColoredString {
    s.cyan()
}

/// 補足・注釈テキスト
pub fn fmt_dim(s: &str) -> ColoredString {
    s.bright_black()
}

/// ツリー文字・プレフィックス
pub fn fmt_tree(s: &str) -> ColoredString {
    s.bright_black()
}

/// セクションヘッダラベル（水色）
pub fn fmt_section(s: &str) -> ColoredString {
    s.cyan().bold()
}

/// フィールド名（白）
pub fn fmt_field(s: &str) -> ColoredString {
    s.white()
}

/// ファイルオフセット列（"[0xXXXXXXXX]  " 形式）
pub fn fmt_offset(o: usize) -> String {
    format!("[{:#010X}]  ", o).bright_black().to_string()
}

/// RVA:/Size: などのラベル（水色）
pub fn fmt_label(s: &str) -> ColoredString {
    s.cyan()
}

/// セットされているフラグ行（緑）: "[x] NAME (0xXXXXXXXX)"
pub fn fmt_flag_on(name: &str, mask: u32) -> String {
    format!(
        "{} {} {}",
        "[x]".bright_green(),
        name.bright_green(),
        format!("(0x{:08X})", mask).bright_black()
    )
}

/// セットされていないフラグ行: "[ ] NAME (0xXXXXXXXX)"
pub fn fmt_flag_off(name: &str, mask: u32) -> String {
    format!(
        "{} {} {}",
        "[ ]".bright_black(),
        name.bright_black(),
        format!("(0x{:08X})", mask).bright_black()
    )
}

/// シンボル名と生の数値を組み合わせて表示する。例: `PE32 (0x010B)`
pub fn fmt_symbol(name: &str, raw: u16) -> String {
    format!(
        "{} {}",
        name.yellow(),
        format!("({:#06X})", raw).bright_black()
    )
}

/// フィールド行を1行出力する。
/// offset: ファイルオフセット（None = 10スペースの空白列）
/// prefix: ツリープレフィックス文字列
/// key: フィールド名（kw幅にパディング）
/// kw: キー列の幅
/// value: 表示する値
pub fn print_field(
    offset: Option<usize>,
    prefix: &str,
    key: &str,
    kw: usize,
    value: impl std::fmt::Display,
) {
    let off = match offset {
        Some(o) => fmt_offset(o),
        None => "              ".to_string(),
    };
    let padded = format!("{:<kw$}", key, kw = kw);
    println!(
        "{}{}{} {}",
        off,
        fmt_tree(prefix),
        fmt_field(&padded),
        value
    );
}

/// セクションヘッダ行を出力する（オフセット列は常に空白）。
/// connector: "├─ " または "└─ "
/// name: セクション名
pub fn print_section_header(connector: &str, name: &str) {
    println!("              {}{}", fmt_tree(connector), fmt_section(name));
}

/// ツリー継続を示す空白セパレータ行を出力する。
pub fn print_separator(tree_chars: &str) {
    println!("              {}", fmt_tree(tree_chars));
}

/// フィールド配下のフラグを出力する。
/// all_flags: true なら全フラグ表示、false ならセット済みフラグのみ + "(N flags not set)" 注釈。
pub fn print_flags(
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
            println!(
                "              {}{}",
                fmt_tree(pfx_last),
                fmt_dim("(no flags set)")
            );
        } else {
            let n = set.len();
            for (i, &(flag, name)) in set.iter().enumerate() {
                let pfx = if i + 1 < n { pfx_mid } else { pfx_last };
                println!("              {}{}", fmt_tree(pfx), fmt_flag_on(name, flag));
            }
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
