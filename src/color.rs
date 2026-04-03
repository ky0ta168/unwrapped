use colored::*;

pub fn fmt_value(s: &str) -> ColoredString {
    s.cyan()
}

pub fn fmt_addr(s: &str) -> ColoredString {
    s.cyan()
}

pub fn fmt_identifier(s: &str) -> ColoredString {
    s.yellow()
}

/// 補足・注釈テキスト（暗グレー）
pub fn fmt_dim(s: &str) -> ColoredString {
    s.bright_black()
}

/// ツリー文字・プレフィックス（暗グレー）
pub fn fmt_tree(s: &str) -> ColoredString {
    s.bright_black()
}

/// セクション名（青・太字）
pub fn fmt_section(s: &str) -> ColoredString {
    s.blue().bold()
}

/// フィールド名（白）
pub fn fmt_field(s: &str) -> ColoredString {
    s.white()
}

/// ファイルオフセット列（暗グレー、"[0xXXXXXXXX]  " 形式）
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

/// セットされていないフラグ行（暗グレー）: "[ ] NAME (0xXXXXXXXX)"
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
