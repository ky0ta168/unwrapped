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

pub fn fmt_dim(s: &str) -> ColoredString {
    s.bright_black()
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
/// prefix: ツリープレフィックス文字列（暗グレーで表示）
/// key: フィールド名（白、kw幅にパディング）
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
        Some(o) => format!("[{:#06X}]  ", o).bright_black().to_string(),
        None => "          ".to_string(),
    };
    let padded = format!("{:<kw$}", key, kw = kw);
    println!(
        "{}{}{} {}",
        off,
        prefix.bright_black(),
        padded.white(),
        value
    );
}

/// セクションヘッダ行を出力する（オフセット列は常に空白）。
/// connector: "├─ " または "└─ "
/// name: セクション名（青・太字）
pub fn print_section_header(connector: &str, name: &str) {
    println!(
        "          {}{}",
        connector.bright_black(),
        name.blue().bold()
    );
}

/// ツリー継続を示す空白セパレータ行を出力する。
pub fn print_separator(tree_chars: &str) {
    println!("          {}", tree_chars.bright_black());
}
