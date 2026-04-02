use colored::*;

/// 左ボーダー付きセクションヘッダを表示
pub fn print_section(title: &str) {
    println!("{} {}", "▌".blue(), title.blue().bold());
}

/// キー名（白薄）
pub fn fmt_key(s: &str) -> ColoredString {
    s.white()
}

/// 値・数値（シアン）
pub fn fmt_value(s: &str) -> ColoredString {
    s.cyan()
}

/// アドレス・RVA（シアン）
pub fn fmt_addr(s: &str) -> ColoredString {
    s.cyan()
}

/// DLL名（黄）
pub fn fmt_dll(s: &str) -> ColoredString {
    s.yellow()
}

/// インデックス・OFFフラグ（グレー）
pub fn fmt_gray(s: &str) -> ColoredString {
    s.bright_black()
}

/// ファイルオフセット（グレー）
pub fn fmt_offset(offset: usize) -> ColoredString {
    format!("[{:#06X}]", offset).bright_black()
}

/// オフセット付きフィールド1行を出力
/// key_width: キー列の可視文字幅
pub fn print_field(offset: usize, key: &str, key_width: usize, value: impl std::fmt::Display) {
    let padded_key = format!("{:<width$}", key, width = key_width);
    println!("  {} {} {}", fmt_offset(offset), padded_key.white(), value);
}

/// ONフラグ（緑）
pub fn fmt_flag_on(s: &str) -> ColoredString {
    s.green()
}

/// エントロピー判定の色付き文字列を返す
pub fn fmt_entropy(entropy: f64) -> ColoredString {
    if entropy < 6.0 {
        "[normal]".green()
    } else if entropy < 7.0 {
        "[^ elevated]".yellow()
    } else {
        "[!! HIGH - possibly packed]".red()
    }
}
