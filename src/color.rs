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
