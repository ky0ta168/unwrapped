# unwrapped

## プロジェクト概要

- 入力：PEファイル（`.exe` / `.dll`）
- 言語：Rust
- プロジェクト名の由来：`unwrap`（開梱+Rust要素）+ `pe`（PE要素）+ `d`（Dump要素）
- `colored` クレート（カラー表示）

---

## 実装ルール

- ステップを1つ実装したら必ず止まり、ユーザーに確認してから次へ進む
- Rustのコードを修正したら `cargo fmt`, `cargo clippy` を実行してください
- 作業対象のファイルのみ Read する。他モジュールは必要な場合のみ参照する

---

## 実装ステップ

✅ ステップ 1〜10 完了済み

| # | 完了 | ステップ名 | 実装内容 | 確認内容 |
|---|------|-----------|---------|---------|
| 11 | [ ] | Base Relocations パース | ブロック / エントリ / Type / Offset 取得 | ブロックごとのVirtualAddress・Type・Offsetをカラー表示 |
| 12 | [ ] | Debug Directory パース | CodeViewのPDBパス / GUID / Age 取得 | PDBパス・GUID・Ageをカラー表示 |
| 13 | [ ] | Section Entropy 計算 | エントロピー計算 / `[normal]` / `[^ elevated]` / `[!! HIGH]` 判定 | セクションごとのエントロピー値と判定結果をカラー表示 |
| 14 | [ ] | CLIフラグの実装 | `-h` / `-S` / `-s` / `-r` / `-d` / `-n` / `-a` 実装 | 各フラグで対応する項目のみ表示される |

---

## 出力例

出力例は `docs/output_example.txt` に記載してあるが、必要な場合のみ Read する。

---
