# unwraped

## プロジェクト概要

- `dumpbin` / `readelf` の簡易自作版PEダンプツール
- 入力：PEファイル（`.exe` / `.dll`）
- 言語：Rust
- プロジェクト名の由来：`unwrap`（開梱+Rust要素）+ `pe`（PE要素）+ `d`（Dump要素）

---

## 技術スタック

- Rust
- `colored` クレート（カラー表示）

---

## 実装ルール

- **ステップを1つ実装したら必ず止まり、ユーザーに確認してから次へ進む**
- 一度に複数のステップを実装しない
- **各ステップ完了時に `main.rs` に動作確認コードを追加する**
  - 例：パース機能を実装したらパース結果をダンプする
  - 次のステップに進む際は前のステップの確認コードを削除してもよい

---

## 実装ステップ

| # | 完了 | ステップ名 | 実装内容 | 確認内容 |
|---|------|-----------|---------|---------|
| 1 | [x] | プロジェクトセットアップ | `cargo new unwraped` / `colored` クレート追加 / コマンドライン引数受け取り | ファイルパスを受け取って表示する |
| 2 | [x] | カラー表示・レイアウト基盤 | 左ボーダー表示関数 / キー・値・アドレス・DLL名の色付け関数 / エントロピー色付け関数 | ダミーデータで全カラーパターンを表示する |
| 3 | [x] | PEファイル読み込み・バリデーション | バイト列読み込み / MZ・PEシグネチャ確認 | 有効なPEかどうかをカラー表示する |
| 4 | [x] | DOS Header パース | `IMAGE_DOS_HEADER` 構造体定義 / `Magic` / `e_lfanew` パース | DOS Headerの各フィールドをカラー表示 |
| 5 | [ ] | COFF File Header パース | `IMAGE_FILE_HEADER` 構造体定義 / Machine / NumberOfSections / Characteristics パース | Machine種別・セクション数・Characteristicsフラグをカラー表示 |
| 6 | [ ] | Optional Header パース | `IMAGE_OPTIONAL_HEADER32` 構造体定義 / EntryPoint / ImageBase / Subsystem / DllCharacteristics パース | EntryPoint・ImageBase・Subsystem・DllCharacteristicsフラグをカラー表示 |
| 7 | [ ] | Data Directories パース | 16エントリの RVA / Size パース | 16エントリのRVA・Sizeをカラー表示 |
| 8 | [ ] | Section Headers パース | `IMAGE_SECTION_HEADER` 構造体定義 / Name / VirtualAddress / VirtualSize / Characteristics パース | セクション名・アドレス・サイズ・フラグをカラー表示 |
| 9 | [ ] | Import Table パース | DLL名 / INT / IAT / 関数名 / Hint 取得 | DLL名・関数名・HintをカラーでDLLごとにグループ表示 |
| 10 | [ ] | Export Table パース | 関数名 / Ordinal / RVA 取得 | エクスポート関数名・Ordinal・RVAをカラー表示 |
| 11 | [ ] | Base Relocations パース | ブロック / エントリ / Type / Offset 取得 | ブロックごとのVirtualAddress・Type・Offsetをカラー表示 |
| 12 | [ ] | Debug Directory パース | CodeViewのPDBパス / GUID / Age 取得 | PDBパス・GUID・Ageをカラー表示 |
| 13 | [ ] | Section Entropy 計算 | エントロピー計算 / `[normal]` / `[^ elevated]` / `[!! HIGH]` 判定 | セクションごとのエントロピー値と判定結果をカラー表示 |
| 14 | [ ] | CLIフラグの実装 | `-h` / `-S` / `-s` / `-r` / `-d` / `-n` / `-a` 実装 | 各フラグで対応する項目のみ表示される |

---

## CLIフラグ

| フラグ | 内容 |
|--------|------|
| `-h` | DOS Header + COFF Header + Optional Header |
| `-S` | Section Headers |
| `-s` | Export Table / COFF Symbol Table |
| `-r` | Base Relocations |
| `-d` | Import Table / IAT |
| `-n` | Debug Directory |
| `-a` | 全項目出力 |

---

## 出力仕様

### レイアウト

- セクション名の左に青いボーダー
- セクション間に空行

### カラールール

| 色 | 用途 |
|----|------|
| 青 | セクションヘッダ名 |
| シアン | 数値・アドレス・RVA |
| 黄 | DLL名 |
| 白（薄） | キー名・関数名 |
| グレー | インデックス・OFFのフラグ |
| 緑 | 正常フラグ・`[normal]` |
| 黄（警告） | `[^ elevated]` |
| 赤 | `[!! HIGH - possibly packed]` |

### エントロピー判定しきい値

| 値 | 判定 | 色 |
|----|------|----|
| 〜6.0 | `[normal]` | 緑 |
| 6.0〜7.0 | `[^ elevated]` | 黄 |
| 7.0〜 | `[!! HIGH - possibly packed]` | 赤 |

### Characteristics / DLL Characteristics

- セットされているフラグ → 緑で `[x]`
- セットされていないフラグ → グレーで `[ ]`

### 出力例（`-a` 時）

```
▌ DOS Header
  Magic:                          MZ
  Offset to PE Header (e_lfanew): 0x00000100

▌ COFF File Header
  Machine:                        IMAGE_FILE_MACHINE_I386 (0x014C)
  Number of Sections:             4
  Characteristics:                0x0102
    [x] IMAGE_FILE_EXECUTABLE_IMAGE
    [x] IMAGE_FILE_32BIT_MACHINE
    [ ] IMAGE_FILE_DLL

▌ Section Headers
  [Nr]  Name     VirtAddr    VirtSize    RawAddr     RawSize     Flags
  [ 0]  .text    0x00001000  0x0000A3C0  0x00000400  0x0000A400  R X
  [ 1]  .rdata   0x0000C000  0x00001234  0x0000A800  0x00001400  R

▌ Import Table
  DLL: kernel32.dll
    INT RVA: 0x0000B5C0    IAT RVA: 0x0000C000
    [00]  Hint=0x0001  Name=ExitProcess
    [01]  Hint=0x0123  Name=GetStdHandle

▌ Section Entropy
  Name      Entropy   Rating
  .text     5.23      [normal]
  .upx0     7.94      [!! HIGH - possibly packed]
```