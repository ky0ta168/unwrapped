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
| 5 | [x] | COFF File Header パース | `IMAGE_FILE_HEADER` 構造体定義 / Machine / NumberOfSections / Characteristics パース | Machine種別・セクション数・Characteristicsフラグをカラー表示 |
| 6 | [x] | Optional Header パース | `IMAGE_OPTIONAL_HEADER32` 構造体定義 / EntryPoint / ImageBase / Subsystem / DllCharacteristics パース | EntryPoint・ImageBase・Subsystem・DllCharacteristicsフラグをカラー表示 |
| 7 | [x] | Data Directories パース | 16エントリの RVA / Size パース | 16エントリのRVA・Sizeをカラー表示 |
| 8 | [x] | Section Headers パース | `IMAGE_SECTION_HEADER` 構造体定義 / Name / VirtualAddress / VirtualSize / Characteristics パース | セクション名・アドレス・サイズ・フラグをカラー表示 |
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

### 基本構造

```
<ASCII art ロゴ>

[FILE] <ファイル名>
          ├─ <セクション名>
[OFFSET]  │  ├─ <フィールド名>         <値>
[OFFSET]  │  └─ <フィールド名>         <値>
          │     ├─ <フラグ>
          │     └─ <フラグ>
          └─ <セクション名>
             └─ <サブセクション名>
[OFFSET]        ├─[IDX] <エントリ名>   RVA: <値>  Size: <値>
```

### オフセット列

- 幅を `[0x0000]  ` の10文字に固定する
- フラグ行・サブセクション行など、オフセットのない行は同幅の空白で埋める
- 全行でツリー文字の開始位置が揃うようにする

### フィールド名と値のアライメント

- 各セクション内で最長のフィールド名に合わせて値の開始位置を統一する
- セクションをまたいだグローバルな統一は行わない

### フラグの表示制御

- デフォルト: `[x]`（セットされているフラグ）のみ表示し、末尾に `(<N> flags not set)` を付記する
- `--all-flags` オプション指定時: 全フラグを展開表示する
セットされているフラグがゼロ件の場合: `(no flags set)` の1行のみ表示する

```
[0x0056]  │  └─ Characteristics          0x0303
          │     ├─ [x] IMAGE_FILE_RELOCS_STRIPPED (0x00000001)
          │     ├─ [x] IMAGE_FILE_EXECUTABLE_IMAGE (0x00000002)
          │     ├─ [x] IMAGE_FILE_32BIT_MACHINE (0x00000100)
          │     └─ [x] IMAGE_FILE_DEBUG_STRIPPED (0x00000200)
          │        (11 flags not set)

[0x009E]  │  ├─ DllCharacteristics       0x0000
          │  │  └─ (no flags set)
```

### ツリー文字

| 記号 | 用途 |
|------|------|
| `├─` | 兄弟ノードが後続する要素 |
| `└─` | 最後の子要素 |
| `│`  | 親が継続していることを示す縦線 |
| 空白 | 親が終端した後のインデント |

### 配列フィールドの折りたたみ

全要素が同じ値の場合、1行に畳む。

```
[0x001C]  │  ├─ e_res[0..3]              0x0000 (all zero)
[0x0028]  │  ├─ e_res2[0..9]             0x0000 (all zero)
```

### Data Directories

- Optional Header の末尾の子として配置する
- ヘッダ行に `(<N> active, <M> empty)` のサマリーを付記する
- インデックスを `[NN]` 形式（2桁ゼロ埋め）で表示する
- `RVA:` `Size:` はラベルとして値と区別する

```
          │  └─ Data Directories  (<N> active, <M> empty)
[0x0170]  │     ├─[00] Export Table             RVA: 0x00000000  Size: 0x00000000
[0x0178]  │     ├─[01] Import Table             RVA: 0x0004C42C  Size: 0x000000C8
          ...
[0x01E8]  │     └─[15] Reserved                RVA: 0x00000000  Size: 0x00000000
```

### カラールール

| 色 | 対象 | 具体例 |
|----|------|--------|
| 青 (bold) | セクション名 | `DOS Header` `COFF File Header` `Optional Header` `Data Directories` |
| 暗グレー | ツリー文字 | `├─` `└─` `│` |
| グレー | オフセット | `[0x0000]` |
| 白 | フィールド名 | `e_magic` `Machine` `ImageBase` |
| 水色 | hex 値 | `0x5A4D` `0x00001000` |
| 黄色 | シンボル名・識別子 | `IMAGE_FILE_MACHINE_I386` `PE32` `IMAGE_SUBSYSTEM_WINDOWS_CUI` |
| 薄グレー | 補足の生値 | `(0x014C)` `(0x010B)` |
| 緑 | セット済みフラグ | `[x] IMAGE_FILE_EXECUTABLE_IMAGE` |
| 暗グレー | 未セットフラグ / 空エントリ行全体 / `(all zero)` | `[ ] IMAGE_FILE_DLL` / RVA=0のData Directory行 |
| 薄グレー (italic) | 注釈 | `(no flags set)` `(11 flags not set)` `(all zero)` `(7 active, 9 empty)` |
| 水色 (dim) | `RVA:` `Size:` ラベル | Data Directories のカラムヘッダ |
| 暗グレー | インデックス | `[00]` `[01]` |

### 空エントリの扱い

Data Directories において RVA と Size がともに `0x00000000` のエントリは、
行全体（インデックス・名前・値）を暗グレーで表示し、有効エントリと視覚的に区別する。

### エントロピー判定しきい値

| 値 | 判定 | 色 |
|----|------|----|
| 〜6.0 | `[normal]` | 緑 |
| 6.0〜7.0 | `[^ elevated]` | 黄 |
| 7.0〜 | `[!! HIGH - possibly packed]` | 赤 |

### Characteristics / DLL Characteristics

- セットされているフラグ → 緑で `[x] FLAG_NAME (0x00000000)`（ビット値を薄グレーで付記）
- セットされていないフラグ → グレーで `[ ] FLAG_NAME`（`--all-flags` 時のみ表示、ビット値を付記）

---

### 出力例（`-a` 時）

```
_   _                                        _
| | | |_ ____      ___ __ __ _ _ __   ___  __| |
| | | | '_ \ \ /\ / / '__/ _` | '_ \ / _ \/ _` |
| |_| | | | \ V  V /| | | (_| | |_) |  __/ (_| |
\___/|_| |_|\_/\_/ |_|  \__,_| .__/ \___|\__,_|
                              |_|

[FILE] example.exe
          ├─ DOS Header
[0x0000]  │  ├─ e_magic                         0x5A4D
[0x0002]  │  ├─ e_cblp                          0x0090
[0x0004]  │  ├─ e_cp                            0x0003
[0x0006]  │  ├─ e_crlc                          0x0000
[0x0008]  │  ├─ e_cparhdr                       0x0004
[0x000A]  │  ├─ e_minalloc                      0x0000
[0x000C]  │  ├─ e_maxalloc                      0xFFFF
[0x000E]  │  ├─ e_ss                            0x0000
[0x0010]  │  ├─ e_sp                            0x00B8
[0x0012]  │  ├─ e_csum                          0x0000
[0x0014]  │  ├─ e_ip                            0x0000
[0x0016]  │  ├─ e_cs                            0x0000
[0x0018]  │  ├─ e_lfarlc                        0x0040
[0x001A]  │  ├─ e_ovno                          0x0000
[0x001C]  │  ├─ e_res[0..3]                     0x0000 (all zero)
[0x0024]  │  ├─ e_oemid                         0x0000
[0x0026]  │  ├─ e_oeminfo                       0x0000
[0x0028]  │  ├─ e_res2[0..9]                    0x0000 (all zero)
[0x003C]  │  └─ e_lfanew                        0x00000040
          │
          ├─ COFF File Header
[0x0044]  │  ├─ Machine                         IMAGE_FILE_MACHINE_I386 (0x014C)
[0x0046]  │  ├─ NumberOfSections                5
[0x0048]  │  ├─ TimeDateStamp                   0x69CCA164
[0x004C]  │  ├─ PointerToSymbolTable            0x00000000
[0x0050]  │  ├─ NumberOfSymbols                 0
[0x0054]  │  ├─ SizeOfOptionalHeader            0x00E0
[0x0056]  │  └─ Characteristics                 0x0303
          │     ├─ [x] IMAGE_FILE_RELOCS_STRIPPED (0x00000001)
          │     ├─ [x] IMAGE_FILE_EXECUTABLE_IMAGE (0x00000002)
          │     ├─ [ ] IMAGE_FILE_LINE_NUMS_STRIPPED
          │     ├─ [ ] IMAGE_FILE_LOCAL_SYMS_STRIPPED
          │     ├─ [ ] IMAGE_FILE_AGGRESIVE_WS_TRIM
          │     ├─ [ ] IMAGE_FILE_LARGE_ADDRESS_AWARE
          │     ├─ [ ] IMAGE_FILE_BYTES_REVERSED_LO
          │     ├─ [x] IMAGE_FILE_32BIT_MACHINE (0x00000100)
          │     ├─ [x] IMAGE_FILE_DEBUG_STRIPPED (0x00000200)
          │     ├─ [ ] IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP
          │     ├─ [ ] IMAGE_FILE_NET_RUN_FROM_SWAP
          │     ├─ [ ] IMAGE_FILE_SYSTEM
          │     ├─ [ ] IMAGE_FILE_DLL
          │     ├─ [ ] IMAGE_FILE_UP_SYSTEM_ONLY
          │     └─ [ ] IMAGE_FILE_BYTES_REVERSED_HI
          │
          └─ Optional Header
[0x0058]     ├─ Magic                           PE32 (0x010B)
[0x005A]     ├─ MajorLinkerVersion              1
[0x005B]     ├─ MinorLinkerVersion              0
[0x005C]     ├─ SizeOfCode                      0x00000200
[0x0060]     ├─ SizeOfInitializedData           0x00000200
[0x0064]     ├─ SizeOfUninitializedData         0x00000004
[0x0068]     ├─ AddressOfEntryPoint             0x00001020
[0x006C]     ├─ BaseOfCode                      0x00001000
[0x0070]     ├─ BaseOfData                      0x00002000
[0x0074]     ├─ ImageBase                       0x0000000000400000
[0x0078]     ├─ SectionAlignment                0x00001000
[0x007C]     ├─ FileAlignment                   0x00000200
[0x0080]     ├─ MajorOperatingSystemVersion     4
[0x0082]     ├─ MinorOperatingSystemVersion     0
[0x0084]     ├─ MajorImageVersion               1
[0x0086]     ├─ MinorImageVersion               0
[0x0088]     ├─ MajorSubsystemVersion           4
[0x008A]     ├─ MinorSubsystemVersion           0
[0x008C]     ├─ Win32VersionValue               0x00000000
[0x0090]     ├─ SizeOfImage                     0x00006000
[0x0094]     ├─ SizeOfHeaders                   0x00000400
[0x0098]     ├─ CheckSum                        0x00000000
[0x009C]     ├─ Subsystem                       IMAGE_SUBSYSTEM_WINDOWS_CUI (0x0003)
[0x009E]     ├─ DllCharacteristics              0x0000
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_NX_COMPAT
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_NO_SEH
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_NO_BIND
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_APPCONTAINER
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
             │  ├─ [ ] IMAGE_DLLCHARACTERISTICS_GUARD_CF
             │  └─ [ ] IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
             │
             └─ Data Directories  (7 active, 9 empty)
[0x0170]        ├─[00] Export Table             RVA: 0x00000000  Size: 0x00000000
[0x0178]        ├─[01] Import Table             RVA: 0x0004C42C  Size: 0x000000C8
[0x0180]        ├─[02] Resource Table           RVA: 0x00000000  Size: 0x00000000
[0x0188]        ├─[03] Exception Table          RVA: 0x0004E000  Size: 0x000033CC
[0x0190]        ├─[04] Certificate Table        RVA: 0x00000000  Size: 0x00000000
[0x0198]        ├─[05] Base Relocation Table    RVA: 0x00052000  Size: 0x00000678
[0x01A0]        ├─[06] Debug                    RVA: 0x000448F0  Size: 0x00000054
[0x01A8]        ├─[07] Architecture             RVA: 0x00000000  Size: 0x00000000
[0x01B0]        ├─[08] Global Ptr               RVA: 0x00000000  Size: 0x00000000
[0x01B8]        ├─[09] TLS Table                RVA: 0x00044980  Size: 0x00000028
[0x01C0]        ├─[10] Load Config Table        RVA: 0x000447B0  Size: 0x00000140
[0x01C8]        ├─[11] Bound Import             RVA: 0x00000000  Size: 0x00000000
[0x01D0]        ├─[12] IAT                      RVA: 0x00039000  Size: 0x00000310
[0x01D8]        ├─[13] Delay Import Descriptor  RVA: 0x00000000  Size: 0x00000000
[0x01E0]        ├─[14] CLR Runtime Header       RVA: 0x00000000  Size: 0x00000000
[0x01E8]        └─[15] Reserved                 RVA: 0x00000000  Size: 0x00000000
```
