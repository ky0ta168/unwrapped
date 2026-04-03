# Unwrapped

PE ファイル（`.exe` / `.dll`）の構造をターミナルにダンプするツール。
`dumpbin` / `readelf` の簡易自作版。

名前の由来: `unwrap`（開梱 + Rust 要素）+ `pe`（PE 要素）+ `d`（Dump 要素）

## ビルド

```
cargo build --release
```

## 使い方

```
unwrapped [--all-flags] <file>
```

| オプション | 説明 |
|------------|------|
| `--all-flags` | Characteristics / DllCharacteristics の未セットフラグも展開表示する |

## 出力内容

### DOS Header

`IMAGE_DOS_HEADER` の全フィールドを表示する。`e_res` / `e_res2` は全要素が同値の場合は1行に畳んで表示する。

### COFF File Header

`IMAGE_FILE_HEADER` の全フィールドを表示する。

- `Machine`: マシン種別をシンボル名（例: `IMAGE_FILE_MACHINE_AMD64`）と生値で表示
- `Characteristics`: フラグ一覧を表示（デフォルト: セット済みのみ / `--all-flags`: 全フラグ）

### Optional Header

`IMAGE_OPTIONAL_HEADER32` / `IMAGE_OPTIONAL_HEADER64` の主要フィールドを表示する。

- `Magic`: PE32 / PE32+ をシンボル名と生値で表示
- `Subsystem`: サブシステム種別をシンボル名と生値で表示
- `DllCharacteristics`: フラグ一覧を表示

### Data Directories

Optional Header の末尾に 16 エントリ分を表示する。ヘッダ行に `(N active, M empty)` のサマリーを付記する。RVA / Size がともにゼロのエントリは暗グレーで表示する。

### Section Headers

各セクションの以下のフィールドを表示する。

- `Name` / `VirtualSize` / `VirtualAddress`
- `SizeOfRawData` / `PointerToRawData`
- `Characteristics`: フラグ一覧を表示

### Export Table

`IMAGE_EXPORT_DIRECTORY` の全フィールドを表示したあと、エクスポート関数の一覧を表示する。

- 関数ごとに Ordinal / RVA / 関数名を表示
- 名前なし（ordinal-only）エクスポートにも対応
- フォワード文字列（`DLL.FunctionName` 形式）を持つエントリも表示

### Import Table

インポートする DLL ごとにグループ化して表示する。

- 関数ごとに Hint / 関数名を表示
- 序数インポートにも対応

## 出力フォーマット

```
          ├─ DOS Header
[0x0000]  │  ├─ e_magic          0x5A4D
[0x0002]  │  └─ ...
          │
          ├─ COFF File Header
[0x0044]  │  ├─ Machine          IMAGE_FILE_MACHINE_I386 (0x014C)
          │  └─ Characteristics  0x0303
          │     ├─ [x] IMAGE_FILE_EXECUTABLE_IMAGE (0x00000002)
          │     └─ (11 flags not set)
          │
          └─ Optional Header
             └─ ...
```

- オフセット列は `[0x00000000]  `（14 文字固定）
- ツリー文字（`├─` `└─` `│`）は暗グレー
- セクション名は青・太字
- フィールド名は白、値は水色
- シンボル名・識別子は黄色
- セット済みフラグは緑、未セットフラグは暗グレー
