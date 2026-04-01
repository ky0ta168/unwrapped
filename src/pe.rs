use std::fs;
use std::path::Path;

pub struct PeFile {
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum PeError {
    Io(std::io::Error),
    TooSmall,
    InvalidMz,
    InvalidPe,
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeError::Io(e) => write!(f, "IO error: {}", e),
            PeError::TooSmall => write!(f, "File too small"),
            PeError::InvalidMz => write!(f, "Invalid MZ signature"),
            PeError::InvalidPe => write!(f, "Invalid PE signature"),
        }
    }
}

impl PeFile {
    pub fn open(path: &Path) -> Result<Self, PeError> {
        let data = fs::read(path).map_err(PeError::Io)?;

        if data.len() < 0x40 {
            return Err(PeError::TooSmall);
        }

        // MZ シグネチャ確認
        if &data[0..2] != b"MZ" {
            return Err(PeError::InvalidMz);
        }

        // e_lfanew (offset 0x3C) から PE ヘッダオフセットを取得
        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;

        if data.len() < e_lfanew + 4 {
            return Err(PeError::InvalidPe);
        }

        // PE\0\0 シグネチャ確認
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(PeError::InvalidPe);
        }

        Ok(PeFile { data })
    }
}
