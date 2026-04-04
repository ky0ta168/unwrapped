use std::fs;
use std::path::Path;

pub mod coff;
pub mod dos_header;
pub mod exports;
pub mod imports;
pub mod optional;
pub mod relocations;
pub mod sections;

pub use coff::dump_coff_header;
pub use dos_header::dump_dos_header;
pub use exports::dump_export_table;
pub use imports::dump_import_table;
pub use optional::dump_optional_header;
pub use relocations::dump_relocation_table;
pub use sections::{SectionHeader, dump_section_headers};

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

pub(crate) fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub(crate) fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

pub(crate) fn read_cstring(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(data.len());
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

pub(crate) fn rva_to_file_offset(rva: u32, secs: &[SectionHeader]) -> Option<usize> {
    for sec in secs {
        let size = if sec.virtual_size != 0 {
            sec.virtual_size
        } else {
            sec.size_of_raw_data
        };
        if rva >= sec.virtual_address && rva < sec.virtual_address + size {
            return Some((rva - sec.virtual_address + sec.pointer_to_raw_data) as usize);
        }
    }
    None
}

impl PeFile {
    pub(crate) fn pe_offset(&self) -> usize {
        read_u32(&self.data, 0x3C) as usize
    }

    pub(crate) fn is_pe32plus(&self) -> bool {
        let opt_base = self.pe_offset() + 4 + 20;
        read_u16(&self.data, opt_base) == 0x020B
    }

    pub fn open(path: &Path) -> Result<Self, PeError> {
        let data = fs::read(path).map_err(PeError::Io)?;

        if data.len() < 0x40 {
            return Err(PeError::TooSmall);
        }

        if &data[0..2] != b"MZ" {
            return Err(PeError::InvalidMz);
        }

        let e_lfanew = read_u32(&data, 0x3C) as usize;

        if data.len() < e_lfanew + 4 {
            return Err(PeError::InvalidPe);
        }

        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return Err(PeError::InvalidPe);
        }

        Ok(PeFile { data })
    }
}
