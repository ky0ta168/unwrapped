use super::{PeFile, SectionHeader, read_u16, read_u32};
use crate::render::*;

const KW: usize = 24;

pub struct DebugDirectory {
    pub file_offset: usize,
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub debug_type: u32,
    pub size_of_data: u32,
    pub address_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
}

pub struct CodeViewInfo {
    pub signature: [u8; 4],
    pub guid: [u8; 16],
    pub age: u32,
    pub pdb_path: String,
}

pub const DEBUG_TYPES: &[(u32, &str)] = &[
    (0, "IMAGE_DEBUG_TYPE_UNKNOWN"),
    (1, "IMAGE_DEBUG_TYPE_COFF"),
    (2, "IMAGE_DEBUG_TYPE_CODEVIEW"),
    (3, "IMAGE_DEBUG_TYPE_FPO"),
    (4, "IMAGE_DEBUG_TYPE_MISC"),
    (5, "IMAGE_DEBUG_TYPE_EXCEPTION"),
    (6, "IMAGE_DEBUG_TYPE_FIXUP"),
    (7, "IMAGE_DEBUG_TYPE_OMAP_TO_SRC"),
    (8, "IMAGE_DEBUG_TYPE_OMAP_FROM_SRC"),
    (9, "IMAGE_DEBUG_TYPE_BORLAND"),
    (11, "IMAGE_DEBUG_TYPE_CLSID"),
    (13, "IMAGE_DEBUG_TYPE_VC_FEATURE"),
    (14, "IMAGE_DEBUG_TYPE_POGO"),
    (15, "IMAGE_DEBUG_TYPE_ILTCG"),
    (16, "IMAGE_DEBUG_TYPE_MPX"),
    (17, "IMAGE_DEBUG_TYPE_REPRO"),
    (20, "IMAGE_DEBUG_TYPE_EMBEDDEDPORTABLEPDB"),
    (21, "IMAGE_DEBUG_TYPE_SPGO"),
];

impl PeFile {
    pub fn debug_directory(
        &self,
        sections: &[SectionHeader],
    ) -> Option<(Vec<DebugDirectory>, Vec<Option<CodeViewInfo>>)> {
        let (_, dirs) = self.data_directories();
        let debug_dir = dirs.get(6)?;
        if debug_dir.virtual_address == 0 || debug_dir.size == 0 {
            return None;
        }

        let file_offset = super::rva_to_file_offset(debug_dir.virtual_address, sections)?;
        let count = (debug_dir.size as usize) / 28;

        let mut entries = Vec::new();
        let mut cv_infos = Vec::new();

        for i in 0..count {
            let off = file_offset + i * 28;
            if off + 28 > self.data.len() {
                break;
            }
            let entry = DebugDirectory {
                file_offset: off,
                characteristics: read_u32(&self.data, off),
                time_date_stamp: read_u32(&self.data, off + 4),
                major_version: read_u16(&self.data, off + 8),
                minor_version: read_u16(&self.data, off + 10),
                debug_type: read_u32(&self.data, off + 12),
                size_of_data: read_u32(&self.data, off + 16),
                address_of_raw_data: read_u32(&self.data, off + 20),
                pointer_to_raw_data: read_u32(&self.data, off + 24),
            };

            let cv = if entry.debug_type == 2 {
                parse_codeview(&self.data, &entry)
            } else {
                None
            };

            entries.push(entry);
            cv_infos.push(cv);
        }

        Some((entries, cv_infos))
    }
}

fn parse_codeview(data: &[u8], entry: &DebugDirectory) -> Option<CodeViewInfo> {
    let ptr = entry.pointer_to_raw_data as usize;
    let size = entry.size_of_data as usize;
    if ptr + size > data.len() || size < 24 {
        return None;
    }
    let raw = &data[ptr..ptr + size];

    // "RSDS" signature
    if &raw[0..4] != b"RSDS" {
        return None;
    }

    let mut guid = [0u8; 16];
    guid.copy_from_slice(&raw[4..20]);
    let age = read_u32(raw, 20);

    // PDB path: null-terminated string after age
    let pdb_start = 24;
    let end = raw[pdb_start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| pdb_start + p)
        .unwrap_or(raw.len());
    let pdb_path = String::from_utf8_lossy(&raw[pdb_start..end]).to_string();

    Some(CodeViewInfo {
        signature: raw[0..4].try_into().unwrap(),
        guid,
        age,
        pdb_path,
    })
}

fn fmt_guid(guid: &[u8; 16]) -> String {
    // {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    let data1 = u32::from_le_bytes(guid[0..4].try_into().unwrap());
    let data2 = u16::from_le_bytes(guid[4..6].try_into().unwrap());
    let data3 = u16::from_le_bytes(guid[6..8].try_into().unwrap());
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        data1,
        data2,
        data3,
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15],
    )
}

pub fn dump_debug_directory(
    entries: &[DebugDirectory],
    cv_infos: &[Option<CodeViewInfo>],
    is_last: bool,
) {
    let connector = if is_last { "└─ " } else { "├─ " };
    let pc = if is_last { "   " } else { "│  " };

    let count = entries.len();
    print_section_header(connector, &format!("Debug Directory ({} entries)", count));

    for (i, (entry, cv)) in entries.iter().zip(cv_infos.iter()).enumerate() {
        let is_last_entry = i + 1 >= count;
        let ec = if is_last_entry {
            format!("{}└─ ", pc)
        } else {
            format!("{}├─ ", pc)
        };
        let epc = if is_last_entry {
            format!("{}   ", pc)
        } else {
            format!("{}│  ", pc)
        };
        let ef = format!("{}├─ ", epc);
        let efl = format!("{}└─ ", epc);

        let type_name = DEBUG_TYPES
            .iter()
            .find(|&&(v, _)| v == entry.debug_type)
            .map(|&(_, n)| n)
            .unwrap_or("UNKNOWN");

        println!(
            "              {}{} {}",
            fmt_tree(&ec),
            fmt_dim(&format!("[{:02}]", i)),
            fmt_identifier(type_name)
        );

        print_field(
            Some(entry.file_offset),
            &ef,
            "Characteristics",
            KW,
            fmt_value(&format!("{:#010X}", entry.characteristics)),
        );
        print_field(
            Some(entry.file_offset + 4),
            &ef,
            "TimeDateStamp",
            KW,
            fmt_value(&format!("{:#010X}", entry.time_date_stamp)),
        );
        print_field(
            Some(entry.file_offset + 8),
            &ef,
            "MajorVersion",
            KW,
            fmt_num(&format!("{}", entry.major_version)),
        );
        print_field(
            Some(entry.file_offset + 10),
            &ef,
            "MinorVersion",
            KW,
            fmt_num(&format!("{}", entry.minor_version)),
        );
        print_field(
            Some(entry.file_offset + 12),
            &ef,
            "Type",
            KW,
            fmt_symbol(type_name, entry.debug_type as u16),
        );
        print_field(
            Some(entry.file_offset + 16),
            &ef,
            "SizeOfData",
            KW,
            fmt_value(&format!("{:#010X}", entry.size_of_data)),
        );
        print_field(
            Some(entry.file_offset + 20),
            &ef,
            "AddressOfRawData",
            KW,
            fmt_addr(&format!("{:#010X}", entry.address_of_raw_data)),
        );
        let ptr_connector = if cv.is_some() { &ef } else { &efl };
        print_field(
            Some(entry.file_offset + 24),
            ptr_connector,
            "PointerToRawData",
            KW,
            fmt_addr(&format!("{:#010X}", entry.pointer_to_raw_data)),
        );

        if let Some(cv) = cv {
            let sig_str = String::from_utf8_lossy(&cv.signature).to_string();
            print_field(
                Some(entry.pointer_to_raw_data as usize),
                &ef,
                "Signature",
                KW,
                fmt_identifier(&format!(
                    "{} ({:02X}{:02X}{:02X}{:02X})",
                    sig_str, cv.signature[0], cv.signature[1], cv.signature[2], cv.signature[3]
                )),
            );
            print_field(
                Some(entry.pointer_to_raw_data as usize + 4),
                &ef,
                "GUID",
                KW,
                fmt_identifier(&fmt_guid(&cv.guid)),
            );
            print_field(
                Some(entry.pointer_to_raw_data as usize + 20),
                &ef,
                "Age",
                KW,
                fmt_num(&format!("{}", cv.age)),
            );
            print_field(
                Some(entry.pointer_to_raw_data as usize + 24),
                &efl,
                "PdbFileName",
                KW,
                fmt_identifier(&cv.pdb_path),
            );
        }
    }
}
