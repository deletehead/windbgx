use std::fs::File;
use std::path::Path;
use std::collections::HashSet;
use std::io::{self, Cursor, Read};

use pdb::{PDB, FallibleIterator};


#[repr(C)]
#[derive(Debug)]
struct CvHeader {
    signature: [u8; 4], // "RSDS"
    guid: [u8; 16],     // GUID
    age: u32,           // PDB age
    // followed by PDB file name (null-terminated string)
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct NtOffsets {
    pub modus_previosa: u64,
    pub protection: u64,
    pub token: u64,
    pub psp_create_process_notify_routine: u64,
    pub psp_create_thread_notify_routine: u64,
    pub psp_load_image_notify_routine: u64,
    pub threat_int_prov_reg_handle: u64,
    pub guid_entry: u64,
    pub prov_enable_info: u64,
    pub ps_process_type: u64,
    pub ps_thread_type: u64,
    pub se_ci_callbacks: u64,
}

/// Generate the full URL for the PDB symbol file download
pub fn pdb_symbol_url<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut file = File::open(&path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Find "RSDS" in the file (CodeView debug signature)
    if let Some(pos) = buffer.windows(4).position(|w| w == b"RSDS") {
        if pos + std::mem::size_of::<CvHeader>() <= buffer.len() {
            let header_bytes = &buffer[pos..pos + std::mem::size_of::<CvHeader>()];
            let cv: CvHeader = unsafe { std::ptr::read(header_bytes.as_ptr() as *const _) };

            // After CvHeader comes the null-terminated PDB filename
            let name_start = pos + std::mem::size_of::<CvHeader>();
            let name_end = buffer[name_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|off| name_start + off)
                .unwrap_or(buffer.len());

            let pdb_name = String::from_utf8_lossy(&buffer[name_start..name_end]);

            // Convert GUID bytes into symbol server format
            let d1 = u32::from_le_bytes(cv.guid[0..4].try_into().unwrap());
            let d2 = u16::from_le_bytes(cv.guid[4..6].try_into().unwrap());
            let d3 = u16::from_le_bytes(cv.guid[6..8].try_into().unwrap());
            let d4 = &cv.guid[8..16];

            let guid_str = format!(
                "{:08X}{:04X}{:04X}{}",
                d1,
                d2,
                d3,
                d4.iter().map(|b| format!("{:02X}", b)).collect::<String>()
            );

            // Build and RETURN the URL
            let url = format!(
                "https://msdl.microsoft.com/download/symbols/{}/{}{}{}",
                pdb_name, guid_str, cv.age, format!("/{}", pdb_name)
            );
            return Ok(url);
        } else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Found RSDS signature but not enough bytes for header.",
            ));
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No RSDS debug entry found in file.",
    ))
}

pub fn get_nt_offsets(pdb: &mut PDB<Cursor<Vec<u8>>>) -> pdb::Result<NtOffsets> {
    let target_symbols: [&str; 7] = [
        "PspCreateProcessNotifyRoutine",
        "PspCreateThreadNotifyRoutine",
        "PspLoadImageNotifyRoutine",
        "EtwThreatIntProvRegHandle",
        "PsProcessType",
        "PsThreadType",
        "SeCiCallbacks",
    ];

    let symbol_table = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;

    let mut found_symbols: HashSet<String> = HashSet::new();
    let mut found_members: HashSet<String> = HashSet::new();
    let mut symbols = symbol_table.iter();

    // Initialize all offsets to 0
    let mut offsets = NtOffsets::default();

    while let Some(symbol) = symbols.next()? {
        if let Ok(pdb::SymbolData::Public(data)) = symbol.parse() {
            let name = data.name.to_string(); // Cow<'_, str>

            if target_symbols.contains(&name.as_ref()) {
                if let Some(rva) = data.offset.to_rva(&address_map) {
                    let addr = rva.0 as u64;

                    match name.as_ref() {
                        "PspCreateProcessNotifyRoutine" => offsets.psp_create_process_notify_routine = addr,
                        "PspCreateThreadNotifyRoutine" => offsets.psp_create_thread_notify_routine = addr,
                        "PspLoadImageNotifyRoutine" => offsets.psp_load_image_notify_routine = addr,
                        "EtwThreatIntProvRegHandle" => offsets.threat_int_prov_reg_handle = addr,
                        "PsProcessType" => offsets.ps_process_type = addr,
                        "PsThreadType" => offsets.ps_thread_type = addr,
                        "SeCiCallbacks" => offsets.se_ci_callbacks = addr,
                        _ => {}
                    }

                    found_symbols.insert(name.into_owned());
                }
            }
        }
    }

    for &target in &target_symbols {
        if !found_symbols.contains(target) {
            println!("[!] Missing symbol: {}. Exiting for safety...", target);
            std::process::exit(-1);
        }
    }

    // =-=-> Get struct offsets
    let struct_mems = [
        ("_EPROCESS", "Token"),
        ("_EPROCESS", "Protection"),
        ("_KTHREAD", "PreviousMode"),
        ("_ETW_REG_ENTRY", "GuidEntry"),
        ("_ETW_GUID_ENTRY", "ProviderEnableInfo"),
    ];

    for (struct_name, member_name) in struct_mems.iter() {
        if let Ok(offset) = get_struct_member_offset(pdb, struct_name, member_name) {
            match (*struct_name, *member_name) {
                ("_EPROCESS", "Token") => offsets.token = offset,
                ("_EPROCESS", "Protection") => offsets.protection = offset,
                ("_KTHREAD", "PreviousMode") => offsets.modus_previosa = offset,
                ("_ETW_REG_ENTRY", "GuidEntry") => offsets.guid_entry = offset,
                ("_ETW_GUID_ENTRY", "ProviderEnableInfo") => offsets.prov_enable_info = offset,
                _ => {}
            }

            found_members.insert(member_name.to_string());
        }
    }

    println!(
        "[+] Found {}/{} symbols and {}/{} structure members",
        found_symbols.len(),
        target_symbols.len(),
        found_members.len(),
        struct_mems.len()
    );

    // Loop over expected members, not the found ones
    for (struct_name, member_name) in struct_mems.iter() {
        if !found_members.contains(&member_name.to_string()) {
            println!("[!] Missing struct member: {}::{}. Exiting for safety...", struct_name, member_name);
            std::process::exit(-1);
        }
    }


    Ok(offsets)
}


// Custom error type for our function
#[derive(Debug)]
pub enum StructOffsetError {
    PdbError(pdb::Error),
    StructNotFound(String),
    MemberNotFound(String, String), // struct_name, member_name
    FieldParseError(String),
    IoError(std::io::Error),
}

impl std::fmt::Display for StructOffsetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StructOffsetError::PdbError(e) => write!(f, "PDB error: {}", e),
            StructOffsetError::StructNotFound(name) => write!(f, "Struct '{}' not found", name),
            StructOffsetError::MemberNotFound(struct_name, member_name) => {
                write!(f, "Member '{}' not found in struct '{}'", member_name, struct_name)
            },
            StructOffsetError::FieldParseError(msg) => write!(f, "Field parse error: {}", msg),
            StructOffsetError::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for StructOffsetError {}

impl From<pdb::Error> for StructOffsetError {
    fn from(err: pdb::Error) -> Self {
        StructOffsetError::PdbError(err)
    }
}

impl From<std::io::Error> for StructOffsetError {
    fn from(err: std::io::Error) -> Self {
        StructOffsetError::IoError(err)
    }
}

/// Get the offset of a specific member within a struct from PDB data
/// 
/// # Arguments
/// * `pdb_data` - Mutable reference to the PDB object
/// * `struct_name` - Name of the struct to search for (e.g., "_EPROCESS")
/// * `member_name` - Name of the member within the struct (e.g., "Token")
/// 
/// # Returns
/// * `Ok(u64)` - The offset of the member in bytes
/// * `Err(StructOffsetError)` - Various error conditions
/// 
/// # Example
/// ```
/// let cursor = std::io::Cursor::new(pdb_data);
/// let mut pdb = PDB::open(cursor)?;
/// let offset = get_struct_member_offset(&mut pdb, "_EPROCESS", "Token")?;
/// println!("Token offset: 0x{:x}", offset);
/// ```
pub fn get_struct_member_offset(
    pdb_data: &mut PDB<std::io::Cursor<Vec<u8>>>,
    struct_name: &str,
    member_name: &str,
) -> Result<u64, StructOffsetError> {
    let type_information = pdb_data.type_information()?;
    let mut iter = type_information.iter();
    
    // First pass: collect all matching struct candidates
    let mut struct_candidates = Vec::new();
    
    while let Some(typ) = iter.next()? {
        let type_index = typ.index();
        
        match typ.parse() {
            Ok(pdb::TypeData::Class(class_type)) => {
                if class_type.name.to_string() == struct_name {
                    struct_candidates.push((type_index, class_type.fields, class_type.size));
                }
            },
            Ok(pdb::TypeData::Union(union_type)) => {
                if union_type.name.to_string() == struct_name {
                    struct_candidates.push((type_index, Some(union_type.fields), union_type.size));
                }
            },
            _ => {}
        }
    }
    
    if struct_candidates.is_empty() {
        return Err(StructOffsetError::StructNotFound(struct_name.to_string()));
    }
    
    // Try each candidate, starting with the largest (most complete) one
    struct_candidates.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by size descending
    
    for (_type_idx, fields_opt, _size) in struct_candidates {
        if let Some(fields_type_index) = fields_opt {
            // Try to find the member in this struct definition
            match find_member_in_field_list(pdb_data, fields_type_index, member_name) {
                Ok(offset) => return Ok(offset),
                Err(_) => continue, // Try next candidate
            }
        }
    }
    
    Err(StructOffsetError::MemberNotFound(struct_name.to_string(), member_name.to_string()))
}

/// Search through all types to find the field list and extract the member offset
fn find_member_in_field_list(
    pdb_data: &mut PDB<std::io::Cursor<Vec<u8>>>,
    target_fields_index: pdb::TypeIndex,
    member_name: &str,
) -> Result<u64, StructOffsetError> {
    let type_information = pdb_data.type_information()?;
    let mut iter = type_information.iter();
    
    while let Some(typ) = iter.next()? {
        let current_index = typ.index();
        
        // Check if this is the field list we're looking for
        if current_index == target_fields_index {
            match typ.parse() {
                Ok(pdb::TypeData::FieldList(field_list)) => {
                    // Search through all fields for the target member
                    for field in field_list.fields {
                        match field {
                            pdb::TypeData::Member(member) => {
                                let field_name = member.name.to_string();
                                if field_name == member_name {
                                    return Ok(member.offset as u64);
                                }
                            },
                            _ => {
                                // Skip non-member fields (methods, base classes, etc.)
                            }
                        }
                    }
                    
                    // Field list found but member not in it
                    return Err(StructOffsetError::MemberNotFound("".to_string(), member_name.to_string()));
                },
                Ok(_other_type) => {
                    return Err(StructOffsetError::FieldParseError(
                        format!("TypeIndex {} is not a FieldList", current_index.0)
                    ));
                },
                Err(e) => {
                    return Err(StructOffsetError::FieldParseError(
                        format!("Failed to parse TypeIndex {}: {}", current_index.0, e)
                    ));
                }
            }
        }
    }
    
    Err(StructOffsetError::FieldParseError(
        format!("Could not find field list TypeIndex {} in type stream", target_fields_index.0)
    ))
}

