use std::fs::File;
use std::path::Path;
use std::collections::HashSet;
use std::io::{self, Cursor, Read};
use std::process;

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
    pub psp_create_process_notify_routine: u64,
    pub psp_create_thread_notify_routine: u64,
    pub psp_load_image_notify_routine: u64,
    pub etw_threat_int_prov_reg_handle: u64,
    pub ps_process_type: u64,
    pub ps_thread_type: u64,
    pub se_ci_callbacks: u64,
}


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
                        "EtwThreatIntProvRegHandle" => offsets.etw_threat_int_prov_reg_handle = addr,
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

    println!(
        "[+] Found {} out of {} target symbols",
        found_symbols.len(),
        target_symbols.len()
    );

    for &target in &target_symbols {
        if !found_symbols.contains(target) {
            println!("[!] Missing symbol: {}", target);
        }
    }

    if &found_symbols.len() != &target_symbols.len() {
        println!("[!] PANIC! Not all symbols resolved. Exiting for safety. Check OS version and stuff...");
        process::exit(-1);
    }

    Ok(offsets)
}
