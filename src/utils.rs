use windows::Win32::System::SystemInformation::GetVersion;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE,
};
use winapi::shared::minwindef::{DWORD};     // Can also use LPVOID

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt; 
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use reqwest::blocking::get;
use std::io::Cursor;
use pdb::PDB;


pub fn get_windows_version_simple() -> &'static str {
    unsafe {
        let ver = GetVersion();
        let major = (ver & 0xFF) as u32;
        let minor = ((ver >> 8) & 0xFF) as u32;

        match (major, minor) {
            (10, 0) => "Windows 10/11 or Server 2016/2019",
            (6, 3) => "Windows 8.1 / Server 2012 R2",
            (6, 2) => "Windows 8 / Server 2012",
            (6, 1) => "Windows 7 / Server 2008 R2",
            (6, 0) => "Windows Vista / Server 2008",
            _ => "Unknown Windows version",
        }
    }
}

pub fn download_pdb(url: &str) -> Result<PDB<Cursor<Vec<u8>>>, Box<dyn std::error::Error>> {
    // Download the bytes into memory
    let response = get(url)?;
    if !response.status().is_success() {
        return Err(format!("[!] Failed to download PDB, status: {}", response.status()).into());
    }

    let bytes = response.bytes()?.to_vec();

    // Wrap in a cursor so it acts like a file
    let cursor = Cursor::new(bytes);

    // Open the PDB directly from memory
    let pdb = PDB::open(cursor)?;

    Ok(pdb)
}

/// Check if any suspicious EDR DLL is loaded in the given process.
pub fn is_edr_dll_loaded(proc_id: DWORD) -> bool {
    unsafe {
        let h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, proc_id);
        if h_snapshot == INVALID_HANDLE_VALUE {
            eprintln!("[-] Invalid handle! Could not create snapshot to check if DLL is loaded.");
            return false;
        }

        // DLL prefixes to check (wide strings)
        let dll_prefixes: [&[u16]; 6] = [
            &['u' as u16, 'm' as u16, 'p' as u16, 'p' as u16, 'c' as u16], // CrowdStrike: umppc18721.dll
            &['c' as u16, 'y' as u16, 'i' as u16, 'n' as u16, 'j' as u16],
            &['c' as u16, 'y' as u16, 'v' as u16, 'e' as u16, 'r' as u16],
            &['c' as u16, 'y' as u16, 'v' as u16, 'r' as u16, 't' as u16],
            &['E' as u16, 'd' as u16, 'r' as u16, 'D' as u16, 'o' as u16],
            &['I' as u16, 'n' as u16, 'P' as u16, 'r' as u16, 'o' as u16], // SentinelOne
        ];

        let mut me32: MODULEENTRY32W = std::mem::zeroed();
        me32.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

        if Module32FirstW(h_snapshot, &mut me32) != 0 {
            loop {
                // Convert module name to Rust String
                let name_wide = &me32.szModule;
                let len = name_wide.iter().position(|&c| c == 0).unwrap_or(name_wide.len());
                let module_name =
                    OsString::from_wide(&name_wide[..len]).to_string_lossy().to_string();

                // Check each DLL prefix
                for prefix in &dll_prefixes {
                    let prefix_str = OsString::from_wide(prefix).to_string_lossy().to_string();
                    if module_name.len() >= 5
                        && module_name[..5].eq_ignore_ascii_case(&prefix_str)
                    {
                        return true;
                    }
                }

                if Module32NextW(h_snapshot, &mut me32) == 0 {
                    break;
                }
            }
        }

        false
    }
}



