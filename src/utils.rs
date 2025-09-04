use std::ffi::{CString, OsString};
use std::os::windows::ffi::OsStringExt;
use std::io::Cursor;
use std::process;
use winapi::shared::minwindef::DWORD;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::sysinfoapi::GetVersionExA;
use winapi::um::winnt::{OSVERSIONINFOA, VER_PLATFORM_WIN32_NT}; 
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE,
};
use reqwest::blocking::get;
use pdb::PDB;


/// Checks Windows version and IORING support
/// 
/// Returns:
/// - `true` if Windows supports IORINGs (Windows 11+)
/// - `false` if Windows 8+ but no IORING support
/// - Exits the program if Windows 7 or earlier
pub fn version_check_and_do_we_have_ioring() -> bool {
    // First check if we're on Windows 7 or earlier and exit if so
    check_minimum_version();
    
    // Then check for IORING support
    check_ioring_support()
}

/// Checks if the system meets minimum version requirements (Windows 8+)
/// Exits the program if running on Windows 7 or earlier
fn check_minimum_version() {
    unsafe {
        let mut version_info: OSVERSIONINFOA = std::mem::zeroed();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOA>() as u32;
        
        if GetVersionExA(&mut version_info) == 0 {
            eprintln!("[-] Error: Failed to get Windows version information");
            process::exit(1);
        }
        
        // Check if we're on Windows NT platform
        if version_info.dwPlatformId != VER_PLATFORM_WIN32_NT {
            eprintln!("[-] Error: This program requires Windows NT-based operating system");
            process::exit(1);
        }
        
        // Windows version numbers:
        // Windows 7: 6.1
        // Windows 8: 6.2
        // Windows 8.1: 6.3
        // Windows 10: 10.0 (but may report as 6.2/6.3 due to compatibility)
        // Windows 11: 10.0 (build 22000+)
        
        let major = version_info.dwMajorVersion;
        let minor = version_info.dwMinorVersion;
        
        // Check for Windows 7 or earlier (version 6.1 or lower)
        if major < 6 || (major == 6 && minor <= 1) {
            eprintln!("[-] Error: This program requires Windows 8 or newer. Current version: {}.{}", major, minor);
            eprintln!("[!] Windows 7 and earlier are not supported. Exiting for safety.");
            process::exit(1);
        }
        
        println!("[+] Windows version check passed (newer than Windows 7): {}.{}", major, minor);
    }
}

/// Checks if the CreateIoRing function is available
/// Returns true if IORINGs are supported, false otherwise
fn check_ioring_support() -> bool {
    unsafe {
        // Try to load the API Set library for IoRing
        let api_ms_win_core_ioring = CString::new("api-ms-win-core-ioring-l1-1-0.dll").unwrap();
        let module_handle = GetModuleHandleA(api_ms_win_core_ioring.as_ptr());
        
        if module_handle.is_null() {
            // If the API Set isn't loaded, try to load kernel32.dll
            let kernel32 = CString::new("kernel32.dll").unwrap();
            let kernel32_handle = GetModuleHandleA(kernel32.as_ptr());
            
            if kernel32_handle.is_null() {
                println!("[-] Warning: Could not get handle to kernel32.dll");
                return false;
            }
            
            // Check for CreateIoRing in kernel32
            let create_ioring = CString::new("CreateIoRing").unwrap();
            let proc_address = GetProcAddress(kernel32_handle, create_ioring.as_ptr());
            
            if proc_address.is_null() {
                println!("[*] IORINGs not supported: Leveraging Modus Previosa technique for read/write...");
                return false;
            } else {
                println!("[*] IORINGs supported: Using IORINGs for read/write...");
                return true;
            }
        } else {
            // API Set is available, check for the function
            let create_ioring = CString::new("CreateIoRing").unwrap();
            let proc_address = GetProcAddress(module_handle, create_ioring.as_ptr());
            
            if proc_address.is_null() {
                println!("[*] IORINGs not supported: Leveraging Modus Previosa technique for read/write...");
                return false;
            } else {
                println!("[*] IORINGs supported: Using IORINGs for read/write...");
                return true;
            }
        }
    }
}


/// Downloads the appropriate symbol file from the URL and returns a PDB handle
pub fn download_pdb(url: &str) ->Result<PDB<'_, Cursor<Vec<u8>>>, Box<dyn std::error::Error>> {
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



