use std::{thread, time, process};
use std::io::{self};

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::winnt::ADMINISTRATOR_POWER_POLICY;

mod utils;
mod pdb_utils;
mod driver_utils;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] =-=-=- WinDbgX Kernel Debugger -=-=-=");
    // Sleeping...
    //   - TKTK: do custom sleep that checks for PPID and/or checks for a specific cadence
    println!("[*] Waiting for the opportune moment...\n");
    let bo_do_bleep = time::Duration::from_millis(100);
    thread::sleep(bo_do_bleep);


    // -=-= Doing setup =-=- //

    // Get the Windows version
    println!("[>] Setting up the environment...");
    let version = utils::get_windows_version_simple();
    println!("[|] Detected OS: {}", version);

    // Get symbol files
    let ntos: String = "C:\\Windows\\System32\\ntoskrnl.exe".to_string();
    let fltmgr: String = "C:\\Windows\\System32\\drivers\\fltmgr.sys".to_string();
    
    let nt_url = match pdb_utils::pdb_symbol_url(ntos) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[!] Failed to get PDB URL for NTOS: {}", e);
            std::process::exit(1);
        }
    };
    let fltmgr_url = match pdb_utils::pdb_symbol_url(fltmgr) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[!] Failed to get PDB URL for FLTMGR: {}", e);
            std::process::exit(1);
        }
    };

    println!("[>] Symbols download URLs:");
    println!("[|]   {}", nt_url);
    println!("[|]   {}", fltmgr_url);
    
    // Download symbol files
    let mut nt_pdb = utils::download_pdb(&nt_url)?;
    let mut fm_pdb = utils::download_pdb(&fltmgr_url)?;

    // Parse symbol files for offsets
    match pdb_utils::get_nt_offsets(&mut nt_pdb) {
        Ok(nt_offsets) => {}
        Err(e) => {
            eprintln!("[-] Failed to parse NT offsets: {}", e);
            process::exit(-1);
        }
    }

    // Get a handle to the driver
    driver_utils::get_driver_handle();

    let drivers = ["ntoskrnl.exe", "fltmgr.sys"];

    for drv in &drivers {
        match driver_utils::get_driver_base(drv) {
            Some(base) => println!("[+] {} base address: {:?}", drv, base),
            None => println!("[-] Could not find {}", drv),
        }
    }

    // -=-= TESTING: Checking the module base address for driver name + if matching EDR
    let mut addr: u64 = 0xfffff807200581e0;
    if let Some(driver_name) = driver_utils::find_driver_name_from_addr(addr) {
        let mut is_edr: bool = driver_utils::is_driver_name_matching_edr(&driver_name);
        println!("[*] Address 0x{:016x}: {} [EDR? {}]", addr, driver_name, is_edr);   
    }

    // =-=- TESTING: Check the loaded DLLs in a process
    let mut target_pid: DWORD = 11212;
    if utils::is_edr_dll_loaded(target_pid) {
        println!("[*] EDR DLL detected in process {}", target_pid);
    } else {
        println!("[-] No suspicious EDR DLLs found in process {}", target_pid);
    }


    // Remove Process Creation Notification callback




    println!("");
    Ok(())
}

