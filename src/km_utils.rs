use std::ffi::{OsString};
use std::os::windows::ffi::OsStringExt;

use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::psapi::{EnumDeviceDrivers, GetDeviceDriverBaseNameW};


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

