use std::ffi::CString;
use std::ptr::null_mut;

use winapi::ctypes::c_void; // <- use this c_void
use winapi::shared::ntdef::HANDLE;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winnt::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, GENERIC_READ, GENERIC_WRITE,
};
use winapi::um::ioapiset::DeviceIoControl;

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
            println!("[+] Opened handle to device");
            Ok(h_device)
        }
    }
}

/// Sends an IOCTL to the driver
/// `output_buffer` is a raw pointer to the memory you want the driver to write to
pub unsafe fn send_ioctl_to_driver(
    h_device: HANDLE,
    input_value: u64,
    output_buffer: *mut c_void, // <- must be winapi::ctypes::c_void
    size: u32,
) -> bool {
    let mut bytes_returned: u32 = 0;

    let success = DeviceIoControl(
        h_device,
        0xCF532017,
        &input_value as *const u64 as *mut c_void, // cast input properly
        size,
        output_buffer,
        size,
        &mut bytes_returned,
        null_mut(), // no overlapped
    );

    success != 0
}

