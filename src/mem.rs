use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::Foundation::{HANDLE, NTSTATUS};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use std::ffi::CString;
use windows::core::PCSTR;

/* 
type NtWriteVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut std::ffi::c_void,
    Buffer: *const std::ffi::c_void,
    NumberOfBytesToWrite: usize,
    NumberOfBytesWritten: *mut usize,
) -> NTSTATUS;
*/

pub unsafe fn resolve_nt_write_virtual_memory() -> Option<
    unsafe extern "system" fn(
        process_handle: HANDLE,
        base_address: *mut core::ffi::c_void,
        buffer: *const core::ffi::c_void,
        number_of_bytes_to_write: usize,
        number_of_bytes_written: *mut usize,
    ) -> NTSTATUS,
> {
    // Convert Rust strings into proper null-terminated C strings
    let dll_name = CString::new("ntdll.dll").unwrap();
    let func_name = CString::new("NtWriteVirtualMemory").unwrap();

    // Handle the Result<HMODULE, Error>
    let ntdll = match GetModuleHandleA(PCSTR(dll_name.as_ptr() as *const u8)) {
        Ok(h) => h,
        Err(_) => return None,
    };

    // Pass the raw HMODULE into GetProcAddress
    let proc = GetProcAddress(ntdll, PCSTR(func_name.as_ptr() as *const u8));
    if proc.is_none() {
        return None;
    }

    Some(std::mem::transmute(proc.unwrap()))
}

pub fn read_qword(address: u64) -> windows::core::Result<u64> {
    let mut buffer: u64 = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const _,
            &mut buffer as *mut _ as *mut _,
            std::mem::size_of::<u64>(),
            None,
        )?;
    }

    Ok(buffer)
}

pub fn read_dword(address: u64) -> windows::core::Result<u32> {
    let mut buffer: u32 = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const _,
            &mut buffer as *mut _ as *mut _,
            std::mem::size_of::<u32>(),
            None,
        )?;
    }

    Ok(buffer)
}

/* 
pub fn read_word(address: u64) -> windows::core::Result<u16> {
    let mut buffer: u16 = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const _,
            &mut buffer as *mut _ as *mut _,
            std::mem::size_of::<u16>(),
            None,
        )?;
    }

    Ok(buffer)
}

pub fn read_byte(address: u64) -> windows::core::Result<u8> {
    let mut buffer: u8 = 0;

    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const _,
            &mut buffer as *mut _ as *mut _,
            std::mem::size_of::<u8>(),
            None,
        )?;
    }

    Ok(buffer)
}
*/

pub fn write_qword(address: u64, value: u64) {
    unsafe {
        // Resolve the function
        let nt_write = resolve_nt_write_virtual_memory().expect("Failed to resolve NtWriteVirtualMemory");
                // Call the function
        let mut bytes_written: usize = 0;
        let _ = nt_write(
            GetCurrentProcess(),
            address as *mut core::ffi::c_void,
            &value as *const u64 as *const core::ffi::c_void,
            std::mem::size_of::<u64>(),
            &mut bytes_written as *mut usize,
        );
    }
}

pub fn write_dword(address: u64, value: u32) {
    unsafe {
        // Resolve the function
        let nt_write = resolve_nt_write_virtual_memory().expect("Failed to resolve NtWriteVirtualMemory");
                // Call the function
        let mut bytes_written: usize = 0;
        let _ = nt_write(
            GetCurrentProcess(),
            address as *mut core::ffi::c_void,
            &value as *const u32 as *const core::ffi::c_void,
            std::mem::size_of::<u64>(),
            &mut bytes_written as *mut usize,
        );
    }
}

/* 
pub fn write_word(address: u64, value: u16) {
    unsafe {
        // Resolve the function
        let nt_write = resolve_nt_write_virtual_memory().expect("Failed to resolve NtWriteVirtualMemory");
                // Call the function
        let mut bytes_written: usize = 0;
        nt_write(
            GetCurrentProcess(),
            address as *mut core::ffi::c_void,
            &value as *const u16 as *const core::ffi::c_void,
            std::mem::size_of::<u64>(),
            &mut bytes_written as *mut usize,
        );
    }
}
*/

pub fn write_byte(address: u64, value: u8) {
    unsafe {
        // Resolve the function
        let nt_write = resolve_nt_write_virtual_memory().expect("Failed to resolve NtWriteVirtualMemory");
                // Call the function
        let mut bytes_written: usize = 0;
        let _ = nt_write(
            GetCurrentProcess(),
            address as *mut core::ffi::c_void,
            &value as *const u8 as *const core::ffi::c_void,
            std::mem::size_of::<u64>(),
            &mut bytes_written as *mut usize,
        );
    }
}

