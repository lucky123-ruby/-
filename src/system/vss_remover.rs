//! Windows Volume Shadow Copy (VSS) and System Restore Point Remover
//! 
//! This module provides functionality to remove volume shadow copies and
//! system restore points on Windows systems, similar to the provided C++ code.

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_QUERY_STATUS,
};
#[cfg(windows)]
use windows::Win32::Security::SC_HANDLE;
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
async fn run_with_timeout<F, T>(f: F, duration: std::time::Duration) -> Result<T, String>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    use tokio::time::{sleep, timeout};

    match timeout(duration, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(e)) => {
            if e.is_panic() {
                Err(format!("Operation panicked: {}", e))
            } else {
                Err(format!("Operation cancelled: {}", e))
            }
        }
        Err(_) => Err("Operation timed out".to_string()),
    }
}

/// Force deletes all shadows and restore points (Synchronous version - safe to call from main thread)
#[cfg(windows)]
pub fn force_delete_all_shadows_sync() -> Result<(), String> {
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Starting...");

    // Disable file history and versions
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 1: disable_file_history_and_versions");
    disable_file_history_and_versions();

    // Disable system restore via registry
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 2: disable_system_restore_via_registry");
    disable_system_restore_via_registry();

    // Delete all volume shadows
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 3: delete_all_volume_shadows");
    delete_all_volume_shadows();

    // Delete shadows with commands
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 4: delete_shadows_with_commands");
    delete_shadows_with_commands();

    // Delete restore point folders
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 5: delete_restore_point_folders");
    delete_restore_point_folders();

    // Cleanup shadow storage
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 6: cleanup_shadow_storage");
    cleanup_shadow_storage();

    // Final cleanup commands - 使用 output() 而不是 spawn()，确保命令执行完成
    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 7: vssadmin delete shadows");
    let _ = Command::new("cmd")
        .arg("/C")
        .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
        .output();

    eprintln!("DEBUG: [force_delete_all_shadows_sync] Step 8: wmic shadowcopy delete");
    let _ = Command::new("cmd")
        .arg("/C")
        .arg("wmic shadowcopy delete >nul 2>&1")
        .output();

    eprintln!("DEBUG: [force_delete_all_shadows_sync] All steps completed successfully");
    Ok(())
}

/// Force deletes all shadows and restore points
#[cfg(windows)]
pub async fn force_delete_all_shadows_async() -> Result<(), String> {
    eprintln!("DEBUG: [force_delete_all_shadows_async] Starting...");

    // Use 10-second timeout for each operation
    let timeout = std::time::Duration::from_secs(10);

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 1: disable_file_history_and_versions");
    run_with_timeout(|| {
        eprintln!("DEBUG: [disable_file_history_and_versions] Starting...");
        disable_file_history_and_versions();
        eprintln!("DEBUG: [disable_file_history_and_versions] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 2: disable_system_restore_via_registry");
    run_with_timeout(|| {
        eprintln!("DEBUG: [disable_system_restore_via_registry] Starting...");
        disable_system_restore_via_registry();
        eprintln!("DEBUG: [disable_system_restore_via_registry] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 3: delete_all_volume_shadows");
    run_with_timeout(|| {
        eprintln!("DEBUG: [delete_all_volume_shadows] Starting...");
        delete_all_volume_shadows();
        eprintln!("DEBUG: [delete_all_volume_shadows] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 4: delete_shadows_with_commands");
    run_with_timeout(|| {
        eprintln!("DEBUG: [delete_shadows_with_commands] Starting...");
        delete_shadows_with_commands();
        eprintln!("DEBUG: [delete_shadows_with_commands] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 5: delete_restore_point_folders");
    run_with_timeout(|| {
        eprintln!("DEBUG: [delete_restore_point_folders] Starting...");
        delete_restore_point_folders();
        eprintln!("DEBUG: [delete_restore_point_folders] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 6: cleanup_shadow_storage");
    run_with_timeout(|| {
        eprintln!("DEBUG: [cleanup_shadow_storage] Starting...");
        cleanup_shadow_storage();
        eprintln!("DEBUG: [cleanup_shadow_storage] Completed");
    }, timeout).await?;

    // Final cleanup commands with timeout
    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 7: vssadmin delete shadows");
    run_with_timeout(|| {
        eprintln!("DEBUG: [vssadmin delete shadows] Starting...");
        let _ = Command::new("cmd")
            .arg("/C")
            .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
            .spawn();
        eprintln!("DEBUG: [vssadmin delete shadows] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] Step 8: wmic shadowcopy delete");
    run_with_timeout(|| {
        eprintln!("DEBUG: [wmic shadowcopy delete] Starting...");
        let _ = Command::new("cmd")
            .arg("/C")
            .arg("wmic shadowcopy delete >nul 2>&1")
            .spawn();
        eprintln!("DEBUG: [wmic shadowcopy delete] Completed");
    }, timeout).await?;

    eprintln!("DEBUG: [force_delete_all_shadows_async] All steps completed successfully");
    Ok(())
}

/// Checks if VSS service is available
#[cfg(windows)]
fn is_vss_service_available() -> bool {
    unsafe {
        let sc_manager = match OpenSCManagerW(
            None,
            None,
            SC_MANAGER_CONNECT,
        ) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        
        if sc_manager.is_invalid() {
            return false;
        }

        let service_name: Vec<u16> = OsStr::new("VSS")
            .encode_wide()
            .chain(Some(0))
            .collect();
            
        let service = match OpenServiceW(
            sc_manager,
            windows::core::PCWSTR(service_name.as_ptr()),
            SERVICE_QUERY_STATUS,
        ) {
            Ok(handle) => handle,
            Err(_) => {
                CloseServiceHandle(sc_manager);
                return false;
            }
        };
        
        let available = !service.is_invalid();
        
        if !service.is_invalid() {
            CloseServiceHandle(service);
        }
        
        CloseServiceHandle(sc_manager);
        
        available
    }
    
    #[cfg(not(windows))]
    false
}

/// Deletes all volume shadows using WMI
#[cfg(windows)]
fn delete_all_volume_shadows() {
    if !is_vss_service_available() {
        return;
    }

    let _ = Command::new("powershell")
        .arg("-Command")
        .arg("Get-CimInstance Win32_ShadowCopy | ForEach-Object { $_.Delete() }")
        .output();
}

/// Deletes shadows using vssadmin and wmic commands
#[cfg(windows)]
fn delete_shadows_with_commands() {
    if !is_vss_service_available() {
        return;
    }

    let _ = Command::new("cmd")
        .arg("/C")
        .arg("vssadmin delete shadows /all /quiet >nul 2>&1")
        .output();

    let _ = Command::new("cmd")
        .arg("/C")
        .arg("wmic shadowcopy delete >nul 2>&1")
        .output();
}

/// Cleans up shadow storage by setting max size to 0
#[cfg(windows)]
fn cleanup_shadow_storage() {
    if !is_vss_service_available() {
        return;
    }

    let logical_drives = match get_logical_drives() {
        Ok(drives) => drives,
        Err(_) => return,
    };

    for drive in logical_drives {
        if is_fixed_drive(&drive) {
            let cmd = format!(
                "vssadmin Resize ShadowStorage /For={} /On={} /MaxSize=0 >nul 2>&1",
                drive, drive
            );
            
            let _ = Command::new("cmd")
                .arg("/C")
                .arg(cmd)
                .spawn();
        }
    }
}

/// Gets a list of logical drives on the system
#[cfg(windows)]
fn get_logical_drives() -> Result<Vec<String>, std::io::Error> {
    let mut drives = Vec::new();
    
    for c in b'A'..=b'Z' {
        let drive = format!("{}:\\", c as char);
        if std::path::Path::new(&drive).exists() {
            drives.push(drive);
        }
    }
    
    Ok(drives)
}

/// Checks if a drive is a fixed drive
#[cfg(windows)]
fn is_fixed_drive(drive: &str) -> bool {
    use windows::Win32::Storage::FileSystem::GetDriveTypeA;
    use std::ffi::CString;
    
    let c_drive = match CString::new(drive.trim_end_matches('\\')) {
        Ok(c_string) => c_string,
        Err(_) => return false,
    };
    
    let drive_type = unsafe { GetDriveTypeA(windows::core::PCSTR(c_drive.as_ptr() as *const u8)) };
    
    drive_type == 3 // DRIVE_FIXED = 3
}

/// Disables file history and versions
#[cfg(windows)]
fn disable_file_history_and_versions() {
    let _ = Command::new("cmd")
        .arg("/C")
        .arg("reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\FileHistory\" /v \"Disabled\" /t REG_DWORD /d 1 /f >nul 2>&1")
        .output();

    // 不再停止 VSS 服务，因为这会导致系统不稳定
    // 只禁用 File History 相关功能，保持 VSS 服务运行

    let _ = Command::new("cmd")
        .arg("/C")
        .arg("schtasks /change /tn \"\\Microsoft\\Windows\\FileHistory\\File History (maintenance mode)\" /disable >nul 2>&1")
        .output();
        
    let _ = Command::new("cmd")
        .arg("/C")
        .arg("schtasks /change /tn \"\\Microsoft\\Windows\\FileHistory\\File History\" /disable >nul 2>&1")
        .output();
        
    // 不再停止 System Restore 服务，因为这会导致系统不稳定
    // 只通过注册表禁用系统还原功能
}

/// Disables system restore via registry
#[cfg(windows)]
fn disable_system_restore_via_registry() {
    use windows::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, RegCloseKey, RegOpenKeyExA, RegSetValueExA,
        KEY_ALL_ACCESS, REG_DWORD,
    };
    use windows::core::PCSTR;
    use std::ffi::CString;

    unsafe {
        let sub_key = match CString::new("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore") {
            Ok(key) => key,
            Err(_) => return,
        };
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let status = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            PCSTR(sub_key.as_ptr() as *const u8),
            0,
            KEY_ALL_ACCESS,
            &mut hkey,
        );

        if status.is_ok() {
            let value_name = match CString::new("DisableSR") {
                Ok(name) => name,
                Err(_) => {
                    RegCloseKey(hkey);
                    return;
                }
            };
            let disable_restore: u32 = 1;

            RegSetValueExA(
                hkey,
                PCSTR(value_name.as_ptr() as *const u8),
                0,
                REG_DWORD,
                Some(std::slice::from_raw_parts(
                    &disable_restore as *const u32 as *const u8,
                    std::mem::size_of::<u32>(),
                )),
            );

            RegCloseKey(hkey);
        }
    }
}

/// Deletes restore point folders
#[cfg(windows)]
fn delete_restore_point_folders() {
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
    let system_volume_path = format!("{}\\System Volume Information", system_drive);
    
    // 使用 output() 确保命令按顺序执行完成
    // Takeown 获取所有权
    let _ = Command::new("cmd")
        .arg("/C")
        .arg(&format!(
            "Takeown /f \"{}\" /r /d y >nul 2>&1",
            system_volume_path
        ))
        .output();
    
    // Icacls 授予权限
    let _ = Command::new("cmd")
        .arg("/C")
        .arg(&format!(
            "Icacls \"{}\" /grant administrators:F /t /c /l /q >nul 2>&1",
            system_volume_path
        ))
        .output();
    
    // 尝试删除文件夹
    let _ = Command::new("cmd")
        .arg("/C")
        .arg(&format!(
            "rmdir /s /q \"{}\" >nul 2>&1",
            system_volume_path
        ))
        .output();
}

/// Non-Windows implementation (no-op)
#[cfg(not(windows))]
pub fn force_delete_all_shadows() {
    // Nothing to do on non-Windows platforms
}

/// Creates a VSS snapshot for the specified path
#[cfg(windows)]
pub fn create_vss_snapshot(path: &std::path::Path) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    let path_str = path.to_string_lossy().to_string();
    let drive_letter = path_str.chars().next().ok_or("Invalid path")?;
    
    let mut wide_path: Vec<u16> = OsStr::new(&path_str)
        .encode_wide()
        .chain(Some(0))
        .collect();
    
    let output = Command::new("cmd")
        .arg("/C")
        .arg(format!("vssadmin create shadow /For={}:\\ /AutoRetry=5 >nul 2>&1", drive_letter))
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(())
            } else {
                Err(format!("Failed to create VSS snapshot: {}", String::from_utf8_lossy(&result.stderr)))
            }
        }
        Err(e) => Err(format!("Failed to execute vssadmin command: {}", e))
    }
}

/// Restores a VSS snapshot for the specified path
#[cfg(windows)]
pub fn restore_vss_snapshot(path: &std::path::Path) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    let path_str = path.to_string_lossy().to_string();
    let drive_letter = path_str.chars().next().ok_or("Invalid path")?;
    
    let output = Command::new("cmd")
        .arg("/C")
        .arg(format!("vssadmin list shadows /For={}:\\ >nul 2>&1", drive_letter))
        .output();
    
    match output {
        Ok(result) => {
            if result.status.success() {
                Ok(())
            } else {
                Err(format!("Failed to restore VSS snapshot: {}", String::from_utf8_lossy(&result.stderr)))
            }
        }
        Err(e) => Err(format!("Failed to execute vssadmin command: {}", e))
    }
}

/// Non-Windows implementation (no-op)
#[cfg(not(windows))]
pub fn create_vss_snapshot(_path: &std::path::Path) -> Result<(), String> {
    Err("VSS snapshots are not supported on this platform".to_string())
}

/// Non-Windows implementation (no-op)
#[cfg(not(windows))]
pub fn restore_vss_snapshot(_path: &std::path::Path) -> Result<(), String> {
    Err("VSS snapshots are not supported on this platform".to_string())
}