use super::platform::{Platform, ProcessInfo, SystemInfo, PlatformType};
use std::path::Path;
use std::fs;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

pub struct LinuxPlatform;

impl LinuxPlatform {
    pub fn new() -> Self {
        LinuxPlatform
    }
}

#[cfg(unix)]
impl Platform for LinuxPlatform {
    fn platform_name(&self) -> &'static str {
        "Linux"
    }
    
    fn file_lock_check(&self, path: &Path) -> bool {
        if let Ok(content) = fs::read_to_string("/proc/locks") {
            let inode = match path.metadata() {
                Ok(meta) => meta.ino(),
                Err(_) => return false,
            };
            
            content.lines().any(|line| {
                line.contains(&inode.to_string())
            })
        } else {
            false
        }
    }
    
    fn get_process_list(&self) -> Vec<ProcessInfo> {
        let mut processes = Vec::new();
        
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = entry.file_name().to_string_lossy().to_string();
                if let Ok(pid) = pid_str.parse::<u32>() {
                    if let Some(info) = self.get_process_info(pid) {
                        processes.push(info);
                    }
                }
            }
        }
        
        processes
    }
    
    fn terminate_process(&self, pid: u32) -> bool {
        use std::process::Command;
        
        Command::new("kill")
            .arg("-9")
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
    
    fn get_network_drives(&self) -> Vec<String> {
        let mut drives = Vec::new();
        
        if let Ok(content) = fs::read_to_string("/proc/mounts") {
            for line in content.lines() {
                if line.contains("nfs") || line.contains("cifs") || line.contains("smb") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        drives.push(parts[1].to_string());
                    }
                }
            }
        }
        
        drives
    }
    
    fn is_virtual_machine(&self) -> bool {
        let vm_indicators = vec![
            "vmware",
            "virtualbox",
            "qemu",
            "xen",
            "kvm",
        ];
        
        if let Ok(content) = fs::read_to_string("/proc/cpuinfo") {
            return vm_indicators.iter().any(|indicator| {
                content.to_lowercase().contains(indicator)
            });
        }
        
        if let Ok(content) = fs::read_to_string("/sys/class/dmi/id/product_name") {
            return vm_indicators.iter().any(|indicator| {
                content.to_lowercase().contains(indicator)
            });
        }
        
        false
    }
    
    fn get_system_info(&self) -> SystemInfo {
        let os_name = fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                content.lines()
                    .find(|line| line.starts_with("PRETTY_NAME="))
                    .and_then(|line| {
                        line.split('=')
                            .nth(1)
                            .map(|s| s.trim_matches('"').to_string())
                    })
            })
            .unwrap_or_else(|| "Linux".to_string());
        
        let hostname = fs::read_to_string("/etc/hostname")
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        
        let total_memory = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content.lines()
                    .find(|line| line.starts_with("MemTotal:"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u64>().ok())
                    })
            })
            .unwrap_or(0) * 1024;
        
        let available_memory = fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content.lines()
                    .find(|line| line.starts_with("MemAvailable:"))
                    .and_then(|line| {
                        line.split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u64>().ok())
                    })
            })
            .unwrap_or(0) * 1024;
        
        SystemInfo {
            os_name,
            os_version: "Unknown".to_string(),
            hostname,
            cpu_cores,
            total_memory,
            available_memory,
            platform_type: PlatformType::Linux,
        }
    }
    
    fn disable_antivirus(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn enable_antivirus(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn create_snapshot(&self, path: &Path) -> Result<(), String> {
        use std::process::Command;
        
        let output = Command::new("btrfs")
            .args(["subvolume", "snapshot", path.to_str().unwrap(), 
                   &format!("{}.snapshot", path.display())])
            .output();
        
        match output {
            Ok(result) if result.status.success() => Ok(()),
            Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn restore_snapshot(&self, path: &Path) -> Result<(), String> {
        use std::process::Command;
        
        let snapshot_path = format!("{}.snapshot", path.display());
        
        let output = Command::new("btrfs")
            .args(["subvolume", "snapshot", &snapshot_path, path.to_str().unwrap()])
            .output();
        
        match output {
            Ok(result) if result.status.success() => Ok(()),
            Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn delete_all_snapshots(&self) -> Result<(), String> {
        println!("[Linux] Deleting all btrfs snapshots...");
        
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
                        println!("[Linux] Deleting btrfs snapshot: {}", snapshot_path);
                        
                        let delete_result = Command::new("btrfs")
                            .args(["subvolume", "delete", snapshot_path])
                            .output();
                        
                        match delete_result {
                            Ok(res) if res.status.success() => {
                                println!("[Linux] Successfully deleted snapshot {}", snapshot_path);
                                deleted_count += 1;
                            }
                            Ok(res) => {
                                eprintln!("[Linux] Failed to delete snapshot {}: {}", 
                                    snapshot_path, String::from_utf8_lossy(&res.stderr));
                            }
                            Err(e) => {
                                eprintln!("[Linux] Error deleting snapshot {}: {}", snapshot_path, e);
                            }
                        }
                    }
                }
                
                println!("[Linux] Deleted {} btrfs snapshots", deleted_count);
                Ok(())
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                if stderr.contains("not a btrfs filesystem") || stderr.contains("ERROR") {
                    println!("[Linux] No btrfs filesystem found, skipping snapshot deletion");
                    Ok(())
                } else {
                    Err(stderr.to_string())
                }
            }
            Err(e) => {
                println!("[Linux] btrfs command not available, skipping snapshot deletion");
                Ok(())
            }
        }
    }
}

impl LinuxPlatform {
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        let proc_path = format!("/proc/{}", pid);
        
        let name = fs::read_to_string(format!("{}/comm", proc_path))
            .ok()
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let path = fs::read_link(format!("{}/exe", proc_path))
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| "unknown".to_string());
        
        let handles = Vec::new();
        
        Some(ProcessInfo {
            pid,
            name,
            path,
            handles,
        })
    }
}
