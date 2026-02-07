use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use std::process::{Child, Command};

#[cfg(target_os = "windows")]
use windows::core::{PWSTR, PCWSTR};
#[cfg(target_os = "windows")]
use windows::Win32::NetworkManagement::WNet::{
    WNetAddConnection2W, WNetCancelConnection2W, NETRESOURCEW, CONNECT_UPDATE_PROFILE, RESOURCETYPE_DISK,
};

#[cfg(not(target_os = "windows"))]
use std::process::Command;

const DRIVE_LETTERS: &[&str] = &["Z", "Y", "X", "W", "V", "U", "T", "S", "R", "Q", "P"];
static DRIVE_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn get_next_drive() -> Option<String> {
    let index = DRIVE_COUNTER.fetch_add(1, Ordering::Relaxed);
    if index < DRIVE_LETTERS.len() {
        Some(format!("{}:", DRIVE_LETTERS[index]))
    } else {
        None
    }
}

fn command_with_timeout(cmd: &mut Command, timeout: Duration) -> Result<std::process::Output, String> {
    let mut child = cmd.spawn()
        .map_err(|e| format!("Failed to spawn command: {}", e))?;
    
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                return child.wait_with_output()
                    .map_err(|e| format!("Failed to get output: {}", e));
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    child.kill().ok();
                    return Err("Command timeout".to_string());
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("Error waiting for child: {}", e)),
        }
    }
}

#[cfg(target_os = "windows")]
pub fn enumerate_shares(host: &str) -> Vec<String> {
    let mut shares = Vec::new();
    
    let host_path = format!(r"\\{}", host);
    let ps_script = format!(
        "Get-SmbShare -ComputerName '{}' | Where-Object {{ $_.Name -notlike '*$' }} | Select-Object -ExpandProperty Name",
        host
    );
    
    match command_with_timeout(Command::new("powershell").args(["-Command", &ps_script]), Duration::from_secs(5)) {
        Ok(output) => {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                
                for line in output_str.lines() {
                    let share_name = line.trim();
                    if !share_name.is_empty() && !share_name.starts_with('#') {
                        let share_path = format!(r"\\{}\{}", host, share_name);
                        shares.push(share_path);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[SMB] PowerShell enumeration timeout for {}: {}", host, e);
        }
    }
    
    if shares.is_empty() {
        match command_with_timeout(Command::new("cmd").args(["/C", "net", "view", &host_path]), Duration::from_secs(5)) {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    
                    for line in output_str.lines() {
                        let line = line.trim();
                        if !line.starts_with('-') && !line.starts_with("The command completed") {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.len() >= 1 {
                                let share_name = parts[0];
                                if !share_name.ends_with('$') && !share_name.is_empty() {
                                    let share_path = format!(r"\\{}\{}", host, share_name);
                                    if !shares.contains(&share_path) {
                                        shares.push(share_path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[SMB] net view timeout for {}: {}", host, e);
            }
        }
    }
    
    shares
}

#[cfg(not(target_os = "windows"))]
pub fn enumerate_shares(host: &str) -> Vec<String> {
    let mut shares = Vec::new();
    
    match command_with_timeout(Command::new("smbclient").args(["-L", host, "-N", "-U", "%"]), Duration::from_secs(5)) {
        Ok(output) => {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                
                for line in output_str.lines() {
                    let line = line.trim();
                    if line.starts_with("Disk") && !line.contains("$") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let share_name = parts[1];
                            if !share_name.is_empty() && !share_name.ends_with('$') {
                                let share_path = format!(r"\\{}\{}", host, share_name);
                                if !shares.contains(&share_path) {
                                    shares.push(share_path);
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("[SMB] smbclient timeout for {}: {}", host, e);
        }
    }
    
    if shares.is_empty() {
        match command_with_timeout(Command::new("nmblookup").args(["-S", host]), Duration::from_secs(5)) {
            Ok(output) => {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    
                    for line in output_str.lines() {
                        if line.contains("<20>") && (line.contains("SHARES") || line.contains("File Server Service")) {
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if !parts.is_empty() {
                                let share_name = parts[0];
                                let share_path = format!(r"\\{}\{}", host, share_name);
                                if !shares.contains(&share_path) {
                                    shares.push(share_path);
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("[SMB] nmblookup timeout for {}: {}", host, e);
            }
        }
    }
    
    if shares.is_empty() {
        let common_shares = ["public", "shared", "files", "data", "documents", "home"];
        for share_name in common_shares {
            let share_path = format!(r"\\{}\{}", host, share_name);
            if let Ok(_) = std::fs::metadata(&share_path.replace(r"\\", "/").replace("\\", "/")) {
                shares.push(share_path);
            }
        }
    }
    
    shares
}

#[cfg(target_os = "windows")]
pub fn map_network_drive(share_path: &str, drive_letter: &str) -> bool {
    let mut net_resource = NETRESOURCEW::default();
    
    let mut local_name: Vec<u16> = drive_letter
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut remote_name: Vec<u16> = share_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    
    net_resource.dwType = RESOURCETYPE_DISK;
    net_resource.lpLocalName = PWSTR(local_name.as_mut_ptr());
    net_resource.lpRemoteName = PWSTR(remote_name.as_mut_ptr());

    let start = Instant::now();
    
    unsafe {
        let result = WNetAddConnection2W(
            &net_resource,
            PCWSTR::null(),
            PCWSTR::null(),
            CONNECT_UPDATE_PROFILE.0,
        );

        if result.is_ok() {
            println!("[SMB] Mapped {} to {} in {:.2}s", share_path, drive_letter, start.elapsed().as_secs_f64());
            true
        } else {
            eprintln!("[SMB] Failed to map {} to {}: {:?}", share_path, drive_letter, result);
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn map_network_drive(_share_path: &str, _drive_letter: &str) -> bool {
    false
}

#[cfg(target_os = "windows")]
pub fn unmap_network_drive(drive_letter: &str) -> bool {
    let drive_wide: Vec<u16> = drive_letter.encode_utf16().chain(Some(0)).collect();

    unsafe {
        let result = WNetCancelConnection2W(PCWSTR(drive_wide.as_ptr()), CONNECT_UPDATE_PROFILE.0, true);
        result.is_ok()
    }
}

#[cfg(not(target_os = "windows"))]
pub fn unmap_network_drive(_drive_letter: &str) -> bool {
    false
}

pub fn map_all_shares(shares: &[String]) -> Vec<String> {
    let mut mapped_drives = Vec::new();
    let start_time = Instant::now();
    const MAX_MAPPING_TIME: Duration = Duration::from_secs(60);

    println!("[SMB] Starting to map {} shares (single-threaded mode)...", shares.len());

    for share_path in shares {
        if start_time.elapsed() > MAX_MAPPING_TIME {
            println!("[SMB] Mapping timeout reached, stopping");
            break;
        }

        if let Some(drive_letter) = get_next_drive() {
            if map_network_drive(share_path, &drive_letter) {
                mapped_drives.push(drive_letter);
            }
        } else {
            println!("[SMB] No available drive letters, stopping");
            break;
        }
    }

    println!("[SMB] Mapping completed in {:.2}s, {} drives mapped", start_time.elapsed().as_secs_f64(), mapped_drives.len());
    mapped_drives
}

pub fn unmap_all_drives(drives: &[String]) {
    for drive in drives {
        let _ = unmap_network_drive(drive);
    }
}
