use std::path::Path;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;
use log::{info, warn, debug};

#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ};

use once_cell::sync::Lazy;
use sysinfo::{Pid, System};

static SYSTEM_PATHS: Lazy<Vec<String>> = Lazy::new(|| {
    vec![
        "C:\\Windows\\".to_string(),
        "C:\\Program Files\\".to_string(),
        "C:\\Program Files (x86)\\".to_string(),
        "C:\\ProgramData\\".to_string(),
    ]
});

static PROTECTED_PROCESS_NAMES: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("system");
    set.insert("system idle process");
    set.insert("registry");
    set.insert("smss");
    set.insert("csrss");
    set.insert("wininit");
    set.insert("winlogon");
    set.insert("services");
    set.insert("lsass");
    set.insert("lsm");
    set.insert("svchost");
    set.insert("explorer");
    set.insert("dwm");
    set.insert("conhost");
    set.insert("rundll32");
    set.insert("taskmgr");
    set.insert("w3wp");
    set.insert("iisexpress");
    set.insert("cmd");
    set.insert("powershell");
    set.insert("pwsh");
    set.insert("trae code");
    set.insert("trae");
    set.insert("traecode");
    set.insert("code");
    set.insert("dllhost");
    set.insert("msdtc");
    set.insert("spoolsv");
    set.insert("audiodg");
    set.insert("searchindexer");
    set.insert("searchprotocolhost");
    set.insert("searchfilterhost");
    set.insert("wlidsvc");
    set.insert("wlidsvcm");
    set.insert("appinfo");
    set.insert("audiosrv");
    set.insert("bfe");
    set.insert("bits");
    set.insert("browser");
    set.insert("cdpsvc");
    set.insert("certpropservice");
    set.insert("clippsv");
    set.insert("coremessaging");
    set.insert("cryptsvc");
    set.insert("cscript");
    set.insert("dasHost");
    set.insert("dfsr");
    set.insert("dhcp");
    set.insert("diagsvc");
    set.insert("diagnosticshub.standardcollector.service");
    set.insert("displayenhancementservice");
    set.insert("dot3svc");
    set.insert("dps");
    set.insert("dusmsvc");
    set.insert("eapsvc");
    set.insert("embeddedmode");
    set.insert("eventlog");
    set.insert("faxsvc");
    set.insert("fdphost");
    set.insert("fdrespub");
    set.insert("gpsvc");
    set.insert("hidserv");
    set.insert("hkcmd");
    set.insert("igfxpers");
    set.insert("igfxtray");
    set.insert("ikeext");
    set.insert("iphlpsvc");
    set.insert("keyiso");
    set.insert("ksecdd");
    set.insert("lanmanserver");
    set.insert("lanmanworkstation");
    set.insert("lmhosts");
    set.insert("mpssvc");
    set.insert("msdtc");
    set.insert("msgsvc");
    set.insert("msiserver");
    set.insert("netprofm");
    set.insert("nettcpportsharing");
    set.insert("p2psvc");
    set.insert("pcaevtsvc");
    set.insert("pla");
    set.insert("plaaservice");
    set.insert("policyagent");
    set.insert("profsvc");
    set.insert("qwave");
    set.insert("rasauto");
    set.insert("rasman");
    set.insert("rpcss");
    set.insert("rpcrt4");
    set.insert("samsrv");
    set.insert("schedule");
    set.insert("seclogon");
    set.insert("sens");
    set.insert("sessionenv");
    set.insert("shellhwdetection");
    set.insert("smphost");
    set.insert("sppsvc");
    set.insert("ssh-agent");
    set.insert("sspisrv");
    set.insert("stisvc");
    set.insert("swprv");
    set.insert("sysmain");
    set.insert("tapisrv");
    set.insert("themeservice");
    set.insert("threadorder");
    set.insert("trkwks");
    set.insert("ui0detect");
    set.insert("umrdpservice");
    set.insert("upnphost");
    set.insert("vds");
    set.insert("vmms");
    set.insert("vmwp");
    set.insert("vss");
    set.insert("w32time");
    set.insert("wbengine");
    set.insert("wbiosrvc");
    set.insert("wcncsvc");
    set.insert("webclient");
    set.insert("webengine");
    set.insert("werfault");
    set.insert("werfaultsecure");
    set.insert("wiaservc");
    set.insert("winmgmt");
    set.insert("winrm");
    set.insert("winsrv");
    set.insert("wlanext");
    set.insert("wlansvc");
    set.insert("wmiapsrv");
    set.insert("wmiprvse");
    set.insert("wmiutils");
    set.insert("wpdshextautoplayplayer");
    set.insert("wpdshserviceobj");
    set.insert("wscsvc");
    set.insert("wsearch");
    set.insert("wuauserv");
    set.insert("wudfsvc");
    set.insert("wusa");
    set
});

static PROCESS_CACHE: Lazy<Mutex<HashMap<u32, bool>>> = Lazy::new(|| {
    Mutex::new(HashMap::with_capacity(1000))
});

const MAX_CACHE_SIZE: usize = 1000;

pub fn find_processes_using_file(path: &Path) -> Vec<u32> {
    let start = Instant::now();
    
    #[cfg(windows)]
    {
        if let Ok(pids) = find_processes_using_file_windows(path) {
            debug!("Found {} processes using file {:?} in {:?}", pids.len(), path, start.elapsed());
            return pids;
        }
    }
    
    #[cfg(not(windows))]
    {
        warn!("File lock handling is only supported on Windows");
    }
    
    vec![]
}

#[cfg(windows)]
fn find_processes_using_file_windows(path: &Path) -> Result<Vec<u32>, String> {
    let path_str = path.to_string_lossy().to_lowercase();
    let path_str = if path_str.starts_with("\\\\?\\") {
        &path_str[4..]
    } else {
        &path_str
    };
    
    let mut system = System::new_all();
    system.refresh_processes();
    
    let mut pids = Vec::new();
    let current_pid = std::process::id();
    
    for (pid, process) in system.processes() {
        let pid_u32 = pid.as_u32();
        
        if pid_u32 == current_pid {
            continue;
        }
        
        if let Some(exe_path) = process.exe() {
            let exe_lower = exe_path.to_string_lossy().to_lowercase();
            
            if exe_lower.contains(path_str) {
                pids.push(pid_u32);
            }
        }
    }
    
    Ok(pids)
}

pub fn is_system_process(pid: u32) -> bool {
    let start = Instant::now();
    
    {
        let cache = PROCESS_CACHE.lock().unwrap();
        if let Some(&cached) = cache.get(&pid) {
            debug!("Cache hit for PID {}: {} ({:?})", pid, cached, start.elapsed());
            return cached;
        }
    }
    
    #[cfg(windows)]
    {
        let result = is_system_process_windows(pid);
        
        {
            let mut cache = PROCESS_CACHE.lock().unwrap();
            if cache.len() >= MAX_CACHE_SIZE {
                cache.clear();
            }
            cache.insert(pid, result);
        }
        
        debug!("PID {} is system process: {} ({:?})", pid, result, start.elapsed());
        return result;
    }
    
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(windows)]
fn is_system_process_windows(pid: u32) -> bool {
    let mut system = System::new_all();
    system.refresh_processes();
    
    let pid_obj = Pid::from_u32(pid);
    
    if let Some(process) = system.process(pid_obj) {
        if let Some(exe_path) = process.exe() {
            let path_lower = exe_path.to_string_lossy().to_lowercase();
            
            for system_path in SYSTEM_PATHS.iter() {
                if path_lower.starts_with(system_path) {
                    return true;
                }
            }
            
            if let Some(exe_name) = Path::new(&exe_path).file_name() {
                if let Some(name_str) = exe_name.to_str() {
                    let name_lower = name_str.to_lowercase();
                    let name_without_exe = name_lower.strip_suffix(".exe").unwrap_or(&name_lower);
                    
                    if name_without_exe == "conhost" {
                        return true;
                    }
                    
                    if PROTECTED_PROCESS_NAMES.contains(name_without_exe) {
                        return true;
                    }
                }
            }
            
            return false;
        }
    }
    
    true
}

pub fn terminate_file_locking_process(path: &Path) -> Result<(), String> {
    let start = Instant::now();
    info!("Attempting to terminate process locking file: {:?}", path);
    
    let pids = find_processes_using_file(path);
    
    if pids.is_empty() {
        return Err("No processes found locking file".to_string());
    }
    
    let current_pid = std::process::id();
    let mut terminated = 0;
    let mut skipped_system = 0;
    let mut skipped_current = 0;
    
    for pid in pids {
        if pid == current_pid {
            info!("Skipping current process PID {}", pid);
            skipped_current += 1;
            continue;
        }
        
        if is_system_process(pid) {
            info!("Skipping system process PID {}", pid);
            skipped_system += 1;
            continue;
        }
        
        info!("Terminating non-system process PID {}", pid);
        
        #[cfg(windows)]
        {
            if terminate_process_windows(pid) {
                terminated += 1;
                info!("Successfully terminated PID {}", pid);
            } else {
                warn!("Failed to terminate PID {}", pid);
            }
        }
        
        #[cfg(not(windows))]
        {
            warn!("Process termination is only supported on Windows");
        }
    }
    
    let elapsed = start.elapsed();
    
    if terminated > 0 {
        info!("Terminated {} processes, skipped {} system processes and {} current process in {:?}", terminated, skipped_system, skipped_current, elapsed);
        Ok(())
    } else if skipped_system > 0 {
        Err(format!("All {} locking processes are system processes, cannot terminate", skipped_system))
    } else if skipped_current > 0 {
        Err(format!("Only current process is locking file, cannot terminate"))
    } else {
        Err("Failed to terminate any locking processes".to_string())
    }
}

#[cfg(windows)]
fn terminate_process_windows(pid: u32) -> bool {
    unsafe {
        match OpenProcess(PROCESS_TERMINATE, false, pid) {
            Ok(handle) => {
                let result = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
                result.is_ok()
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_paths() {
        assert!(SYSTEM_PATHS.len() > 0);
        assert!(SYSTEM_PATHS[0].starts_with("C:\\"));
    }

    #[test]
    fn test_is_system_process_cache() {
        let pid = std::process::id();
        let result1 = is_system_process(pid);
        let result2 = is_system_process(pid);
        assert_eq!(result1, result2);
    }
}
