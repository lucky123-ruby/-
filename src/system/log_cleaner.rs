use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;
use log::{info, warn};

pub struct LogCleaner {
    deleted_count: AtomicUsize,
    failed_count: AtomicUsize,
    skipped_count: AtomicUsize,
}

impl LogCleaner {
    pub fn new() -> Self {
        Self {
            deleted_count: AtomicUsize::new(0),
            failed_count: AtomicUsize::new(0),
            skipped_count: AtomicUsize::new(0),
        }
    }

    pub fn clean_all_logs(&self) {
        let start_time = Instant::now();
        info!("Starting log cleanup...");

        let mut handles = vec![];

        handles.push(thread::spawn({
            let cleaner = self.clone();
            move || cleaner.clean_windows_logs()
        }));

        handles.push(thread::spawn({
            let cleaner = self.clone();
            move || cleaner.clean_event_logs()
        }));

        handles.push(thread::spawn({
            let cleaner = self.clone();
            move || cleaner.clean_temp_logs()
        }));

        handles.push(thread::spawn({
            let cleaner = self.clone();
            move || cleaner.clean_browser_logs()
        }));

        handles.push(thread::spawn({
            let cleaner = self.clone();
            move || cleaner.clean_network_logs()
        }));

        handles.push(thread::spawn({
            let cleaner = self.clone();
            move || cleaner.clean_application_logs()
        }));

        for handle in handles {
            let _ = handle.join();
        }

        let elapsed = start_time.elapsed();
        let deleted = self.deleted_count.load(Ordering::Relaxed);
        let failed = self.failed_count.load(Ordering::Relaxed);
        let skipped = self.skipped_count.load(Ordering::Relaxed);

        info!("Log cleanup completed in {:?}", elapsed);
        info!("Deleted: {} files, Failed: {} files, Skipped: {} files", deleted, failed, skipped);
    }

    fn clean_windows_logs(&self) {
        info!("Cleaning Windows logs...");

        let log_dirs = vec![
            "C:\\Windows\\Logs",
            "C:\\Windows\\Debug",
            "C:\\Windows\\INF",
            "C:\\Windows\\System32\\LogFiles",
            "C:\\Windows\\System32\\winevt\\Logs",
        ];

        for dir in &log_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        self.try_delete_log(&path, "Windows");
                    }
                }
            }
        }
    }

    fn clean_event_logs(&self) {
        info!("Cleaning event logs...");

        let event_log_dir = "C:\\Windows\\System32\\winevt\\Logs";

        if let Ok(entries) = fs::read_dir(event_log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "evtx" || ext == "evt" {
                            self.try_delete_log(&path, "Event Log");
                        }
                    }
                }
            }
        }
    }

    fn clean_temp_logs(&self) {
        info!("Cleaning temporary logs...");

        let temp_dirs = vec![
            std::env::var("TEMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string()),
            std::env::var("TMP").unwrap_or_else(|_| "C:\\Windows\\Temp".to_string()),
            format!("{}\\Local\\Temp", std::env::var("LOCALAPPDATA").unwrap_or_default()),
            "C:\\Windows\\Temp".to_string(),
        ];

        for dir in &temp_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension() {
                            let ext_str = ext.to_string_lossy().to_lowercase();
                            if ext_str == "log" || ext_str == "txt" || ext_str == "tmp" {
                                self.try_delete_log(&path, "Temp");
                            }
                        }
                    }
                }
            }
        }
    }

    fn clean_browser_logs(&self) {
        info!("Cleaning browser logs...");

        let app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let roaming_app_data = std::env::var("APPDATA").unwrap_or_default();

        let browser_dirs = vec![
            format!("{}\\Google\\Chrome\\User Data\\Default", app_data),
            format!("{}\\Google\\Chrome\\User Data\\Default\\Network", app_data),
            format!("{}\\Microsoft\\Edge\\User Data\\Default", app_data),
            format!("{}\\Mozilla\\Firefox\\Profiles", roaming_app_data),
        ];

        for dir in &browser_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        let file_name = path.file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("")
                            .to_lowercase();

                        if file_name.contains("log") || file_name.ends_with(".log") {
                            self.try_delete_log(&path, "Browser");
                        }
                    }
                }
            }
        }
    }

    fn clean_network_logs(&self) {
        info!("Cleaning network logs...");

        let network_log_dirs = vec![
            "C:\\Windows\\System32\\LogFiles\\Firewall",
            "C:\\Windows\\System32\\LogFiles\\W3SVC1",
            "C:\\Windows\\System32\\LogFiles\\FTPSVC1",
            "C:\\inetpub\\logs\\LogFiles",
        ];

        for dir in &network_log_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension() {
                            let ext_str = ext.to_string_lossy().to_lowercase();
                            if ext_str == "log" || ext_str == "txt" {
                                self.try_delete_log(&path, "Network");
                            }
                        }
                    }
                }
            }
        }
    }

    fn clean_application_logs(&self) {
        info!("Cleaning application logs...");

        let app_data = std::env::var("LOCALAPPDATA").unwrap_or_default();
        let program_data = "C:\\ProgramData".to_string();

        let app_log_dirs = vec![
            format!("{}\\Microsoft\\Windows\\INetCache", app_data),
            format!("{}\\Microsoft\\Windows\\History", app_data),
            format!("{}\\Microsoft\\Windows\\IECompatCache", app_data),
            format!("{}\\Microsoft\\Windows\\IEDownloadHistory", app_data),
            format!("{}\\Microsoft\\Windows\\PowerShell", app_data),
            format!("{}\\Microsoft\\Windows\\TaskScheduler", app_data),
            format!("{}\\Microsoft\\Windows\\Terminal Services", program_data),
            format!("{}\\Microsoft\\Windows\\DHCP", program_data),
            format!("{}\\Microsoft\\Windows\\DNS", program_data),
        ];

        for dir in &app_log_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(ext) = path.extension() {
                            let ext_str = ext.to_string_lossy().to_lowercase();
                            if ext_str == "log" || ext_str == "txt" || ext_str == "evtx" {
                                self.try_delete_log(&path, "Application");
                            }
                        }
                    }
                }
            }
        }
    }

    fn try_delete_log(&self, path: &Path, log_type: &str) {
        if self.is_protected_file(path) {
            self.skipped_count.fetch_add(1, Ordering::Relaxed);
            return;
        }

        match fs::remove_file(path) {
            Ok(_) => {
                self.deleted_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                self.failed_count.fetch_add(1, Ordering::Relaxed);
                if e.kind() != std::io::ErrorKind::PermissionDenied {
                    warn!("Failed to delete {:?} ({}): {}", path, log_type, e);
                }
            }
        }
    }

    fn is_protected_file(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();

        let protected_patterns = vec![
            "ntuser.dat",
            "usrclass.dat",
            "bootsect.dos",
            "ntldr",
            "boot.ini",
            "pagefile.sys",
            "hiberfil.sys",
            "swapfile.sys",
        ];

        for pattern in &protected_patterns {
            if path_str.contains(pattern) {
                return true;
            }
        }

        false
    }

    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.deleted_count.load(Ordering::Relaxed),
            self.failed_count.load(Ordering::Relaxed),
            self.skipped_count.load(Ordering::Relaxed),
        )
    }
}

impl Clone for LogCleaner {
    fn clone(&self) -> Self {
        Self {
            deleted_count: AtomicUsize::new(self.deleted_count.load(Ordering::Relaxed)),
            failed_count: AtomicUsize::new(self.failed_count.load(Ordering::Relaxed)),
            skipped_count: AtomicUsize::new(self.skipped_count.load(Ordering::Relaxed)),
        }
    }
}

impl Default for LogCleaner {
    fn default() -> Self {
        Self::new()
    }
}
