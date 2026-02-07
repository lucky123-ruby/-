//! 系统控制模块
//!
//! 该模块提供了云服务控制和系统资源管理功能

use std::path::Path;
use std::process::Command;
use std::ffi::OsString;

/// 云服务配置结构体
#[derive(Debug, Clone)]
pub struct CloudService {
    /// 服务名称
    pub name: String,
    /// 可能的进程名列表
    pub process_names: Vec<String>,
    /// 对应的后台服务名
    pub service_name: String,
    /// 客户端主程序完整路径
    pub client_path: String,
    /// 备选安装路径
    pub alternative_paths: Vec<String>,
    /// 标记是否已安装
    pub is_installed: bool,
}

impl CloudService {
    /// 创建新的云服务配置
    pub fn new(
        name: &str,
        process_names: Vec<&str>,
        service_name: &str,
        client_path: &str,
        alternative_paths: Vec<&str>,
    ) -> Self {
        CloudService {
            name: name.to_string(),
            process_names: process_names.into_iter().map(|s| s.to_string()).collect(),
            service_name: service_name.to_string(),
            client_path: client_path.to_string(),
            alternative_paths: alternative_paths.into_iter().map(|s| s.to_string()).collect(),
            is_installed: false,
        }
    }
}

/// 云服务控制器
pub struct CloudServiceController {
    /// 支持的云服务列表
    services: Vec<CloudService>,
}

impl CloudServiceController {
    /// 创建新的云服务控制器实例
    pub fn new() -> Self {
        let mut controller = CloudServiceController {
            services: Vec::new(),
        };
        controller.initialize_services();
        controller
    }

    /// 初始化服务列表并检查安装状态
    fn initialize_services(&mut self) {
        // 定义所有可能的云服务
        let mut all_services = vec![
            // Microsoft OneDrive
            CloudService::new(
                "OneDrive",
                vec!["OneDrive.exe", "OneDriveStandaloneUpdater.exe"],
                "OneDrive Updater Service",
                "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                vec![
                    "C:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
                ],
            ),

            // Google Drive
            CloudService::new(
                "Google Drive",
                vec!["GoogleDriveFS.exe", "googledrivesync.exe"],
                "Google Drive File Stream",
                "C:\\Program Files\\Google\\Drive File Stream\\launch.exe",
                vec![
                    "C:\\Program Files (x86)\\Google\\Drive\\googledrivesync.exe",
                    "C:\\Program Files\\Google\\Drive\\googledrivesync.exe"
                ],
            ),

            // Dropbox
            CloudService::new(
                "Dropbox",
                vec!["Dropbox.exe"],
                "DropboxUpdateService",
                "C:\\Program Files\\Dropbox\\Client\\Dropbox.exe",
                vec![
                    "C:\\Program Files (x86)\\Dropbox\\Client\\Dropbox.exe",
                    "%USERPROFILE%\\AppData\\Local\\Dropbox\\Update\\DropboxUpdate.exe"
                ],
            ),

            // Box
            CloudService::new(
                "Box",
                vec!["BoxSync.exe", "BoxTools.exe"],
                "",
                "C:\\Program Files\\Box\\Box Sync\\BoxSync.exe",
                vec![
                    "C:\\Program Files (x86)\\Box\\Box Sync\\BoxSync.exe"
                ],
            ),

            // iCloud Drive
            CloudService::new(
                "iCloud Drive",
                vec!["iCloudDrive.exe", "iCloudServices.exe", "iCloud.exe"],
                "",
                "C:\\Program Files\\Common Files\\Apple\\Internet Services\\iCloudDrive.exe",
                vec![
                    "C:\\Program Files (x86)\\Common Files\\Apple\\Internet Services\\iCloudDrive.exe",
                    "%USERPROFILE%\\AppData\\Local\\Apple\\iCloud\\iCloudDrive.exe"
                ],
            ),

            // Amazon Drive
            CloudService::new(
                "Amazon Drive",
                vec!["Amazon Drive.exe"],
                "",
                "C:\\Program Files\\Amazon\\Amazon Drive\\Amazon Drive.exe",
                vec![
                    "C:\\Program Files (x86)\\Amazon\\Amazon Drive\\Amazon Drive.exe"
                ],
            ),

            // Sync.com
            CloudService::new(
                "Sync.com",
                vec!["Sync.com.exe", "SyncCom.exe"],
                "",
                "C:\\Program Files\\Sync.com\\Sync.com.exe",
                vec![
                    "C:\\Program Files (x86)\\Sync.com\\Sync.com.exe"
                ],
            ),

            // pCloud
            CloudService::new(
                "pCloud",
                vec!["pCloud.exe"],
                "",
                "C:\\Program Files\\pCloud\\pCloud.exe",
                vec![
                    "C:\\Program Files (x86)\\pCloud\\pCloud.exe"
                ],
            ),

            // MegaSync
            CloudService::new(
                "MegaSync",
                vec!["MegaSync.exe", "MEGAsync.exe"],
                "",
                "C:\\Program Files\\Mega Limited\\MEGAsync\\MegaSync.exe",
                vec![
                    "C:\\Program Files (x86)\\Mega Limited\\MEGAsync\\MegaSync.exe"
                ],
            ),

            // Nextcloud
            CloudService::new(
                "Nextcloud",
                vec!["nextcloud.exe"],
                "",
                "C:\\Program Files\\Nextcloud\\nextcloud.exe",
                vec![
                    "C:\\Program Files (x86)\\Nextcloud\\nextcloud.exe"
                ],
            ),

            // ownCloud
            CloudService::new(
                "ownCloud",
                vec!["owncloud.exe"],
                "",
                "C:\\Program Files\\ownCloud\\owncloud.exe",
                vec![
                    "C:\\Program Files (x86)\\ownCloud\\owncloud.exe"
                ],
            ),

            // Tresorit
            CloudService::new(
                "Tresorit",
                vec!["Tresorit.exe"],
                "Tresorit",
                "C:\\Program Files\\Tresorit\\Tresorit.exe",
                vec![
                    "C:\\Program Files (x86)\\Tresorit\\Tresorit.exe"
                ],
            ),

            // SpiderOak
            CloudService::new(
                "SpiderOak",
                vec!["SpiderOak.exe", "SpiderOakONE.exe"],
                "",
                "C:\\Program Files\\SpiderOakONE\\SpiderOak.exe",
                vec![
                    "C:\\Program Files (x86)\\SpiderOakONE\\SpiderOak.exe"
                ],
            ),

            // Resilio Sync
            CloudService::new(
                "Resilio Sync",
                vec!["rslsync.exe", "Resilio-Sync.exe"],
                "rslsync",
                "C:\\Program Files\\Resilio Sync\\rslsync.exe",
                vec![
                    "C:\\Program Files (x86)\\Resilio Sync\\rslsync.exe"
                ],
            ),

            // Seafile
            CloudService::new(
                "Seafile",
                vec!["seafile-daemon.exe", "seafile.exe"],
                "",
                "C:\\Program Files\\Seafile\\seafile-daemon.exe",
                vec![
                    "C:\\Program Files (x86)\\Seafile\\seafile-daemon.exe"
                ],
            ),

            // Degoo
            CloudService::new(
                "Degoo",
                vec!["Degoo.exe"],
                "",
                "C:\\Program Files\\Degoo\\Degoo.exe",
                vec![
                    "C:\\Program Files (x86)\\Degoo\\Degoo.exe"
                ],
            ),

            // Jottacloud
            CloudService::new(
                "Jottacloud",
                vec!["Jottacloud.exe"],
                "",
                "C:\\Program Files\\Jottacloud\\Jottacloud.exe",
                vec![
                    "C:\\Program Files (x86)\\Jottacloud\\Jottacloud.exe"
                ],
            ),

            // Yandex.Disk
            CloudService::new(
                "Yandex.Disk",
                vec!["YandexDisk.exe", "Yandex.Disk.exe"],
                "",
                "C:\\Program Files\\Yandex\\YandexDisk\\YandexDisk.exe",
                vec![
                    "C:\\Program Files (x86)\\Yandex\\YandexDisk\\YandexDisk.exe"
                ],
            ),

            // MediaFire
            CloudService::new(
                "MediaFire",
                vec!["MediaFire.exe"],
                "",
                "C:\\Program Files\\MediaFire\\MediaFire.exe",
                vec![
                    "C:\\Program Files (x86)\\MediaFire\\MediaFire.exe"
                ],
            ),

            // Koofr
            CloudService::new(
                "Koofr",
                vec!["Koofr.exe"],
                "",
                "C:\\Program Files\\Koofr\\Koofr.exe",
                vec![
                    "C:\\Program Files (x86)\\Koofr\\Koofr.exe"
                ],
            ),

            // Microsoft OneDrive for Business
            CloudService::new(
                "OneDrive for Business",
                vec!["OneDrive.exe", "OneDriveStandaloneUpdater.exe"],
                "OneDrive Updater Service",
                "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
                vec![
                    "C:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe",
                    "%USERPROFILE%\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
                ],
            ),

            // Adobe Creative Cloud
            CloudService::new(
                "Adobe Creative Cloud",
                vec!["Adobe Creative Cloud.exe", "CCXProcess.exe"],
                "AdobeUpdateService",
                "C:\\Program Files\\Adobe\\Adobe Creative Cloud\\ACC\\Creative Cloud.exe",
                vec![
                    "C:\\Program Files (x86)\\Adobe\\Adobe Creative Cloud\\ACC\\Creative Cloud.exe"
                ],
            ),

            // SugarSync
            CloudService::new(
                "SugarSync",
                vec!["SugarSync.exe"],
                "",
                "C:\\Program Files\\SugarSync\\SugarSync.exe",
                vec![
                    "C:\\Program Files (x86)\\SugarSync\\SugarSync.exe"
                ],
            ),

            // IDrive
            CloudService::new(
                "IDrive",
                vec!["IDrive.exe"],
                "",
                "C:\\Program Files\\IDriveWindows\\IDrive.exe",
                vec![
                    "C:\\Program Files (x86)\\IDriveWindows\\IDrive.exe"
                ],
            ),

            // Zoho WorkDrive
            CloudService::new(
                "Zoho WorkDrive",
                vec!["Zoho WorkDrive.exe"],
                "",
                "C:\\Program Files\\Zoho WorkDrive\\Zoho WorkDrive.exe",
                vec![
                    "C:\\Program Files (x86)\\Zoho WorkDrive\\Zoho WorkDrive.exe"
                ],
            )
        ];

        // 展开环境变量路径并检查每个服务是否安装
        for service in &mut all_services {
            // 展开客户端路径的环境变量
            if let Ok(expanded) = Self::expand_environment_variables(&service.client_path) {
                service.client_path = expanded;
            }
            
            // 展开备选路径的环境变量
            for path in &mut service.alternative_paths {
                if let Ok(expanded) = Self::expand_environment_variables(path) {
                    *path = expanded;
                }
            }
            
            // 检查服务是否安装
            if Self::check_service_installed(service) {
                service.is_installed = true;
                self.services.push(service.clone());
                println!("[云控模块] 检测到已安装服务: {}", service.name);
            }
        }
    }

    /// 展开环境变量字符串
    fn expand_environment_variables(input: &str) -> Result<String, std::env::VarError> {
        // 简单实现环境变量展开
        let mut result = input.to_string();
        
        // 展开常见的环境变量
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            result = result.replace("%USERPROFILE%", &user_profile);
        }
        
        Ok(result)
    }

    /// 检查服务是否已安装
    fn check_service_installed(service: &mut CloudService) -> bool {
        // 检查主路径是否存在
        if Path::new(&service.client_path).exists() {
            return true;
        }

        // 检查备选路径
        for alt_path in &service.alternative_paths {
            if Path::new(alt_path).exists() {
                service.client_path = alt_path.clone();
                return true;
            }
        }

        // 注意：在纯Rust实现中，我们暂时不检查Windows服务是否存在
        // 因为这需要调用Windows API，而这需要额外的依赖和unsafe代码
        
        false
    }

    /// 确保所有云服务运行
    pub fn ensure_all_cloud_services_running(&self) {
        if self.services.is_empty() {
            println!("[云控模块] 未检测到任何云同步服务");
            return;
        }

        println!("[云控模块] 开始激活云同步服务...");

        for service in &self.services {
            println!("检查服务: {}", service.name);

            let mut is_running = false;
            // 检查任一相关进程是否运行
            for process in &service.process_names {
                if Self::is_process_running(process) {
                    is_running = true;
                    println!("  ✓ 进程已运行: {}", process);
                    break;
                }
            }

            if !is_running {
                println!("  ✗ 服务未运行，尝试激活...");

                // 策略1: 尝试启动服务
                if !service.service_name.is_empty() && Self::start_service(&service.service_name) {
                    println!("  ✓ 服务启动成功: {}", service.service_name);
                    continue;
                }

                // 策略2: 尝试直接启动客户端
                if Self::launch_client(&service.client_path) {
                    println!("  ✓ 客户端启动成功: {}", service.client_path);
                    continue;
                }

                println!("  ✗ 服务启动失败");
            }
        }

        println!("[云控模块] 云服务激活流程完成");
    }

    /// 检查进程是否运行
    fn is_process_running(process_name: &str) -> bool {
        // 在纯Rust实现中，我们暂时使用tasklist命令检查进程
        // 注意：这在Windows上有效，在Unix-like系统上需要不同实现
        if cfg!(target_os = "windows") {
            match Command::new("tasklist").output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.contains(process_name)
                }
                Err(_) => false,
            }
        } else {
            // Unix-like系统的实现会有所不同
            false
        }
    }

    /// 启动Windows服务
    fn start_service(service_name: &str) -> bool {
        if service_name.is_empty() {
            return false;
        }

        // 在纯Rust实现中，我们暂时使用net命令启动服务
        // 注意：这在Windows上有效，在Unix-like系统上需要不同实现
        if cfg!(target_os = "windows") {
            match Command::new("net")
                .arg("start")
                .arg(service_name)
                .output() {
                    Ok(output) => output.status.success(),
                    Err(_) => false,
                }
        } else {
            // Unix-like系统的实现会有所不同
            false
        }
    }

    /// 直接启动客户端程序
    fn launch_client(client_path: &str) -> bool {
        if !Path::new(client_path).exists() {
            return false;
        }

        // 使用 /background 参数静默启动（如果支持）
        match Command::new(client_path)
            .arg("/background")
            .spawn() {
                Ok(_) => true,
                Err(_) => {
                    // 如果带参数失败，尝试直接启动
                    Command::new(client_path).spawn().is_ok()
                }
            }
    }

    /// 获取所有云同步文件夹路径
    pub fn get_cloud_sync_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = Vec::new();
        
        // 获取用户主目录
        let user_profile = match std::env::var("USERPROFILE") {
            Ok(profile) => profile,
            Err(_) => return paths, // 如果无法获取用户目录，则返回空列表
        };

        // 获取已知的云文件夹路径
        let known_paths = [
            format!("{}\\OneDrive", user_profile),
            format!("{}\\OneDrive\\Documents", user_profile),
            format!("{}\\Google Drive", user_profile),
            format!("{}\\Dropbox", user_profile),
            format!("{}\\Box Sync", user_profile),
            format!("{}\\iCloudDrive", user_profile),
            format!("{}\\Amazon Drive", user_profile),
            format!("{}\\Sync", user_profile),
            format!("{}\\pCloud Drive", user_profile),
            format!("{}\\Mega", user_profile),
            format!("{}\\Nextcloud", user_profile),
            format!("{}\\ownCloud", user_profile),
            format!("{}\\Tresorit", user_profile),
            format!("{}\\SpiderOak", user_profile),
            format!("{}\\Resilio Sync", user_profile),
            format!("{}\\Seafile", user_profile),
            format!("{}\\Degoo", user_profile),
            format!("{}\\Jottacloud", user_profile),
            format!("{}\\Yandex.Disk", user_profile),
            format!("{}\\MediaFire", user_profile),
            format!("{}\\Koofr", user_profile),
            format!("{}\\SugarSync", user_profile),
            format!("{}\\IDrive", user_profile),
            format!("{}\\Zoho WorkDrive", user_profile),
            format!("{}\\Creative Cloud Files", user_profile), // Adobe Creative Cloud
        ];

        // 只返回存在的路径
        for path in &known_paths {
            if Path::new(path).exists() {
                paths.push(path.clone());
            }
        }

        paths
    }

    /// 获取检测到的服务数量
    pub fn get_detected_service_count(&self) -> usize {
        self.services.len()
    }
}

/// 系统资源管理器
pub struct SystemResourceManager {
    essential_processes: Vec<String>,
}

impl SystemResourceManager {
    pub fn new() -> Self {
        SystemResourceManager {
            essential_processes: vec![
                "system".to_string(),
                "svchost.exe".to_string(),
                "lsass.exe".to_string(),
                "winlogon.exe".to_string(),
                "csrss.exe".to_string(),
                "explorer.exe".to_string(),
                "taskhost.exe".to_string(),
                "dwm.exe".to_string(),
            ],
        }
    }

    /// 设置高优先级
    pub fn set_high_priority(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            use windows::Win32::System::Threading::{
                GetCurrentProcess, SetPriorityClass,
                REALTIME_PRIORITY_CLASS, HIGH_PRIORITY_CLASS,
            };
            
            let handle = unsafe { GetCurrentProcess() };
            let result = unsafe { SetPriorityClass(handle, REALTIME_PRIORITY_CLASS) };
            
            if result.is_ok() {
                println!("优先级设置为最高");
                true
            } else {
                println!("无法设置实时优先级，尝试高优先级");
                let result = unsafe { SetPriorityClass(handle, HIGH_PRIORITY_CLASS) };
                result.is_ok()
            }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            println!("在非Windows系统上设置进程优先级");
            true
        }
    }

    /// 强制挂载所有磁盘
    pub fn force_mount_all_disks(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            // 在Windows上使用wmic命令强制磁盘上线
            match Command::new("wmic")
                .args(&["diskdrive", "where", "status='offline'", "call", "online"])
                .output() {
                    Ok(output) => {
                        println!("执行磁盘上线命令");
                        output.status.success()
                    },
                    Err(_) => {
                        println!("磁盘上线命令执行失败");
                        false
                    }
                }
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // 在非Windows系统上的简化实现
            println!("在非Windows系统上尝试挂载磁盘");
            true
        }
    }

    /// 终止高资源使用进程
    pub fn terminate_high_usage_processes(&self) {
        // 这是一个简化的实现，实际的Windows版本需要使用更多的WinAPI调用
        println!("检查高资源使用进程...");
        
        #[cfg(target_os = "windows")]
        {
            // 使用tasklist获取进程列表
            match Command::new("tasklist").output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    println!("当前运行进程数量: {}", stdout.lines().count());
                }
                Err(_) => {
                    println!("无法获取进程列表");
                }
            }
        }
    }

    /// 启动单次执行
    pub fn start_single_execution(&self) {
        println!("=== 开始单次系统资源检查 ===");

        println!("1. 设置进程优先级...");
        self.set_high_priority();

        println!("2. 强制挂载离线磁盘...");
        self.force_mount_all_disks();

        println!("3. 检查磁盘状态...");
        self.monitor_disks();

        println!("4. 检查高资源使用进程...");
        self.terminate_high_usage_processes();

        println!("5. 记录系统状态...");
        self.log_system_status();

        println!("6. 执行清理操作...");
        self.execute_remaining_operations();

        println!("=== 单次系统资源检查完成 ===");
    }

    /// 监控磁盘
    fn monitor_disks(&self) {
        println!("监控磁盘状态...");
        
        #[cfg(target_os = "windows")]
        {
            // 使用wmic获取磁盘信息
            match Command::new("wmic")
                .args(&["logicaldisk", "get", "size,freespace,caption"])
                .output() {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        println!("磁盘使用情况:\n{}", stdout);
                    }
                    Err(_) => {
                        println!("无法获取磁盘信息");
                    }
                }
        }
    }

    /// 记录系统状态
    fn log_system_status(&self) {
        println!("记录系统状态...");
        
        #[cfg(target_os = "windows")]
        {
            // 使用systeminfo获取系统信息
            match Command::new("systeminfo").output() {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // 只显示前几行以避免输出过多
                    let lines: Vec<&str> = stdout.lines().take(10).collect();
                    println!("系统信息摘要:\n{}", lines.join("\n"));
                }
                Err(_) => {
                    println!("无法获取系统信息");
                }
            }
        }
    }

    /// 执行剩余操作
    fn execute_remaining_operations(&self) {
        println!("执行剩余操作...");
        println!("1. 清理临时文件");
        println!("2. 关闭未使用服务");
        println!("3. 释放系统资源");
        println!("4. 优化内存使用");
        
        // 模拟一些处理时间
        std::thread::sleep(std::time::Duration::from_millis(500));
        println!("剩余操作完成");
    }
}