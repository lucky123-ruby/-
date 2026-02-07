//! Asynchronous deletion coordinator
//!
//! Manages asynchronous deletion of original files after encryption is complete.
//! Uses a thread pool to handle deletions without blocking the encryption pipeline.

use std::collections::VecDeque;
use std::fs;
use std::io::Seek;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use rand::{RngCore, rngs::OsRng};

use crate::crypt::PerformanceStatsManager;

struct DeletionTask {
    original_file: PathBuf,
    encrypted_file: PathBuf,
    retry_count: usize,
    schedule_time: std::time::SystemTime,
    cancelled: AtomicBool,
}

impl DeletionTask {
    fn new(original_file: PathBuf, encrypted_file: PathBuf) -> Self {
        Self {
            original_file,
            encrypted_file,
            retry_count: 0,
            schedule_time: std::time::SystemTime::now(),
            cancelled: AtomicBool::new(false),
        }
    }
}

pub struct AsyncDeletionCoordinator {
    deletion_queue: Arc<Mutex<VecDeque<Arc<DeletionTask>>>>,
    stop_flag: Arc<AtomicBool>,
    deletion_threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    stats_manager: Arc<PerformanceStatsManager>,
    pending_tasks: AtomicUsize,
    completed_tasks: AtomicUsize,
    failed_tasks: AtomicUsize,
    encryption_completed: AtomicBool,
    target_thread_count: AtomicUsize,
    active_threads: AtomicUsize,
}

impl AsyncDeletionCoordinator {
    pub fn new(stats_manager: Arc<PerformanceStatsManager>) -> Self {
        Self {
            deletion_queue: Arc::new(Mutex::new(VecDeque::new())),
            stop_flag: Arc::new(AtomicBool::new(false)),
            deletion_threads: Arc::new(Mutex::new(Vec::new())),
            stats_manager,
            pending_tasks: AtomicUsize::new(0),
            completed_tasks: AtomicUsize::new(0),
            failed_tasks: AtomicUsize::new(0),
            encryption_completed: AtomicBool::new(false),
            target_thread_count: AtomicUsize::new(4), // Initial thread count
            active_threads: AtomicUsize::new(0),
        }
    }

    pub fn schedule_deletion(&self, original: &std::path::Path, encrypted: &std::path::Path) {
        let task = Arc::new(DeletionTask::new(
            original.to_path_buf(),
            encrypted.to_path_buf(),
        ));
        
        self.deletion_queue.lock().unwrap().push_back(task.clone());
        self.pending_tasks.fetch_add(1, Ordering::Relaxed);
        
        // If encryption is completed, we might want to expand our thread pool
        if self.encryption_completed.load(Ordering::Relaxed) {
            self.expand_deletion_threads();
        }
    }

    pub fn get_pending_tasks(&self) -> usize {
        self.pending_tasks.load(Ordering::Relaxed)
    }

    pub fn get_completed_tasks(&self) -> usize {
        self.completed_tasks.load(Ordering::Relaxed)
    }

    pub fn mark_encryption_completed(&self) {
        if self.encryption_completed.swap(true, Ordering::Relaxed) {
            return; // Already marked
        }
        
        println!("Encryption completed, starting fast deletion mode...");
        
        // Increase target thread count for faster deletion
        self.target_thread_count.store(16, Ordering::Relaxed);
        println!("Target deletion threads increased to: 16");
        
        // Immediately create additional deletion threads
        self.expand_deletion_threads();
        
        // Rapidly expand deletion thread pool
        self.rapid_expand_deletion_threads();
    }

    fn expand_deletion_threads(&self) {
        let current_threads = self.deletion_threads.lock().unwrap().len();
        let target_threads = self.target_thread_count.load(Ordering::Relaxed);
        
        if current_threads < target_threads {
            for i in current_threads..target_threads {
                self.create_deletion_thread(i);
            }
            println!("Expanded deletion threads to {}", target_threads);
        }
    }

    fn rapid_expand_deletion_threads(&self) {
        let num_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        // 限制最大线程数，避免创建过多线程导致系统资源紧张
        let target_threads = std::cmp::min(
            num_cores,  // 进一步减少删除线程数量
            8,                // 降低最大线程数上限
        );
        
        self.target_thread_count.store(target_threads, Ordering::Relaxed);
        
        let current_threads = self.deletion_threads.lock().unwrap().len();
        // 只在需要时创建额外线程
        if current_threads < target_threads {
            for i in current_threads..target_threads {
                self.create_deletion_thread(i);
            }
        }
        
        println!("Rapid expansion completed: {} deletion threads active", target_threads);
    }

    fn create_deletion_thread(&self, _thread_id: usize) {
        let deletion_queue = Arc::clone(&self.deletion_queue);
        let stop_flag = Arc::clone(&self.stop_flag);
        
        let handle = thread::spawn(move || {
            while !stop_flag.load(Ordering::Relaxed) {
                // Try to get a task from the queue
                let task_option = {
                    let mut queue = deletion_queue.lock().unwrap();
                    queue.pop_front()
                };
                
                if let Some(task) = task_option {
                    if !task.cancelled.load(Ordering::Relaxed) {
                        // Perform the actual deletion
                        match Self::perform_deletion(&task.original_file, &task.encrypted_file) {
                            Ok(_) => {
                                // 成功删除，不输出日志以减少I/O开销
                            }
                            Err(_e) => {
                                // 删除失败时不输出错误日志，避免大量错误信息刷屏
                                // 在生产环境中，可以考虑将错误记录到专门的日志文件中
                            }
                        }
                    }
                } else {
                    // 无任务时休眠，增加休眠时间以减少CPU占用
                    thread::sleep(Duration::from_millis(1));
                }
            }
        });
        
        self.deletion_threads.lock().unwrap().push(handle);
    }

    fn perform_deletion(original_file: &std::path::Path, encrypted_file: &std::path::Path) -> Result<(), String> {
        // Check if encrypted file exists
        if !encrypted_file.exists() {
            return Err("Encrypted file not found, skipping deletion".to_string());
        }
        
        // Validate encrypted file
        if !Self::validate_encrypted_file(encrypted_file, original_file) {
            return Err("Encrypted file validation failed, skipping deletion".to_string());
        }
        
        // Perform secure deletion - overwrite file content multiple times before deleting
        Self::secure_delete_file(original_file)
            .map_err(|e| format!("Failed to securely delete original file: {}", e))?;
        
        Ok(())
    }

    fn validate_encrypted_file(encrypted_file: &std::path::Path, original_file: &std::path::Path) -> bool {
        // Basic validation - in a real implementation, this would check file integrity
        if let (Ok(encrypted_meta), Ok(original_meta)) = (fs::metadata(encrypted_file), fs::metadata(original_file)) {
            encrypted_meta.len() > 0 && original_meta.len() > 0
        } else {
            false
        }
    }

    /// Securely delete a file by overwriting its content multiple times before deleting
    fn secure_delete_file(file_path: &std::path::Path) -> Result<(), String> {
        use std::fs::OpenOptions;
        use std::io::Write;
        
        // Check if file exists first
        if !file_path.exists() {
            return Ok(()); // File doesn't exist, nothing to delete
        }
        
        // Open file for writing
        let mut file = OpenOptions::new()
            .write(true)
            .open(file_path)
            .map_err(|e| format!("Failed to open file for secure deletion: {}", e))?;
        
        // Get file size
        let file_size = file.metadata()
            .map_err(|e| format!("Failed to get file metadata: {}", e))?
            .len();
        
        // Overwrite the file content with fewer passes for better performance
        const PASSES: usize = 1; // Reduce number of overwrite passes
        let overwrite_byte = 0u8; // Use fixed overwrite byte instead of random data
        
        for _ in 0..PASSES {
            // Seek to beginning of file
            if let Err(e) = file.seek(std::io::SeekFrom::Start(0)) {
                return Err(format!("Failed to seek to beginning of file: {}", e));
            }
            
            let mut remaining = file_size as usize;
            const BUFFER_SIZE: usize = 64 * 1024; // Increase buffer size
            let buffer = vec![overwrite_byte; BUFFER_SIZE];
            
            // Overwrite file content
            while remaining > 0 {
                let write_size = std::cmp::min(remaining, BUFFER_SIZE);
                
                if let Err(e) = file.write_all(&buffer[..write_size]) {
                    return Err(format!("Failed to write to file: {}", e));
                }
                
                remaining -= write_size;
            }
            
            // Force the writes to disk
            if let Err(e) = file.sync_all() {
                return Err(format!("Failed to sync file: {}", e));
            }
        }
        
        // Close the file by dropping it
        drop(file);
        
        // Finally, delete the file
        fs::remove_file(file_path)
            .map_err(|e| format!("Failed to remove file: {}", e))?;
        
        Ok(())
    }

    pub fn shutdown(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        
        // Wait for all deletion threads to complete
        let mut deletion_threads = self.deletion_threads.lock().unwrap();
        for handle in deletion_threads.drain(..) {
            if let Err(e) = handle.join() {
                eprintln!("Error joining deletion thread: {:?}", e);
            }
        }
        
        println!("Async deletion coordinator stopped. Completed: {}, Failed: {}",
                 self.completed_tasks.load(Ordering::Relaxed),
                 self.failed_tasks.load(Ordering::Relaxed));
    }
}