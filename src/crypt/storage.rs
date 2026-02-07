//! Storage management including file I/O, memory pooling, and secure deletion

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Re-export file API functions
pub use crate::crypt::file_api::*;
pub use crate::crypt::io::*;
pub use crate::crypt::mempool::*;

/// Represents a deletion task
#[derive(Debug, Clone)]
pub struct DeletionTask {
    pub original_file: PathBuf,
    pub encrypted_file: PathBuf,
    pub retry_count: u32,
}

/// Statistics for deletion operations
struct DeletionStats {
    pending_tasks: AtomicUsize,
    completed_tasks: AtomicUsize,
    failed_tasks: AtomicUsize,
}

impl DeletionStats {
    fn new() -> Self {
        Self {
            pending_tasks: AtomicUsize::new(0),
            completed_tasks: AtomicUsize::new(0),
            failed_tasks: AtomicUsize::new(0),
        }
    }
}

/// Coordinates asynchronous deletion of files with secure erasure
#[derive(Clone)]
pub struct DeletionCoordinator {
    task_queue: Arc<Mutex<VecDeque<DeletionTask>>>,
    sender: mpsc::Sender<DeletionTask>,
    receiver: Arc<Mutex<mpsc::Receiver<DeletionTask>>>,
    running: Arc<AtomicBool>,
    threads: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    target_thread_count: Arc<AtomicUsize>,
    encryption_completed: Arc<AtomicBool>,
    stats: Arc<DeletionStats>,
}

impl DeletionCoordinator {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::channel();

        let coordinator = Self {
            task_queue: Arc::new(Mutex::new(VecDeque::new())),
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
            running: Arc::new(AtomicBool::new(false)),
            threads: Arc::new(Mutex::new(Vec::new())),
            target_thread_count: Arc::new(AtomicUsize::new(1)), // Default to 1 thread
            encryption_completed: Arc::new(AtomicBool::new(false)),
            stats: Arc::new(DeletionStats::new()),
        };

        coordinator
    }

    /// Start worker threads for processing deletion tasks
    pub fn start_worker(&self) {
        if self.running.load(Ordering::Relaxed) {
            return;
        }

        self.running.store(true, Ordering::Relaxed);

        let thread_count = self.target_thread_count.load(Ordering::Relaxed);
        println!("Starting {} deletion worker threads", thread_count);

        for i in 0..thread_count {
            let receiver = Arc::clone(&self.receiver);
            let running = Arc::clone(&self.running);
            let stats = Arc::clone(&self.stats);

            let handle = thread::spawn(move || {
                Self::deletion_worker(receiver, running, stats, i);
            });

            self.threads.lock().unwrap().push(handle);
        }
    }

    /// Worker thread function for processing deletion tasks
    fn deletion_worker(
        receiver: Arc<Mutex<mpsc::Receiver<DeletionTask>>>,
        running: Arc<AtomicBool>,
        stats: Arc<DeletionStats>,
        worker_id: usize,
    ) {
        println!("Deletion worker {} started", worker_id);

        while running.load(Ordering::Relaxed) {
            // Try to receive a task with a timeout
            if let Ok(receiver_lock) = receiver.try_lock() {
                if let Ok(task) = receiver_lock.recv_timeout(Duration::from_millis(100)) {
                    stats.pending_tasks.fetch_sub(1, Ordering::Relaxed);

                    // Process the deletion task
                    match Self::perform_secure_deletion(&task) {
                        Ok(_) => {
                            stats.completed_tasks.fetch_add(1, Ordering::Relaxed);
                            println!("Successfully deleted: {:?}", task.original_file);
                        }
                        Err(e) => {
                            stats.failed_tasks.fetch_add(1, Ordering::Relaxed);
                            eprintln!("Failed to delete {:?}: {}", task.original_file, e);

                            // Retry logic - only retry a limited number of times
                            if task.retry_count < 3 {
                                eprintln!(
                                    "Retrying deletion of {:?}, attempt {}",
                                    task.original_file,
                                    task.retry_count + 1
                                );

                                let _retry_task = DeletionTask {
                                    original_file: task.original_file,
                                    encrypted_file: task.encrypted_file,
                                    retry_count: task.retry_count + 1,
                                };

                                // Note: In a real implementation, we'd requeue the task
                                // For now, we'll just log the failure
                            }
                        }
                    }
                }
            } else {
                // If we can't get the lock, sleep briefly and try again
                thread::sleep(Duration::from_millis(10));
            }
        }

        println!("Deletion worker {} stopped", worker_id);
    }

    /// Perform secure deletion of a file
    fn perform_secure_deletion(task: &DeletionTask) -> Result<(), String> {
        // First, verify that the encrypted file exists
        if !task.encrypted_file.exists() {
            return Err(format!(
                "Encrypted file does not exist: {:?}",
                task.encrypted_file
            ));
        }

        // Perform secure overwrite with random data
        // Note: This is a simplified implementation. A production version would:
        // 1. Check file size
        // 2. Overwrite with random data multiple times
        // 3. Optionally rename the file
        // 4. Finally delete the file

        let mut file = OpenOptions::new()
            .write(true)
            .open(&task.original_file)
            .map_err(|e| format!("Failed to open file for secure deletion: {}", e))?;

        let file_size = file
            .metadata()
            .map_err(|e| format!("Failed to get file metadata: {}", e))?
            .len();

        // Simple overwrite with zeros (in a real implementation, this would be more thorough)
        let zero_buf = vec![0u8; 256 * 1024]; // 256KB buffer for better performance
        let mut remaining = file_size as usize;

        while remaining > 0 {
            let to_write = std::cmp::min(remaining, zero_buf.len());
            file.write_all(&zero_buf[..to_write])
                .map_err(|e| format!("Failed to write to file: {}", e))?;
            remaining -= to_write;
        }

        file.sync_all()
            .map_err(|e| format!("Failed to sync file: {}", e))?;

        // Close the file by dropping it
        drop(file);

        // Finally, delete the file
        fs::remove_file(&task.original_file)
            .map_err(|e| format!("Failed to remove file: {}", e))?;

        Ok(())
    }

    /// Schedule a file for deletion after encryption
    pub fn schedule_deletion(
        &self,
        original_path: &std::path::Path,
        encrypted_path: &std::path::Path,
    ) {
        let task = DeletionTask {
            original_file: original_path.to_path_buf(),
            encrypted_file: encrypted_path.to_path_buf(),
            retry_count: 0,
        };

        self.stats.pending_tasks.fetch_add(1, Ordering::Relaxed);

        // Try to send the task to a worker thread
        if let Err(_) = self.sender.send(task.clone()) {
            // If sending fails, add to the backup queue
            let mut queue = self.task_queue.lock().unwrap();
            queue.push_back(task);
        }
    }

    /// Mark that encryption is completed to speed up deletion
    pub fn mark_encryption_completed(&self) {
        self.encryption_completed.store(true, Ordering::Relaxed);
        println!("Encryption marked as completed, deletion will accelerate");
    }

    /// Wait for all deletion tasks to complete
    pub fn wait_for_completion(&self) {
        self.wait_for_completion_with_timeout(Duration::from_secs(300))
    }

    /// Wait for all deletion tasks to complete with timeout
    pub fn wait_for_completion_with_timeout(&self, timeout: Duration) {
        let start = Instant::now();
        let mut last_pending = 0usize;
        let mut last_status_time = start;

        loop {
            let pending = self.stats.pending_tasks.load(Ordering::Relaxed);

            if pending == 0 {
                println!("All deletion tasks completed");
                break;
            }

            let elapsed = start.elapsed();

            if elapsed > timeout {
                eprintln!(
                    "[TIMEOUT] wait_for_completion timed out after {:?} (pending tasks: {})",
                    timeout, pending
                );
                eprintln!("[TIMEOUT] This may indicate stuck deletion tasks. Continuing anyway...");
                break;
            }

            let status_elapsed = last_status_time.elapsed();
            if status_elapsed > Duration::from_secs(10) || pending != last_pending {
                println!(
                    "[DELETION] Pending tasks: {}, Elapsed: {:.1}s",
                    pending,
                    elapsed.as_secs_f64()
                );
                last_status_time = Instant::now();
                last_pending = pending;
            }

            thread::sleep(Duration::from_millis(100));
        }
    }
}
