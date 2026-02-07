use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::crypt::config::Config;
use crate::crypt::three_layer_pipeline::ThreeLayerPipeline;
use crate::crypt::utils;

#[derive(Debug, Clone)]
pub struct RetryTask {
    pub file_path: PathBuf,
    pub retry_count: u32,
    pub max_retries: u32,
    pub error_message: String,
}

unsafe impl Send for RetryTask {}
unsafe impl Sync for RetryTask {}

pub struct BackgroundRetryHandler {
    running: Arc<AtomicBool>,
    task_tx_list: Arc<Vec<Sender<RetryTask>>>,
    pipeline: Arc<ThreeLayerPipeline>,
    config: Arc<Config>,

    retry_count: Arc<AtomicU64>,
    success_count: Arc<AtomicU64>,
    failed_count: Arc<AtomicU64>,

    worker_count: usize,
    next_worker: Arc<AtomicUsize>,

    rx_list: Option<Vec<Receiver<RetryTask>>>,
}

unsafe impl Send for BackgroundRetryHandler {}
unsafe impl Sync for BackgroundRetryHandler {}

impl BackgroundRetryHandler {
    pub fn new(pipeline: Arc<ThreeLayerPipeline>, config: Arc<Config>) -> Self {
        let worker_count = 2;
        let mut task_tx_list = Vec::with_capacity(worker_count);
        let mut rx_list = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let (tx, rx) = channel();
            task_tx_list.push(tx);
            rx_list.push(rx);
        }

        Self {
            running: Arc::new(AtomicBool::new(false)),
            task_tx_list: Arc::new(task_tx_list),
            pipeline,
            config,
            retry_count: Arc::new(AtomicU64::new(0)),
            success_count: Arc::new(AtomicU64::new(0)),
            failed_count: Arc::new(AtomicU64::new(0)),
            worker_count,
            next_worker: Arc::new(AtomicUsize::new(0)),
            rx_list: Some(rx_list),
        }
    }

    pub fn start(&mut self) {
        println!(
            "[RETRY] Starting background retry handler with {} workers",
            self.worker_count
        );

        self.running.store(true, Ordering::SeqCst);

        let mut rx_list = self.rx_list.take().unwrap_or_default();

        for worker_id in 0..self.worker_count {
            let rx = rx_list.pop().unwrap();

            let pipeline = self.pipeline.clone();
            let config = self.config.clone();
            let running = self.running.clone();
            let retry_count = self.retry_count.clone();
            let success_count = self.success_count.clone();
            let failed_count = self.failed_count.clone();

            thread::spawn(move || {
                Self::retry_worker(
                    worker_id,
                    rx,
                    pipeline,
                    config,
                    running,
                    retry_count,
                    success_count,
                    failed_count,
                );
            });
        }

        println!(
            "[RETRY] Background retry handler started with {} workers",
            self.worker_count
        );
    }

    pub fn stop(&self) {
        println!("[RETRY] Stopping background retry handler...");
        self.running.store(false, Ordering::SeqCst);

        let retry_count = self.retry_count.load(Ordering::Relaxed);
        let success_count = self.success_count.load(Ordering::Relaxed);
        let failed_count = self.failed_count.load(Ordering::Relaxed);

        println!(
            "[RETRY] Retry statistics - Total: {}, Success: {}, Failed: {}",
            retry_count, success_count, failed_count
        );
    }

    pub fn add_retry_task(&self, file_path: &Path, error_message: String) {
        let task = RetryTask {
            file_path: file_path.to_path_buf(),
            retry_count: 0,
            max_retries: 5,
            error_message,
        };

        self.retry_count.fetch_add(1, Ordering::Relaxed);

        let worker_id = self.next_worker.fetch_add(1, Ordering::Relaxed) % self.worker_count;

        if let Err(e) = self.task_tx_list[worker_id].send(task) {
            eprintln!(
                "[RETRY] Failed to add retry task to worker {}: {}",
                worker_id, e
            );
        }
    }

    fn retry_worker(
        worker_id: usize,
        rx: Receiver<RetryTask>,
        pipeline: Arc<ThreeLayerPipeline>,
        _config: Arc<Config>,
        running: Arc<AtomicBool>,
        retry_count: Arc<AtomicU64>,
        success_count: Arc<AtomicU64>,
        failed_count: Arc<AtomicU64>,
    ) {
        println!("[RETRY] Worker {} started", worker_id);

        let mut local_retry_queue: Vec<RetryTask> = Vec::new();

        while running.load(Ordering::Relaxed) {
            let task = if let Some(task) = local_retry_queue.pop() {
                task
            } else {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(task) => task,
                    Err(_) => {
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                        continue;
                    }
                }
            };

            if let Err(e) = Self::process_retry_task(&pipeline, &task) {
                if task.retry_count < task.max_retries {
                    let new_task = RetryTask {
                        file_path: task.file_path.clone(),
                        retry_count: task.retry_count + 1,
                        max_retries: task.max_retries,
                        error_message: e.clone(),
                    };

                    let delay_ms = [100u64, 200, 400, 800][task.retry_count as usize];
                    let delay = Duration::from_millis(delay_ms);
                    thread::sleep(delay);

                    local_retry_queue.push(new_task);
                } else {
                    failed_count.fetch_add(1, Ordering::Relaxed);
                    eprintln!(
                        "[RETRY] Worker {} - Gave up on {:?} after {} attempts: {}",
                        worker_id, task.file_path, task.max_retries, e
                    );
                }
            } else {
                success_count.fetch_add(1, Ordering::Relaxed);
                println!(
                    "[RETRY] Worker {} - Successfully processed {:?}",
                    worker_id, task.file_path
                );
            }
        }

        println!("[RETRY] Worker {} stopped", worker_id);
    }

    fn process_retry_task(pipeline: &ThreeLayerPipeline, task: &RetryTask) -> Result<(), String> {
        let file_path = &task.file_path;

        if !file_path.exists() {
            return Err(format!("File no longer exists: {:?}", file_path));
        }

        if Self::is_file_locked_with_timeout(file_path, Duration::from_secs(1)) {
            return Err(format!("File still locked: {:?}", file_path));
        }

        match pipeline.add_file_for_retry(file_path) {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.contains("Failed to send encryption task") || e.contains("channel") {
                    Err(format!("Pipeline channel busy: {}", e))
                } else {
                    Err(format!("Failed to add file to pipeline: {}", e))
                }
            }
        }
    }

    fn is_file_locked_with_timeout<P: AsRef<Path>>(file_path: P, timeout: Duration) -> bool {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            match std::fs::File::options()
                .read(true)
                .write(true)
                .open(&file_path)
            {
                Ok(_) => return false,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::PermissionDenied
                        || e.kind() == std::io::ErrorKind::NotFound
                    {
                        return true;
                    }
                }
            }
            thread::sleep(Duration::from_millis(10));
        }

        true
    }

    pub fn get_worker_count(&self) -> usize {
        self.worker_count
    }

    pub fn get_stats(&self) -> (u64, u64, u64) {
        (
            self.retry_count.load(Ordering::Relaxed),
            self.success_count.load(Ordering::Relaxed),
            self.failed_count.load(Ordering::Relaxed),
        )
    }
}
