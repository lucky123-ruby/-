//! Optimized pipeline controller and worker logic.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::crypt::config::Config;
use crate::crypt::engine::{EncryptionEngine, KEY_LENGTH};

pub struct OptimizedPipelineController {
    encryption_key: Option<[u8; KEY_LENGTH]>,
    config: Config,
    pipeline_running: Arc<Mutex<bool>>,
    total_files_processed: Arc<Mutex<usize>>,
    total_bytes_processed: Arc<Mutex<u64>>,
    error_count: Arc<Mutex<usize>>,
}

impl OptimizedPipelineController {
    pub fn new(config: &Config) -> Self {
        Self {
            encryption_key: None,
            config: config.clone(),
            pipeline_running: Arc::new(Mutex::new(false)),
            total_files_processed: Arc::new(Mutex::new(0)),
            total_bytes_processed: Arc::new(Mutex::new(0)),
            error_count: Arc::new(Mutex::new(0)),
        }
    }

    pub fn initialize_pipeline(&mut self, key: &[u8; KEY_LENGTH]) -> bool {
        self.encryption_key = Some(*key);
        true
    }

    pub fn add_encryption_task(&self, _input: &Path, _output: &Path, _priority: i32) {
        // Placeholder for network encryption mode
        // This is only used for network mapping, not actual encryption
    }

    pub fn wait_for_completion(&self) {
        self.wait_for_completion_with_timeout(None)
    }

    pub fn wait_for_completion_with_timeout(&self, timeout: Option<std::time::Duration>) {
        let start = Instant::now();
        let mut last_status_time = start;
        
        loop {
            let running = *self.pipeline_running.lock().unwrap_or_else(|e| {
                eprintln!("[Pipeline] Lock poisoned: {}, using default value", e);
                e.into_inner()
            });
            
            if !running {
                println!("[Pipeline] Pipeline stopped");
                break;
            }
            
            if let Some(timeout) = timeout {
                if start.elapsed() > timeout {
                    eprintln!("[Pipeline] wait_for_completion timed out after {:?}", timeout);
                    break;
                }
            }
            
            let status_elapsed = last_status_time.elapsed();
            if status_elapsed > std::time::Duration::from_secs(5) {
                let files = *self.total_files_processed.lock().unwrap_or_else(|e| {
                    eprintln!("[Pipeline] Lock poisoned: {}, using default value", e);
                    e.into_inner()
                });
                let bytes = *self.total_bytes_processed.lock().unwrap_or_else(|e| {
                    eprintln!("[Pipeline] Lock poisoned: {}, using default value", e);
                    e.into_inner()
                });
                let errors = *self.error_count.lock().unwrap_or_else(|e| {
                    eprintln!("[Pipeline] Lock poisoned: {}, using default value", e);
                    e.into_inner()
                });
                
                println!("[Pipeline] Status - Files: {}, Bytes: {}, Errors: {}, Elapsed: {:.1}s", 
                    files, bytes, errors, start.elapsed().as_secs_f64());
                last_status_time = Instant::now();
            }
            
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    pub fn shutdown_pipeline(&mut self) {
        match self.pipeline_running.lock() {
            Ok(mut running) => {
                *running = false;
            }
            Err(e) => {
                eprintln!("[Pipeline] Lock poisoned during shutdown: {}, forcing shutdown", e);
                *e.into_inner() = false;
            }
        }
    }
}

impl Drop for OptimizedPipelineController {
    fn drop(&mut self) {
        self.shutdown_pipeline();
    }
}

// Implement PipelineControllerTrait for network encryption
impl crate::crypt::network::PipelineControllerTrait for OptimizedPipelineController {
    fn add_encryption_task(&self, _input: &Path, _output: &Path, _priority: i32) {
        // Placeholder for network encryption mode
        // This is only used for network mapping, not actual encryption
    }

    fn wait_for_completion(&self) {
        // Delegate to the implementation with timeout
        self.wait_for_completion()
    }
}
