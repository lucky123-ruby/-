//! Task definitions and scheduler for the encryption pipeline

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Condvar;
use std::sync::{Arc, Mutex};

/// Represents a file encryption task with metadata
#[derive(Debug, Clone)]
pub struct EncryptionTask {
    pub file_path: PathBuf,
    pub file_size: u64,
    pub is_database_file: bool,
    pub priority: i32,
}

impl EncryptionTask {
    pub fn new(file_path: PathBuf, file_size: u64, is_database_file: bool, priority: i32) -> Self {
        Self {
            file_path,
            file_size,
            is_database_file,
            priority,
        }
    }
}

/// Represents a pipeline task
#[derive(Debug, Clone)]
pub struct PipelineTask {
    pub input_path: PathBuf,
    pub output_path: PathBuf,
    pub priority: i32,
    pub file_size: u64,
    pub is_database_file: bool,
    pub use_async_io: bool,
}

impl PipelineTask {
    pub fn new(
        input_path: PathBuf,
        output_path: PathBuf,
        priority: i32,
        file_size: u64,
        is_database_file: bool,
        use_async_io: bool,
    ) -> Self {
        Self {
            input_path,
            output_path,
            priority,
            file_size,
            is_database_file,
            use_async_io,
        }
    }
}

impl PartialEq for PipelineTask {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.input_path == other.input_path
    }
}

impl Eq for PipelineTask {}

impl PartialOrd for PipelineTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PipelineTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}

/// Pipeline stages
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PipelineStage {
    IoRead,
    DataPrep,
    Encryption,
    IoWrite,
}

/// Thread-safe task scheduler
#[derive(Clone)]
pub struct TaskScheduler {
    // Tasks waiting to be processed
    pending_tasks: Arc<Mutex<VecDeque<EncryptionTask>>>,

    // Pipeline tasks - using BinaryHeap for O(log n) priority retrieval
    pipeline_tasks: Arc<Mutex<BinaryHeap<Reverse<PipelineTask>>>>,

    // Condition variable for notifying when tasks are available
    task_available: Arc<Condvar>,

    // Encryption key
    key: Arc<Mutex<[u8; 16]>>,
}

impl TaskScheduler {
    /// Create a new task scheduler
    pub fn new() -> Self {
        Self {
            pending_tasks: Arc::new(Mutex::new(VecDeque::new())),
            pipeline_tasks: Arc::new(Mutex::new(BinaryHeap::new())),
            task_available: Arc::new(Condvar::new()),
            key: Arc::new(Mutex::new([0u8; 16])),
        }
    }

    /// Initialize the encryption key
    pub fn initialize_key(&self, key: [u8; 16]) {
        let mut key_guard = self.key.lock().unwrap();
        *key_guard = key;
    }

    /// Get the encryption key
    pub fn get_key(&self) -> [u8; 16] {
        let key_guard = self.key.lock().unwrap();
        *key_guard
    }

    /// Add a new encryption task
    pub fn add_task(&self, task: EncryptionTask) {
        let mut tasks = self.pending_tasks.lock().unwrap();
        tasks.push_back(task);
        self.task_available.notify_one();
    }

    /// Add a new pipeline task
    pub fn add_pipeline_task(&self, task: PipelineTask) {
        let mut tasks = self.pipeline_tasks.lock().unwrap();
        tasks.push(Reverse(task));
        self.task_available.notify_one();
    }

    /// Get the next task for a specific stage
    pub fn get_next_task_for_stage(&self, _stage: PipelineStage) -> Option<EncryptionTask> {
        let mut tasks = self.pending_tasks.lock().unwrap();

        // If no tasks, wait for a bit
        if tasks.is_empty() {
            let result = self
                .task_available
                .wait_timeout(tasks, std::time::Duration::from_millis(10))
                .unwrap();
            tasks = result.0;
        }

        // Return highest priority task
        if !tasks.is_empty() {
            // Find the task with the highest priority
            let mut best_index = 0;
            let mut best_priority = tasks[0].priority;

            for (i, task) in tasks.iter().enumerate() {
                if task.priority > best_priority {
                    best_priority = task.priority;
                    best_index = i;
                }
            }

            // Remove and return the highest priority task
            Some(tasks.remove(best_index).unwrap())
        } else {
            None
        }
    }

    /// Get the next pipeline task
    pub fn get_next_pipeline_task(&self) -> Option<PipelineTask> {
        let mut tasks = self.pipeline_tasks.lock().unwrap();

        // If no tasks, wait for a bit
        if tasks.is_empty() {
            let result = self
                .task_available
                .wait_timeout(tasks, std::time::Duration::from_millis(10))
                .unwrap();
            tasks = result.0;
        }

        // Return highest priority task - O(log n) operation
        tasks.pop().map(|Reverse(task)| task)
    }

    /// Get the count of pending tasks
    pub fn get_pending_task_count(&self) -> usize {
        let tasks = self.pending_tasks.lock().unwrap();
        tasks.len()
    }

    /// Get the count of pipeline tasks
    pub fn get_pipeline_task_count(&self) -> usize {
        let tasks = self.pipeline_tasks.lock().unwrap();
        tasks.len()
    }
}
