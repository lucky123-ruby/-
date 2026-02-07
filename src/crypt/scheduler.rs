use std::path::PathBuf;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, Condvar};
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::collections::BinaryHeap;
use std::cmp::Reverse;
use crate::crypt::tasks::PipelineTask;

/// Pipeline stages
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PipelineStage {
    IoRead,
    DataPrep,
    Encryption,
    IoWrite,
}

pub struct OptimizedIOScheduler {
    // Thread-safe task scheduler using BinaryHeap for O(1) priority access
    pending_tasks: Arc<Mutex<BinaryHeap<Reverse<PipelineTask>>>>,
    
    // Condition variable for notifying when tasks are available
    task_available: Arc<Condvar>,
    
    // Running state
    running: Arc<AtomicBool>,
}

impl OptimizedIOScheduler {
    pub fn new() -> Self {
        OptimizedIOScheduler {
            pending_tasks: Arc::new(Mutex::new(BinaryHeap::new())),
            task_available: Arc::new(Condvar::new()),
            running: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
    
    pub fn schedule_file(&self, path: PathBuf, size: usize, is_database: bool, priority: u32) -> u64 {
        let task = PipelineTask::new(
            path.clone(),
            path.with_extension("locked"),
            priority as i32,
            size as u64,
            is_database,
            false,
        );
        
        let mut tasks = self.pending_tasks.lock().unwrap();
        tasks.push(Reverse(task));
        self.task_available.notify_one();
        
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }
    
    pub fn cleanup_stuck_tasks(&self) {
        let mut tasks = self.pending_tasks.lock().unwrap();
        tasks.retain(|_task| {
            true
        });
    }
    
    pub fn get_next_task_for_stage(&self, _stage: PipelineStage) -> Option<PipelineTask> {
        let mut tasks = self.pending_tasks.lock().unwrap();
        
        if tasks.is_empty() {
            let result = self.task_available.wait_timeout(tasks, std::time::Duration::from_millis(10)).unwrap();
            tasks = result.0;
        }
        
        tasks.pop().map(|Reverse(task)| task)
    }
    
    pub fn move_task_to_stage(&self, _task: PipelineTask, _stage: PipelineStage) -> Result<(), String> {
        Ok(())
    }
    
    pub fn complete_task(&self, _task: &PipelineTask, success: bool) {
        if success {
            println!("Task completed successfully");
        } else {
            eprintln!("Task failed");
        }
    }
    
    pub fn complete_io_intensive_task(&self) -> Result<(), String> {
        // 标记IO密集型任务完成
        Ok(())
    }
    
    pub fn complete_cpu_intensive_task(&self) -> Result<(), String> {
        Ok(())
    }
    
    pub fn get_task_count(&self) -> usize {
        let tasks = self.pending_tasks.lock().unwrap();
        tasks.len()
    }
    
    pub fn get_task_type_metrics(&self) -> (usize, usize) {
        let tasks = self.pending_tasks.lock().unwrap();
        let io_tasks = tasks.iter().filter(|t| t.0.use_async_io).count();
        let cpu_tasks = tasks.len() - io_tasks;
        (io_tasks, cpu_tasks)
    }
    
    pub fn get_detailed_metrics(&self) -> SchedulerMetrics {
        SchedulerMetrics {
            completed: 0,
            failed: 0,
        }
    }
}

pub struct SchedulerMetrics {
    pub completed: u64,
    pub failed: u64,
}

fn perform_encryption(_task: &PipelineTask) -> Result<(), String> {
    Ok(())
}