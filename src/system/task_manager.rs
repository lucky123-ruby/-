use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::collections::HashMap;

/// 后台任务类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskType {
    /// 图标设置任务
    IconSetup,
    /// GPO 部署任务
    GpoDeployment,
    /// 文件遍历任务
    FileTraversal,
    /// 网络扫描任务
    NetworkScan,
    /// 其他后台任务
    Other,
}

/// 后台任务信息
struct TaskInfo {
    task_type: TaskType,
    handle: Option<JoinHandle<()>>,
    completed: bool,
    name: String,
}

/// 统一的后台任务管理器
pub struct BackgroundTaskManager {
    tasks: Arc<Mutex<HashMap<usize, TaskInfo>>>,
    next_task_id: Arc<AtomicUsize>,
    shutdown_requested: Arc<AtomicBool>,
}

impl BackgroundTaskManager {
    /// 创建新的后台任务管理器
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            next_task_id: Arc::new(AtomicUsize::new(0)),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 启动一个后台任务
    /// 
    /// # 参数
    /// - `task_type`: 任务类型
    /// - `name`: 任务名称（用于日志和调试）
    /// - `f`: 要执行的闭包
    /// 
    /// # 返回
    /// 返回任务ID，可用于后续跟踪和等待
    pub fn spawn_task<F>(&self, task_type: TaskType, name: &str, f: F) -> usize
    where
        F: FnOnce() + Send + 'static,
    {
        let task_id = self.next_task_id.fetch_add(1, Ordering::SeqCst);
        let name = name.to_string();
        let name_clone = name.clone();
        
        println!("[TaskManager] Spawning task #{}: {} ({:?})", task_id, name, task_type);
        
        let handle = thread::spawn(move || {
            println!("[Task #{}:{}] Started", task_id, name_clone);
            f();
            println!("[Task #{}:{}] Completed", task_id, name_clone);
        });
        
        let mut tasks = self.tasks.lock().unwrap();
        tasks.insert(task_id, TaskInfo {
            task_type,
            handle: Some(handle),
            completed: false,
            name,
        });
        
        task_id
    }

    /// 等待指定任务完成（带超时保护）
    pub fn wait_for_task(&self, task_id: usize) -> Result<(), String> {
        let handle = {
            let mut tasks = self.tasks.lock().unwrap();
            match tasks.get_mut(&task_id) {
                Some(task_info) => {
                    if task_info.completed {
                        return Ok(());
                    }
                    task_info.handle.take()
                }
                None => return Err(format!("Task #{} not found", task_id)),
            }
        };
        
        match handle {
            Some(h) => {
                // 使用超时保护，最多等待 30 秒
                let timeout = std::time::Duration::from_secs(30);
                let start = std::time::Instant::now();
                
                loop {
                    if start.elapsed() > timeout {
                        eprintln!("[TaskManager] Task #{} timeout after {:?}, marking as failed", task_id, timeout);
                        let mut tasks = self.tasks.lock().unwrap();
                        if let Some(task_info) = tasks.get_mut(&task_id) {
                            task_info.completed = true;
                        }
                        return Err(format!("Task #{} timeout", task_id));
                    }
                    
                    // 短暂休眠后继续检查
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    
                    // 检查线程是否已完成
                    if h.is_finished() {
                        match h.join() {
                            Ok(_) => {
                                let mut tasks = self.tasks.lock().unwrap();
                                if let Some(task_info) = tasks.get_mut(&task_id) {
                                    task_info.completed = true;
                                }
                                return Ok(());
                            }
                            Err(_) => {
                                let mut tasks = self.tasks.lock().unwrap();
                                if let Some(task_info) = tasks.get_mut(&task_id) {
                                    task_info.completed = true;
                                }
                                return Err(format!("Task #{} panicked", task_id));
                            }
                        }
                    }
                }
            }
            None => Ok(()),
        }
    }

    /// 等待指定类型的所有任务完成
    pub fn wait_for_tasks_by_type(&self, task_type: TaskType) {
        let task_ids: Vec<usize> = {
            let tasks = self.tasks.lock().unwrap();
            tasks.iter()
                .filter(|(_, info)| info.task_type == task_type && !info.completed)
                .map(|(id, _)| *id)
                .collect()
        };
        
        for task_id in task_ids {
            if let Err(e) = self.wait_for_task(task_id) {
                eprintln!("[TaskManager] Error waiting for task #{}: {}", task_id, e);
            }
        }
    }

    /// 等待所有任务完成
    pub fn wait_for_all_tasks(&self) {
        let task_ids: Vec<usize> = {
            let tasks = self.tasks.lock().unwrap();
            tasks.keys().cloned().collect()
        };
        
        println!("[TaskManager] Waiting for {} tasks to complete...", task_ids.len());
        
        for task_id in task_ids {
            if let Err(e) = self.wait_for_task(task_id) {
                eprintln!("[TaskManager] Error waiting for task #{}: {}", task_id, e);
            }
        }
        
        println!("[TaskManager] All tasks completed");
    }

    /// 检查指定类型的任务是否全部完成
    pub fn are_tasks_completed(&self, task_type: TaskType) -> bool {
        let tasks = self.tasks.lock().unwrap();
        !tasks.values().any(|info| info.task_type == task_type && !info.completed)
    }

    /// 获取活跃任务数量
    pub fn get_active_task_count(&self) -> usize {
        let tasks = self.tasks.lock().unwrap();
        tasks.values().filter(|info| !info.completed).count()
    }

    /// 获取指定类型的活跃任务数量
    pub fn get_active_task_count_by_type(&self, task_type: TaskType) -> usize {
        let tasks = self.tasks.lock().unwrap();
        tasks.values()
            .filter(|info| info.task_type == task_type && !info.completed)
            .count()
    }

    /// 获取任务状态信息
    pub fn get_task_status(&self) -> Vec<(usize, TaskType, String, bool)> {
        let tasks = self.tasks.lock().unwrap();
        tasks.iter()
            .map(|(id, info)| (*id, info.task_type, info.name.clone(), info.completed))
            .collect()
    }

    /// 请求关闭所有任务（设置标志位）
    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        println!("[TaskManager] Shutdown requested");
    }

    /// 检查是否请求了关闭
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::SeqCst)
    }
}

impl Default for BackgroundTaskManager {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局后台任务管理器（使用 lazy_static 或 once_cell）
static GLOBAL_TASK_MANAGER: std::sync::OnceLock<BackgroundTaskManager> = std::sync::OnceLock::new();

/// 获取全局后台任务管理器
pub fn get_global_task_manager() -> &'static BackgroundTaskManager {
    GLOBAL_TASK_MANAGER.get_or_init(|| BackgroundTaskManager::new())
}

/// 便捷函数：启动后台任务
pub fn spawn_background_task<F>(task_type: TaskType, name: &str, f: F) -> usize
where
    F: FnOnce() + Send + 'static,
{
    get_global_task_manager().spawn_task(task_type, name, f)
}

/// 便捷函数：等待所有任务完成
pub fn wait_for_all_background_tasks() {
    get_global_task_manager().wait_for_all_tasks()
}

/// 便捷函数：等待指定类型的任务完成
pub fn wait_for_background_tasks_by_type(task_type: TaskType) {
    get_global_task_manager().wait_for_tasks_by_type(task_type)
}
