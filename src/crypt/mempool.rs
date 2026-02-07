//! Cross-platform aligned memory pool with per-thread optimization.
//! Provide allocate/deallocate API with reduced lock contention.

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::cell::RefCell;

// 添加原子计数器以更好地跟踪内存使用情况
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};

#[cfg(target_os = "windows")]
fn get_available_memory() -> usize {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    
    unsafe {
        let mut status = MEMORYSTATUSEX::default();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        
        if GlobalMemoryStatusEx(&mut status).is_ok() {
            status.ullAvailPhys as usize
        } else {
            4 * 1024 * 1024 * 1024
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn get_available_memory() -> usize {
    use sysinfo::System;
    
    let mut sys = System::new_all();
    sys.refresh_all();
    
    sys.available_memory() as usize
}

pub fn get_optimal_local_pool_size() -> usize {
    let available_memory = get_available_memory();
    
    if available_memory < 4 * 1024 * 1024 * 1024 {
        32
    } else if available_memory < 16 * 1024 * 1024 * 1024 {
        64
    } else {
        128
    }
}

#[derive(Clone)]
pub struct AlignedMemoryPool {
    inner: Arc<Mutex<MemoryPoolInner>>,
    thread_local_pool: Arc<ThreadLocalPool>,
    stats: Arc<MemoryPoolStats>,
    monitor: Arc<MemoryMonitor>,
}

// 内存池统计信息
#[derive(Debug)]
struct MemoryPoolStats {
    total_allocated: AtomicU64,
    total_deallocated: AtomicU64,
    total_reused: AtomicU64,
    peak_memory: AtomicU64,
}

struct ThreadLocalPool {
    // Global pool for blocks that don't fit in thread-local storage
    global_pool: Arc<Mutex<MemoryPoolInner>>,
}

struct MemoryPoolInner {
    blocks: HashMap<usize, Vec<Vec<u8>>>,
    alignment: usize,
    allocated: usize,
    peak_allocated: usize,
}

impl AlignedMemoryPool {
    pub fn new(_initial_size: usize, alignment: usize) -> Self {
        let inner = MemoryPoolInner {
            blocks: HashMap::new(),
            alignment,
            allocated: 0,
            peak_allocated: 0,
        };
        
        let stats = Arc::new(MemoryPoolStats {
            total_allocated: AtomicU64::new(0),
            total_deallocated: AtomicU64::new(0),
            total_reused: AtomicU64::new(0),
            peak_memory: AtomicU64::new(0),
        });
        
        let monitor = Arc::new(MemoryMonitor::new());
        
        let pool = Self {
            inner: Arc::new(Mutex::new(inner)),
            thread_local_pool: Arc::new(ThreadLocalPool {
                global_pool: Arc::new(Mutex::new(MemoryPoolInner {
                    blocks: HashMap::new(),
                    alignment,
                    allocated: 0,
                    peak_allocated: 0,
                })),
            }),
            stats: stats.clone(),
            monitor: monitor.clone(),
        };
        
        pool.preallocate_memory();
        pool
    }
    
    fn preallocate_memory(&self) {
        // More aggressive preallocation set inspired by crypt1.h sizes
        let sizes = [64usize, 256, 1024, 4096, 16384, 65536, 262144, 1048576];

        let mut inner = self.inner.lock().unwrap();

        for size in &sizes {
            let aligned_size = Self::align_size(*size, inner.alignment);
            let entry = inner.blocks.entry(aligned_size).or_insert_with(Vec::new);

            // 根据块大小调整预分配数量，更好地平衡内存使用和性能
            let count = match *size {
                s if s <= 1024 => 256,      // 小块多预分配 (64 → 256, 4倍)
                s if s <= 16384 => 128,     // 中等块适量预分配 (32 → 128, 4倍)
                s if s <= 65536 => 64,      // 大块少预分配 (16 → 64, 4倍)
                _ => 32,                    // 超大块最少预分配 (8 → 32, 4倍)
            };

            for _ in 0..count {
                let block = vec![0u8; aligned_size];
                entry.push(block);
            }
        }
    }
    
    /// Align size to the required boundary
    fn align_size(size: usize, alignment: usize) -> usize {
        (size + alignment - 1) & !(alignment - 1)
    }
    
    /// Get the alignment requirement of this memory pool
    pub fn alignment(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.alignment
    }
    
    #[inline(always)]
    pub fn allocate(&self, size: usize) -> Option<Vec<u8>> {
        let aligned_size = Self::align_size(size, self.alignment());
        
        self.stats.total_allocated.fetch_add(size as u64, Ordering::Relaxed);
        self.monitor.record_allocation(aligned_size);
        
        let local_block = LOCAL_FREE_LIST.with(|free_list| {
            let mut list = free_list.borrow_mut();
            for i in (0..list.len()).rev() {
                if list[i].capacity() == aligned_size {
                    self.stats.total_reused.fetch_add(1, Ordering::Relaxed);
                    return Some(list.swap_remove(i));
                }
            }
            None
        });
        
        if let Some(block) = local_block {
            let mut inner = self.inner.lock().unwrap();
            inner.allocated = inner.allocated.saturating_add(size);
            inner.peak_allocated = inner.peak_allocated.max(inner.allocated);
            return Some(block);
        }
        
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(blocks) = inner.blocks.get_mut(&aligned_size) {
                if let Some(block) = blocks.pop() {
                    inner.allocated = inner.allocated.saturating_add(size);
                    inner.peak_allocated = inner.peak_allocated.max(inner.allocated);
                    self.stats.total_reused.fetch_add(1, Ordering::Relaxed);
                    return Some(block);
                }
            }
        }
        
        let block = vec![0u8; aligned_size];
        let mut inner = self.inner.lock().unwrap();
        inner.allocated = inner.allocated.saturating_add(size);
        inner.peak_allocated = inner.peak_allocated.max(inner.allocated);
        Some(block)
    }
    
    /// 释放内存块，将其返回到合适的池中
    #[inline(always)]
    pub fn deallocate(&self, mut block: Vec<u8>) {
        let capacity = block.capacity();
        self.stats.total_deallocated.fetch_add(capacity as u64, Ordering::Relaxed);
        self.monitor.record_deallocation(capacity);
        
        let mut block_opt = Some(block);
        let placed_locally = LOCAL_FREE_LIST.with(|free_list| {
            let mut list = free_list.borrow_mut();
            let limit = get_optimal_local_pool_size();
            if list.len() < limit {
                if let Some(b) = block_opt.take() {
                    list.push(b);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        });
        
        if !placed_locally {
            if let Some(b) = block_opt {
                let mut inner = self.inner.lock().unwrap();
                let entry = inner.blocks.entry(capacity).or_insert_with(|| Vec::new());
                if entry.len() < 128 {
                    entry.push(b);
                }
            }
        }
    }
    
    /// 获取内存池统计信息
    pub fn get_stats(&self) -> MemoryPoolStatsSnapshot {
        MemoryPoolStatsSnapshot {
            total_allocated: self.stats.total_allocated.load(Ordering::Relaxed),
            total_deallocated: self.stats.total_deallocated.load(Ordering::Relaxed),
            total_reused: self.stats.total_reused.load(Ordering::Relaxed),
            peak_memory: self.stats.peak_memory.load(Ordering::Relaxed),
        }
    }
    
    pub fn get_monitor_stats(&self) -> MemoryMonitorStats {
        self.monitor.get_stats()
    }
}

/// 内存池统计信息快照
#[derive(Debug, Clone)]
pub struct MemoryPoolStatsSnapshot {
    pub total_allocated: u64,
    pub total_deallocated: u64,
    pub total_reused: u64,
    pub peak_memory: u64,
}

// Thread-local storage for per-thread free lists
pub struct MemoryMonitor {
    peak_usage: AtomicU64,
    allocation_failures: AtomicU64,
    current_usage: AtomicU64,
}

impl MemoryMonitor {
    pub fn new() -> Self {
        Self {
            peak_usage: AtomicU64::new(0),
            allocation_failures: AtomicU64::new(0),
            current_usage: AtomicU64::new(0),
        }
    }
    
    pub fn record_allocation(&self, size: usize) {
        let current = self.current_usage.fetch_add(size as u64, Ordering::Relaxed);
        let new_usage = current + size as u64;
        
        let mut peak = self.peak_usage.load(Ordering::Relaxed);
        while new_usage > peak {
            match self.peak_usage.compare_exchange_weak(
                peak,
                new_usage,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }
    
    pub fn record_deallocation(&self, size: usize) {
        self.current_usage.fetch_sub(size as u64, Ordering::Relaxed);
    }
    
    pub fn record_failure(&self) {
        self.allocation_failures.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_stats(&self) -> MemoryMonitorStats {
        MemoryMonitorStats {
            peak_usage: self.peak_usage.load(Ordering::Relaxed),
            allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
            current_usage: self.current_usage.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MemoryMonitorStats {
    pub peak_usage: u64,
    pub allocation_failures: u64,
    pub current_usage: u64,
}

thread_local! {
    static LOCAL_FREE_LIST: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
}