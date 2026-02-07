// TODO: ThreadAffinityManager skeleton
// Expected API (based on crypt1.h):
// pub struct ThreadAffinityManager { /* fields */ }
// impl ThreadAffinityManager {
//     pub fn new() -> Self;
//     pub fn set_thread_affinity(&self, thread_id: usize, core_id: usize) -> bool;
//     pub fn set_current_thread_affinity(&self, core_id: usize) -> bool;
// }

//! Cross-platform thread affinity management with NUMA support (Linux only).
//!
//! This module provides a cross-platform abstraction for setting thread
//! affinity. On Windows, it uses SetThreadAffinityMask via windows crate. On
//! Linux, it uses pthread_setaffinity_np. On unsupported platforms,
//! it provides a no-op implementation that always returns true.
//!
//! NUMA (Non-Uniform Memory Access) optimization is available on Linux systems
//! with multiple NUMA nodes to improve memory locality.

use std::sync::Arc;

#[cfg(target_os = "linux")]
mod linux {
    use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO};
    use std::mem;

    pub fn set_current_thread_affinity(core_id: usize) -> bool {
        unsafe {
            let mut set: cpu_set_t = mem::zeroed();
            CPU_ZERO(&mut set);
            CPU_SET(core_id, &mut set);

            let result = sched_setaffinity(0, mem::size_of::<cpu_set_t>(), &set);
            result == 0
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use windows::Win32::System::Threading::{GetCurrentThread, SetThreadAffinityMask};

    pub fn set_current_thread_affinity(core_id: usize) -> bool {
        let max_cores = std::mem::size_of::<usize>() * 8;
        if core_id >= max_cores {
            return false;
        }

        unsafe {
            let thread = GetCurrentThread();
            if thread.is_invalid() {
                return false;
            }

            let mask: usize = 1usize << core_id;
            let res = SetThreadAffinityMask(thread, mask);

            res != 0
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
mod other {
    pub fn set_current_thread_affinity(_core_id: usize) -> bool {
        true
    }
}

/// NUMA 节点信息
#[derive(Debug, Clone)]
pub struct NUMANode {
    pub node_id: usize,
    pub core_count: usize,
    pub core_ids: Vec<usize>,
}

#[derive(Clone)]
pub struct ThreadAffinityManager {
    inner: Arc<ThreadAffinityInner>,
}

struct ThreadAffinityInner {
    processor_count: usize,
    numa_enabled: bool,
    numa_nodes: Vec<NUMANode>,
}

impl ThreadAffinityManager {
    pub fn new() -> Self {
        let processor_count = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let (numa_enabled, numa_nodes) = Self::detect_numa_support(processor_count);

        if numa_enabled {
            println!("[NUMA] NUMA support detected: {} nodes", numa_nodes.len());
        }

        Self {
            inner: Arc::new(ThreadAffinityInner {
                processor_count,
                numa_enabled,
                numa_nodes,
            }),
        }
    }

    /// 检测 NUMA 支持 (仅 Linux)
    fn detect_numa_support(processor_count: usize) -> (bool, Vec<NUMANode>) {
        #[cfg(target_os = "linux")]
        {
            Self::detect_numa_linux(processor_count)
        }

        #[cfg(not(target_os = "linux"))]
        {
            (
                false,
                vec![NUMANode {
                    node_id: 0,
                    core_count: processor_count,
                    core_ids: (0..processor_count).collect(),
                }],
            )
        }
    }

    /// Linux 平台 NUMA 检测
    #[cfg(target_os = "linux")]
    fn detect_numa_linux(processor_count: usize) -> (bool, Vec<NUMANode>) {
        use std::path::Path;

        let node_path = Path::new("/sys/devices/system/node");

        if !node_path.exists() {
            return (
                false,
                vec![NUMANode {
                    node_id: 0,
                    core_count: processor_count,
                    core_ids: (0..processor_count).collect(),
                }],
            );
        }

        let mut nodes = Vec::new();

        if let Ok(entries) = std::fs::read_dir(node_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                let node_name = entry.file_name();
                let node_str = node_name.to_string_lossy();

                if node_str.starts_with("node") {
                    if let Ok(node_id) = node_str[4..].parse::<usize>() {
                        let mut core_ids = Vec::new();

                        let cpu_list_path = path.join("cpulist");
                        if let Ok(cpu_list) = std::fs::read_to_string(&cpu_list_path) {
                            core_ids = Self::parse_cpu_list(&cpu_list);
                        }

                        if !core_ids.is_empty() {
                            nodes.push(NUMANode {
                                node_id,
                                core_count: core_ids.len(),
                                core_ids,
                            });
                        }
                    }
                }
            }
        }

        let enabled = nodes.len() > 1;
        if enabled {
            println!("[NUMA] Found {} NUMA nodes:", nodes.len());
            for node in &nodes {
                println!(
                    "[NUMA]   Node {}: {} cores ({} total)",
                    node.node_id, node.core_count, processor_count
                );
            }
        }

        (enabled, nodes)
    }

    /// 解析 Linux CPU 列表
    #[cfg(target_os = "linux")]
    fn parse_cpu_list(cpu_list: &str) -> Vec<usize> {
        let mut cores = Vec::new();

        for part in cpu_list.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() == 2 {
                    if let (Ok(start), Ok(end)) =
                        (range[0].parse::<usize>(), range[1].parse::<usize>())
                    {
                        for core in start..=end {
                            cores.push(core);
                        }
                    }
                }
            } else {
                if let Ok(core) = part.parse::<usize>() {
                    cores.push(core);
                }
            }
        }

        cores
    }

    pub fn set_thread_affinity(&self, _thread_id: usize, _core_id: usize) -> bool {
        true
    }

    pub fn set_current_thread_affinity(&self, preferred_core: Option<usize>) -> bool {
        let core_id = preferred_core.unwrap_or(0) % self.inner.processor_count;

        #[cfg(target_os = "linux")]
        {
            return linux::set_current_thread_affinity(core_id);
        }

        #[cfg(target_os = "windows")]
        {
            return windows::set_current_thread_affinity(core_id);
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            return other::set_current_thread_affinity(core_id);
        }
    }

    /// 绑定当前线程到指定 NUMA 节点
    pub fn bind_current_thread_to_numa_node(&self, node_id: usize, thread_index: usize) -> bool {
        if !self.inner.numa_enabled {
            // NUMA 不可用，使用普通亲和性
            return self.set_current_thread_affinity(Some(thread_index));
        }

        if let Some(node) = self.inner.numa_nodes.get(node_id) {
            if !node.core_ids.is_empty() {
                let core_id = node.core_ids[thread_index % node.core_ids.len()];
                #[cfg(target_os = "linux")]
                {
                    return linux::set_current_thread_affinity(core_id);
                }

                #[cfg(not(target_os = "linux"))]
                {
                    return true;
                }
            }
        }

        false
    }

    pub fn get_processor_count(&self) -> usize {
        self.inner.processor_count
    }

    pub fn is_numa_enabled(&self) -> bool {
        self.inner.numa_enabled
    }

    pub fn get_numa_node_count(&self) -> usize {
        self.inner.numa_nodes.len()
    }

    pub fn get_best_numa_node(&self) -> Option<usize> {
        if !self.inner.numa_enabled || self.inner.numa_nodes.is_empty() {
            return Some(0);
        }

        // 选择核心最多的节点
        self.inner
            .numa_nodes
            .iter()
            .enumerate()
            .max_by_key(|(_, node)| node.core_count)
            .map(|(id, _)| id)
    }
}

impl Default for ThreadAffinityManager {
    fn default() -> Self {
        Self::new()
    }
}
