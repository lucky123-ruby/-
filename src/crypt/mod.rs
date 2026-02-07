// Crypt modules
pub mod aesni;
pub mod aes_ctr;
pub mod aes_ctr_ni;
pub mod affinity;
pub mod config;
pub mod core;
pub mod engine;
pub mod file_api;
pub mod io;
pub mod lockfree_pool;
pub mod mempool;
pub mod network;
pub mod pipeline;
pub mod performance_monitor;
pub mod retry_handler;
pub mod smb;
pub mod three_layer_pipeline;
pub mod rsa;
pub mod scheduler;
pub mod stats;
pub mod storage;
pub mod tasks;
pub mod utils;
pub mod walker;

// 优化模块
// pub mod numa_affinity;
// pub mod batch_processor;
// pub mod aes_ni_optimizer;
// pub mod zero_copy_io;
// pub mod buffer_optimizer;
// pub mod optimized_integration;

pub mod platform;

// Public exports
pub use pipeline::OptimizedPipelineController;
pub use network::PipelineControllerTrait;
pub use stats::PerformanceStatsManager;
pub use affinity::ThreadAffinityManager;

// Re-exports
pub use affinity::*;
pub use engine::*;
pub use file_api::*;
pub use io::*;
pub use mempool::*;
pub use network::*;
pub use pipeline::*;
pub use performance_monitor::*;
pub use retry_handler::*;
pub use three_layer_pipeline::*;
pub use scheduler::*;
pub use utils::*;
pub use walker::*;
pub use config::*;
