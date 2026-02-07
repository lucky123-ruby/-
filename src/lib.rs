// Core module exports
pub mod crypt;
pub mod system;
pub mod control;
pub mod gpo;
pub use crypt::*;
pub use system::*;
pub use control::*;
pub use gpo::{safe_gpo_deployment, safe_gpo_deployment_with_mode, ImplementationMode};
pub use crypt::Config;

/// Initializes the system resources including optimized thread pools
pub fn init() {
    // Initialize the logger
    #[cfg(debug_assertions)]
    {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .try_init();
    }
    
    #[cfg(not(debug_assertions))]
    {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .try_init();
    }
    
    // Initialize the thread pool with optimized settings
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    rayon::ThreadPoolBuilder::new()
        .num_threads(std::cmp::min(num_cores * 2, 8))
        .build_global()
        .expect("Failed to initialize global thread pool");
}