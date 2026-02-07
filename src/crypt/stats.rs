//! Performance statistics manager for tracking encryption pipeline metrics.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone)]
struct StageMetrics {
    files_processed: Arc<AtomicU64>,
    bytes_processed: Arc<AtomicU64>,
    total_time_ms: Arc<AtomicU64>,
    error_count: Arc<AtomicU64>,
    peak_throughput_mbs: Arc<AtomicU64>,
}

impl StageMetrics {
    fn new() -> Self {
        Self {
            files_processed: Arc::new(AtomicU64::new(0)),
            bytes_processed: Arc::new(AtomicU64::new(0)),
            total_time_ms: Arc::new(AtomicU64::new(0)),
            error_count: Arc::new(AtomicU64::new(0)),
            peak_throughput_mbs: Arc::new(AtomicU64::new(0)),
        }
    }

    fn update(&self, bytes: usize, time_ms: f64) {
        self.files_processed.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.total_time_ms
            .fetch_add(time_ms as u64, Ordering::Relaxed);

        // Calculate throughput in MB/s (scaled by 100 for integer storage)
        if time_ms > 0.0 {
            let throughput_scaled = ((bytes as u64 * 10000) / (1024 * 1024)) / (time_ms as u64);
            let _ = self
                .peak_throughput_mbs
                .fetch_max(throughput_scaled, Ordering::Relaxed);
        }
    }

    fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    fn get_files_processed(&self) -> u64 {
        self.files_processed.load(Ordering::Relaxed)
    }

    fn get_bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    fn get_total_time_ms(&self) -> u64 {
        self.total_time_ms.load(Ordering::Relaxed)
    }

    fn get_error_count(&self) -> u64 {
        self.error_count.load(Ordering::Relaxed)
    }

    fn get_peak_throughput(&self) -> f64 {
        self.peak_throughput_mbs.load(Ordering::Relaxed) as f64 / 100.0
    }
}

pub struct PerformanceStatsManager {
    traversal: Arc<StageMetrics>,
    encryption: Arc<StageMetrics>,
    write: Arc<StageMetrics>,
    monitoring: Arc<AtomicUsize>,
    start_time: Arc<AtomicU64>,
}

impl PerformanceStatsManager {
    pub fn new() -> Self {
        Self {
            traversal: Arc::new(StageMetrics::new()),
            encryption: Arc::new(StageMetrics::new()),
            write: Arc::new(StageMetrics::new()),
            monitoring: Arc::new(AtomicUsize::new(0)),
            start_time: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_metric(&self, stage_name: &str, bytes: usize, time_ms: f64) {
        let start_ns = self.start_time.load(Ordering::Relaxed);
        if start_ns == 0 {
            let now = Instant::now();
            self.start_time
                .store(now.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }

        let metrics = match stage_name {
            "traversal" | "Traversal" => &self.traversal,
            "encryption" | "Encryption" => &self.encryption,
            "write" | "Write" => &self.write,
            _ => &self.encryption,
        };
        metrics.update(bytes, time_ms);
    }

    pub fn record_error(&self, stage_name: &str) {
        let metrics = match stage_name {
            "traversal" | "Traversal" => &self.traversal,
            "encryption" | "Encryption" => &self.encryption,
            "write" | "Write" => &self.write,
            _ => &self.encryption,
        };
        metrics.record_error();
    }

    pub fn print_stats(&self) {
        let monitoring = self.monitoring.load(Ordering::Relaxed) != 0;
        let start_ns = self.start_time.load(Ordering::Relaxed);
        let elapsed = if start_ns > 0 {
            let now = Instant::now();
            let elapsed_ns = now.elapsed().as_nanos() as u64 - start_ns;
            Some(elapsed_ns as f64 / 1_000_000_000.0)
        } else {
            None
        };

        println!("=== Performance Statistics ===");
        if let Some(elapsed) = elapsed {
            println!("Total runtime: {:.2} seconds", elapsed);
        }
        println!(
            "Monitoring: {}",
            if monitoring { "Active" } else { "Inactive" }
        );

        println!("\nStage: Traversal");
        println!(
            "  Files processed: {}",
            self.traversal.get_files_processed()
        );
        println!(
            "  Bytes processed: {}",
            self.traversal.get_bytes_processed()
        );
        println!("  Total time: {:.2} ms", self.traversal.get_total_time_ms());
        println!("  Errors: {}", self.traversal.get_error_count());
        println!(
            "  Peak throughput: {:.2} MB/s",
            self.traversal.get_peak_throughput()
        );

        let traversal_time = self.traversal.get_total_time_ms() as f64;
        if traversal_time > 0.0 {
            let files = self.traversal.get_files_processed();
            if files > 0 {
                let avg_time = traversal_time / files as f64;
                println!("  Average time per file: {:.2} ms", avg_time);
            }
        }

        if self.traversal.get_files_processed() > 0 {
            let avg_size =
                self.traversal.get_bytes_processed() / self.traversal.get_files_processed().max(1);
            println!("  Average file size: {} bytes", avg_size);
        }

        println!("\nStage: Encryption");
        println!(
            "  Files processed: {}",
            self.encryption.get_files_processed()
        );
        println!(
            "  Bytes processed: {}",
            self.encryption.get_bytes_processed()
        );
        println!(
            "  Total time: {:.2} ms",
            self.encryption.get_total_time_ms()
        );
        println!("  Errors: {}", self.encryption.get_error_count());
        println!(
            "  Peak throughput: {:.2} MB/s",
            self.encryption.get_peak_throughput()
        );

        let encryption_time = self.encryption.get_total_time_ms() as f64;
        if encryption_time > 0.0 {
            let files = self.encryption.get_files_processed();
            if files > 0 {
                let avg_time = encryption_time / files as f64;
                println!("  Average time per file: {:.2} ms", avg_time);
            }
        }

        if self.encryption.get_files_processed() > 0 {
            let avg_size = self.encryption.get_bytes_processed()
                / self.encryption.get_files_processed().max(1);
            println!("  Average file size: {} bytes", avg_size);
        }

        println!("\nStage: Write");
        println!("  Files processed: {}", self.write.get_files_processed());
        println!("  Bytes processed: {}", self.write.get_bytes_processed());
        println!("  Total time: {:.2} ms", self.write.get_total_time_ms());
        println!("  Errors: {}", self.write.get_error_count());
        println!(
            "  Peak throughput: {:.2} MB/s",
            self.write.get_peak_throughput()
        );

        let write_time = self.write.get_total_time_ms() as f64;
        if write_time > 0.0 {
            let files = self.write.get_files_processed();
            if files > 0 {
                let avg_time = write_time / files as f64;
                println!("  Average time per file: {:.2} ms", avg_time);
            }
        }

        if self.write.get_files_processed() > 0 {
            let avg_size =
                self.write.get_bytes_processed() / self.write.get_files_processed().max(1);
            println!("  Average file size: {} bytes", avg_size);
        }
    }

    pub fn start_monitoring(&self) {
        self.monitoring.store(1, Ordering::Relaxed);
        let now = Instant::now();
        self.start_time
            .store(now.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    pub fn stop_monitoring(&self) {
        self.monitoring.store(0, Ordering::Relaxed);
    }
}

impl Clone for PerformanceStatsManager {
    fn clone(&self) -> Self {
        Self {
            traversal: Arc::clone(&self.traversal),
            encryption: Arc::clone(&self.encryption),
            write: Arc::clone(&self.write),
            monitoring: Arc::clone(&self.monitoring),
            start_time: Arc::clone(&self.start_time),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_stats_recording() {
        let stats = PerformanceStatsManager::new();
        stats.start_monitoring();

        stats.record_metric("Encryption", 1024 * 1024, 100.0);
        stats.record_error("Encryption");

        stats.print_stats();

        // 验证统计数据被记录
        assert_eq!(stats.encryption.get_files_processed(), 1);
        assert_eq!(stats.encryption.get_error_count(), 1);
    }

    #[test]
    fn test_concurrent_stats() {
        let stats = PerformanceStatsManager::new();
        stats.start_monitoring();

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let stats = stats.clone();
                thread::spawn(move || {
                    stats.record_metric("Encryption", 1024, 10.0);
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(stats.encryption.get_files_processed(), 10);
    }
}
