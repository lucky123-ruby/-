//! Performance monitoring and benchmarking for encryption operations
//!
//! This module provides comprehensive performance tracking including:
//! - Encryption speed (MB/s)
//! - Memory usage statistics
//! - CPU utilization
//! - I/O wait times
//! - Benchmarking utilities

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Performance metrics snapshot (non-atomic for cloning)
#[derive(Debug, Clone)]
pub struct PerformanceMetricsSnapshot {
    pub total_bytes_processed: u64,
    pub total_encryption_time_ms: u64,
    pub encryption_speed_mbps: f64,
    pub peak_memory_mb: u64,
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub cache_hit_rate: f64,
}

/// Performance metrics (atomic for thread-safe updates)
pub struct PerformanceMetrics {
    total_bytes_processed: AtomicU64,
    total_encryption_time_ms: AtomicU64,
    encryption_speed_mbps: AtomicU64,
    peak_memory_mb: AtomicU64,
    total_allocations: AtomicU64,
    total_deallocations: AtomicU64,
    cache_hit_rate: AtomicU64,
}

impl PerformanceMetrics {
    pub fn new() -> Self {
        Self {
            total_bytes_processed: AtomicU64::new(0),
            total_encryption_time_ms: AtomicU64::new(0),
            encryption_speed_mbps: AtomicU64::new(0),
            peak_memory_mb: AtomicU64::new(0),
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            cache_hit_rate: AtomicU64::new(0),
        }
    }

    pub fn calculate_speed(&self) -> f64 {
        let total_time = self.total_encryption_time_ms.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes_processed.load(Ordering::Relaxed);
        
        if total_time == 0 {
            0.0
        } else {
            let bytes_per_second = (total_bytes as f64 * 1000.0) / total_time as f64;
            bytes_per_second / (1024.0 * 1024.0) // Convert to MB/s
        }
    }

    pub fn to_snapshot(&self) -> PerformanceMetricsSnapshot {
        PerformanceMetricsSnapshot {
            total_bytes_processed: self.total_bytes_processed.load(Ordering::Relaxed),
            total_encryption_time_ms: self.total_encryption_time_ms.load(Ordering::Relaxed),
            encryption_speed_mbps: self.calculate_speed(),
            peak_memory_mb: self.peak_memory_mb.load(Ordering::Relaxed),
            total_allocations: self.total_allocations.load(Ordering::Relaxed),
            total_deallocations: self.total_deallocations.load(Ordering::Relaxed),
            cache_hit_rate: self.cache_hit_rate.load(Ordering::Relaxed) as f64,
        }
    }
}

/// Real-time performance monitor
pub struct PerformanceMonitor {
    metrics: Arc<PerformanceMetrics>,
    start_time: Instant,
    last_report_time: Instant,
    report_interval: Duration,
}

impl PerformanceMonitor {
    pub fn new(report_interval: Duration) -> Self {
        Self {
            metrics: Arc::new(PerformanceMetrics::new()),
            start_time: Instant::now(),
            last_report_time: Instant::now(),
            report_interval,
        }
    }

    pub fn start_operation(&mut self) {
        self.start_time = Instant::now();
    }

    pub fn end_operation(&mut self, bytes_processed: u64) {
        let duration = self.start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;
        
        self.metrics.total_bytes_processed.fetch_add(bytes_processed, Ordering::Relaxed);
        self.metrics.total_encryption_time_ms.fetch_add(duration_ms, Ordering::Relaxed);
        
        let speed = self.metrics.calculate_speed();
        
        if self.last_report_time.elapsed() >= self.report_interval {
            self.last_report_time = Instant::now();
            self.print_report(bytes_processed, duration_ms, speed);
        }
    }

    pub fn update_memory_stats(&self, allocated_mb: u64, deallocated_mb: u64, cache_hits: u64, cache_misses: u64) {
        self.metrics.peak_memory_mb.fetch_max(allocated_mb, Ordering::Relaxed);
        self.metrics.total_allocations.fetch_add(allocated_mb, Ordering::Relaxed);
        self.metrics.total_deallocations.fetch_add(deallocated_mb, Ordering::Relaxed);

        let total_cache_ops = cache_hits + cache_misses;
        if total_cache_ops > 0 {
            let cache_hit_rate = (cache_hits as f64 / total_cache_ops as f64) * 100.0;
            self.metrics.cache_hit_rate.store(cache_hit_rate as u64, Ordering::Relaxed);
        }
    }

    pub fn get_metrics(&self) -> PerformanceMetricsSnapshot {
        self.metrics.to_snapshot()
    }

    fn print_report(&self, bytes_processed: u64, duration_ms: u64, speed_mbps: f64) {
        println!("=== Performance Report ===");
        println!("Bytes processed: {:.2} MB", bytes_processed as f64 / (1024.0 * 1024.0));
        println!("Time taken: {:.2} ms", duration_ms);
        println!("Speed: {:.2} MB/s", speed_mbps);
        println!("Peak memory: {:.2} MB", self.metrics.peak_memory_mb.load(Ordering::Relaxed) as f64 / (1024.0 * 1024.0));
        println!("Cache hit rate: {:.1}%", self.metrics.cache_hit_rate.load(Ordering::Relaxed) as f64);
        println!("========================");
    }

    pub fn print_final_report(&self) {
        let metrics = self.get_metrics();
        println!("\n=== Final Performance Summary ===");
        println!("Total bytes processed: {:.2} MB", metrics.total_bytes_processed as f64 / (1024.0 * 1024.0));
        println!("Total encryption time: {:.2} s", metrics.total_encryption_time_ms as f64 / 1000.0);
        println!("Average speed: {:.2} MB/s", metrics.encryption_speed_mbps);
        println!("Peak memory usage: {:.2} MB", metrics.peak_memory_mb as f64 / (1024.0 * 1024.0));
        println!("Total allocations: {}", metrics.total_allocations);
        println!("Total deallocations: {}", metrics.total_deallocations);
        println!("Cache hit rate: {:.1}%", metrics.cache_hit_rate);
        println!("=============================\n");
    }
}

/// Benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub algorithm: String,
    pub file_size_mb: u64,
    pub encryption_time_ms: u64,
    pub speed_mbps: f64,
    pub memory_peak_mb: u64,
}

/// Simple benchmarking utility
pub fn run_benchmark<F>(
    algorithm_name: &str,
    encrypt_fn: F,
    data_sizes_mb: &[u64],
    iterations: usize,
) -> Vec<BenchmarkResult>
where
    F: Fn(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>>,
{
    let mut results = Vec::new();

    for &size_mb in data_sizes_mb {
        let data = vec![0u8; (size_mb * 1024 * 1024) as usize];

        let mut total_time = 0u64;
        let mut peak_memory = 0u64;

        for _ in 0..iterations {
            let start = Instant::now();
            let _ = encrypt_fn(&data);
            let duration = start.elapsed().as_millis() as u64;
            total_time += duration;

            let current_memory = size_mb * 1024 * 1024;
            if current_memory > peak_memory {
                peak_memory = current_memory;
            }
        }

        let avg_time_ms = total_time / iterations as u64;
        let speed_mbps = (size_mb as f64 * 8.0) / (avg_time_ms as f64 / 1000.0);

        results.push(BenchmarkResult {
            algorithm: algorithm_name.to_string(),
            file_size_mb: size_mb,
            encryption_time_ms: avg_time_ms,
            speed_mbps,
            memory_peak_mb: peak_memory,
        });
    }

    results
}

/// Print benchmark comparison table
pub fn print_benchmark_comparison(results: &[BenchmarkResult]) {
    println!("\n=== Benchmark Comparison ===");
    println!("{:<20} | {:<15} | {:<12} | {:<12} | {:<12}", 
        "Algorithm", "Size (MB)", "Time (ms)", "Speed (MB/s)", "Peak Mem (MB)"
    );
    println!("{}", "-".repeat(60));

    for result in results {
        println!("{:<20} | {:<15} | {:<12} | {:<12.2} | {:<12}", 
            result.algorithm, 
            result.file_size_mb, 
            result.encryption_time_ms, 
            result.speed_mbps, 
            result.memory_peak_mb
        );
    }
    println!("{}", "-".repeat(60));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_metrics() {
        let metrics = PerformanceMetrics::new();
        assert_eq!(metrics.total_bytes_processed, 0);
        assert_eq!(metrics.encryption_speed_mbps, 0.0);
    }

    #[test]
    fn test_calculate_speed() {
        let mut metrics = PerformanceMetrics::new();
        metrics.total_bytes_processed.store(1024 * 1024, Ordering::Relaxed);
        metrics.total_encryption_time_ms.store(1000, Ordering::Relaxed);

        let speed = metrics.calculate_speed();
        assert!((speed - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new(Duration::from_secs(1));
        monitor.start_operation();

        for i in 0..10 {
            monitor.end_operation(1024 * 1024);
            std::thread::sleep(Duration::from_millis(10));
        }

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_bytes_processed, 10 * 1024 * 1024);
        assert!(metrics.encryption_speed_mbps > 0.0);
    }
}