//! 高性能无锁缓冲区池
//!
//! 使用无锁数据结构实现极致性能的缓冲区管理

use std::fmt;
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// 无锁缓冲区池节点
struct BufferNode {
    buffer: Vec<u8>,
    next: AtomicPtr<BufferNode>,
}

impl fmt::Debug for BufferNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferNode")
            .field("buffer_len", &self.buffer.len())
            .field("buffer_capacity", &self.buffer.capacity())
            .finish()
    }
}

/// 高性能无锁缓冲区池
pub struct LockFreeBufferPool {
    head: AtomicPtr<BufferNode>,
    size: AtomicUsize,
    capacity: usize,
    buffer_size: usize,
    temp_allocations: AtomicUsize,
}

unsafe impl Send for LockFreeBufferPool {}
unsafe impl Sync for LockFreeBufferPool {}

impl fmt::Debug for LockFreeBufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockFreeBufferPool")
            .field("size", &self.size.load(Ordering::Relaxed))
            .field("capacity", &self.capacity)
            .field("buffer_size", &self.buffer_size)
            .finish()
    }
}

impl LockFreeBufferPool {
    pub fn new(capacity: usize, buffer_size: usize) -> Self {
        let initial_count = std::cmp::min(capacity, 100);
        let mut head = ptr::null_mut();

        for _ in 0..initial_count {
            let mut buffer = Vec::new();
            if buffer.try_reserve(buffer_size).is_err() {
                eprintln!("[LockFreePool] Initial buffer allocation failed, using smaller size");
                buffer = Vec::with_capacity(std::cmp::min(buffer_size, 64 * 1024));
            }
            let node = Box::into_raw(Box::new(BufferNode {
                buffer,
                next: AtomicPtr::new(head),
            }));
            head = node;
        }

        Self {
            head: AtomicPtr::new(head),
            size: AtomicUsize::new(initial_count),
            capacity,
            buffer_size,
            temp_allocations: AtomicUsize::new(0),
        }
    }

    pub fn expand_pool(&self, additional: usize) {
        let current_size = self.size.load(Ordering::Relaxed);
        if current_size + additional > self.capacity {
            return;
        }

        for _ in 0..additional {
            let mut buffer = Vec::new();
            if buffer.try_reserve(self.buffer_size).is_err() {
                eprintln!("[LockFreePool] Failed to expand pool, skipping buffer");
                break;
            }
            
            let node = Box::into_raw(Box::new(BufferNode {
                buffer,
                next: AtomicPtr::new(ptr::null_mut()),
            }));

            loop {
                let head_ptr = self.head.load(Ordering::Acquire);
                unsafe {
                    (*node).next.store(head_ptr, Ordering::Relaxed);
                }

                if self
                    .head
                    .compare_exchange_weak(head_ptr, node, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    self.size.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        self.acquire_with_timeout(Duration::from_secs(5))
    }

    pub fn acquire_with_timeout(&self, timeout: Duration) -> Vec<u8> {
        let start = Instant::now();
        let mut spin_count = 0u32;
        const MAX_SPIN: u32 = 100;
        let mut last_warning = start;

        loop {
            let head_ptr = self.head.load(Ordering::Acquire);

            if head_ptr.is_null() {
                let temp_count = self.temp_allocations.load(Ordering::Relaxed);
                if temp_count < self.capacity {
                    self.temp_allocations.fetch_add(1, Ordering::Relaxed);
                    let mut buffer = Vec::new();
                    if buffer.try_reserve(self.buffer_size).is_err() {
                        eprintln!("[LockFreePool] Memory allocation failed, using smaller buffer");
                        buffer = Vec::with_capacity(std::cmp::min(self.buffer_size, 64 * 1024));
                    }
                    return buffer;
                }

                let elapsed = start.elapsed();
                if elapsed > timeout {
                    eprintln!("[LockFreePool] Timeout acquiring buffer after {:?} (pool empty, temp_allocations: {}/{})", 
                        timeout, temp_count, self.capacity);
                    eprintln!("[LockFreePool] Forcing temporary allocation to avoid deadlock");
                    self.temp_allocations.fetch_add(1, Ordering::Relaxed);
                    let mut buffer = Vec::new();
                    if buffer.try_reserve(self.buffer_size).is_err() {
                        buffer = Vec::with_capacity(std::cmp::min(self.buffer_size, 64 * 1024));
                    }
                    return buffer;
                }

                if spin_count < 5 {
                    std::hint::spin_loop();
                    spin_count += 1;
                    continue;
                }

                let warning_elapsed = last_warning.elapsed();
                if warning_elapsed > Duration::from_secs(5) {
                    eprintln!("[LockFreePool] Waiting for buffer (pool empty, temp_allocations: {}/{}, elapsed: {:.1}s)", 
                        temp_count, self.capacity, elapsed.as_secs_f64());
                    last_warning = Instant::now();
                }

                std::thread::yield_now();
                continue;
            }

            let node = unsafe { &*head_ptr };
            let next_ptr = node.next.load(Ordering::Acquire);

            if self
                .head
                .compare_exchange_weak(head_ptr, next_ptr, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_sub(1, Ordering::Relaxed);
                let mut buffer = unsafe { Box::from_raw(head_ptr) }.buffer;
                buffer.clear();
                return buffer;
            }
        }
    }

    pub fn release(&self, mut buffer: Vec<u8>) {
        if buffer.capacity() < self.buffer_size {
            buffer.reserve(self.buffer_size - buffer.capacity());
        }

        if buffer.capacity() == self.buffer_size
            && self.temp_allocations.load(Ordering::Relaxed) > 0
        {
            self.temp_allocations.fetch_sub(1, Ordering::Relaxed);
        }

        let node = Box::into_raw(Box::new(BufferNode {
            buffer,
            next: AtomicPtr::new(ptr::null_mut()),
        }));

        loop {
            let head_ptr = self.head.load(Ordering::Acquire);
            unsafe {
                (*node).next.store(head_ptr, Ordering::Relaxed);
            }

            if self
                .head
                .compare_exchange_weak(head_ptr, node, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                self.size.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    pub fn size(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }
}

impl Drop for LockFreeBufferPool {
    fn drop(&mut self) {
        let mut head_ptr = self.head.load(Ordering::Acquire);

        while !head_ptr.is_null() {
            let node = unsafe { Box::from_raw(head_ptr) };
            head_ptr = node.next.load(Ordering::Acquire);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_lock_free_pool() {
        let pool = LockFreeBufferPool::new(4000, 16384);

        let buffer = pool.acquire();
        assert_eq!(buffer.capacity(), 16384);

        pool.release(buffer);
        assert_eq!(pool.size(), 1000);
    }

    #[test]
    fn test_concurrent_access() {
        let pool = Arc::new(LockFreeBufferPool::new(4000, 65536));
        let mut handles = vec![];

        for _ in 0..10 {
            let pool = pool.clone();
            let handle = thread::spawn(move || {
                for _ in 0..10000 {
                    let buffer = pool.acquire();
                    pool.release(buffer);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(pool.size(), 1000);
    }
}
