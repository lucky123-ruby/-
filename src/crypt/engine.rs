use crate::crypt::aes_ctr::create_aes_ctr_engine;
use crate::crypt::aes_ctr_ni::create_aes_ctr_ni_engine;
use crate::crypt::mempool::AlignedMemoryPool;
use log::{error, info, warn};
use rand::RngCore;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

pub const KEY_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 16;

/// Generate random key to `buf` (buf length determines number of bytes to generate)
pub fn generate_random_key(buf: &mut [u8]) {
    rand::rngs::OsRng.fill_bytes(buf);
}

/// Check if CPU supports AES-NI instructions
pub fn is_aesni_supported() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

// Global shared memory pool used by engines to reduce allocations and improve reuse.
static GLOBAL_POOL: OnceLock<Arc<AlignedMemoryPool>> = OnceLock::new();

pub(crate) fn get_global_pool() -> Arc<AlignedMemoryPool> {
    GLOBAL_POOL
        .get_or_init(|| Arc::new(AlignedMemoryPool::new(1024 * 1024, 16)))
        .clone()
}

/// Optionally replace the global pool (useful for tests/benchmarks).
pub fn set_global_pool(pool: Arc<AlignedMemoryPool>) -> bool {
    GLOBAL_POOL.set(pool).is_ok()
}

/// Trait that allows pluggable encryption algorithms
pub trait EncryptionAlgorithm: Send + Sync {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String>;
    fn decrypt(&self, data: &[u8], tag: &[u8]) -> Result<Vec<u8>, String>;

    /// Memory mapped encryption: encrypt large files using memory mapping
    fn encrypt_mmap(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.encrypt(data)
    }

    /// Zero-copy in-place encryption: encrypts data directly in the provided buffer
    /// This eliminates memory allocation and copying overhead
    fn encrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        let encrypted = self.encrypt(data)?;
        data.copy_from_slice(&encrypted);
        Ok(())
    }

    /// Zero-copy in-place decryption: decrypts data directly in the provided buffer
    fn decrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        let tag_start = data.len().saturating_sub(16);
        let (ciphertext, tag) = data.split_at_mut(tag_start);
        let decrypted = self.decrypt(ciphertext, tag)?;
        ciphertext.copy_from_slice(&decrypted);
        Ok(())
    }
}

/// Simple factory returning a boxed algorithm implementation using AES-CTR
pub(crate) fn create_aes_ctr_engine_with_hardware_acceleration(
    key: [u8; KEY_LENGTH],
) -> Arc<dyn EncryptionAlgorithm> {
    if is_aesni_supported() {
        if let Ok(engine) = std::panic::catch_unwind(|| create_aes_ctr_ni_engine(key)) {
            if let Ok(_) = engine.encrypt(&[0u8; 1024]) {
                info!("Successfully initialized AES-NI CTR engine");
                return engine;
            } else {
                warn!("AES-NI CTR engine created but failed test encryption");
            }
        } else {
            warn!("Failed to create AES-NI CTR engine (panic or unsupported)");
        }
        warn!("Falling back to software AES-CTR implementation");
    }

    create_aes_ctr_engine(key)
}

/// Type alias for worker tasks: (task_id, buffer, length, is_encrypt)
type WorkerTask = (usize, Vec<u8>, usize, bool);

/// Backwards-compatible wrapper expected by pipeline code.
#[derive(Clone)]
pub struct EncryptResult {
    pub success: bool,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct EncryptionEngine {
    inner: Arc<dyn EncryptionAlgorithm>,
    pool: Arc<AlignedMemoryPool>,
    input_tx: Sender<WorkerTask>,
}

impl EncryptionEngine {
    pub fn new() -> Self {
        // default key of zeros (not secure) until initialized
        let key = [0u8; KEY_LENGTH];
        let pool = get_global_pool();

        // Create channel for worker communication
        let (input_tx, input_rx) = channel();
        let output_tx = channel();

        // Start worker thread
        let engine = Self {
            inner: create_aes_ctr_engine_with_hardware_acceleration(key),
            pool: pool.clone(),
            input_tx: input_tx.clone(),
        };

        let worker_engine = Arc::new(engine.clone());
        thread::spawn(move || {
            Self::worker_thread(worker_engine, input_rx, output_tx.0);
        });

        engine
    }

    pub fn initialize(&mut self, key: &[u8; KEY_LENGTH]) -> bool {
        // Replace inner with real engine created from provided key
        self.inner = create_aes_ctr_engine_with_hardware_acceleration(*key);
        true
    }

    /// Create a ready-to-use engine initialized with `key`.
    pub fn with_key(key: [u8; KEY_LENGTH]) -> Self {
        let mut engine = Self::new();
        let _ = engine.initialize(&key);
        engine
    }

    pub fn encrypt(
        &self,
        data: &[u8],
        _encrypt_size: usize,
    ) -> Result<EncryptResult, Box<dyn std::error::Error>> {
        // For compatibility, encrypt the entire provided data
        match self.inner.encrypt(data) {
            Ok(ciphertext) => Ok(EncryptResult {
                success: true,
                ciphertext,
            }),
            Err(e) => Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, e))),
        }
    }

    pub fn encrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        self.inner.encrypt_in_place(data)
    }

    pub fn decrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        self.inner.decrypt_in_place(data)
    }

    pub fn batch_encrypt(&self, buffers: &mut [&mut [u8]]) -> Result<(), String> {
        for buffer in buffers {
            self.inner.encrypt_in_place(buffer)?;
        }
        Ok(())
    }

    pub fn batch_decrypt(&self, buffers: &mut [&mut [u8]]) -> Result<(), String> {
        for buffer in buffers {
            self.inner.decrypt_in_place(buffer)?;
        }
        Ok(())
    }

    fn worker_thread(
        engine: Arc<Self>,
        input_rx: Receiver<WorkerTask>,
        output_tx: Sender<Result<(usize, Vec<u8>), String>>,
    ) {
        loop {
            match input_rx.recv() {
                Ok((task_id, buffer, len, is_encrypt)) => {
                    // Allocate aligned memory
                    let mut aligned_buffer = match engine.pool.allocate(len) {
                        Some(buf) => buf,
                        None => {
                            let err_msg = "Failed to allocate memory".to_string();
                            if let Err(e) = output_tx.send(Err(err_msg)) {
                                error!("Failed to send error: {}", e);
                            }
                            continue;
                        }
                    };

                    // Copy data to aligned buffer
                    aligned_buffer[..len].copy_from_slice(&buffer[..len]);

                    // Perform actual encryption/decryption
                    let result = if is_encrypt {
                        engine.inner.encrypt(&aligned_buffer[..len])
                    } else {
                        // For decryption, we need to separate data from tag
                        let tag_start = len.saturating_sub(16);
                        let data = &aligned_buffer[..tag_start];
                        let tag = &aligned_buffer[tag_start..len];
                        engine.inner.decrypt(data, tag)
                    };

                    // Process the result
                    match result {
                        Ok(output) => {
                            if let Err(e) = output_tx.send(Ok((task_id, output))) {
                                error!("Failed to send processed data: {}", e);
                                break;
                            }
                        }
                        Err(e) => {
                            error!("Processing failed: {}", e);
                            if let Err(send_err) =
                                output_tx.send(Err(format!("Processing failed: {}", e)))
                            {
                                error!("Failed to send error: {}", send_err);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Channel closed, exit thread
                    break;
                }
            }
        }
    }

    pub fn shutdown(self) {
        // Drop the input sender to signal workers to shut down
        drop(self.input_tx);
        info!("Encryption engine shut down");
    }
}

impl Default for EncryptionEngine {
    fn default() -> Self {
        EncryptionEngine::new()
    }
}
