use std::fs::{self};
use std::io::{Read, Seek, Write};
use std::path::Path;

/// Constants for cryptographic operations
pub const KEY_LENGTH: usize = 16;
pub const IV_LENGTH: usize = 16;

use crate::crypt::aes_ctr::create_aes_ctr_engine;
use crate::crypt::config::Config;
use crate::crypt::io::{allocate_buffer_smart_with_fallback, encrypt_file_with_mmap_partial};
use std::sync::Arc;

/// Core encryption engine optimized for performance
pub struct OptimizedEncryptionEngine {
    key: [u8; KEY_LENGTH],
    config: Arc<Config>,
}

impl OptimizedEncryptionEngine {
    /// Create a new encryption engine with given key and configuration
    pub fn new(key: [u8; KEY_LENGTH], config: Arc<Config>) -> Self {
        Self { key, config }
    }

    /// Simple AES-CTR encryption function
    pub fn encrypt_ctr(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let engine = create_aes_ctr_engine(self.key);
        engine.encrypt(plaintext)
    }

    /// Encrypt a file using optimized methods
    pub fn encrypt_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: Q,
    ) -> Result<(), String> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        // Get file size to determine optimal processing strategy
        let metadata =
            fs::metadata(input_path).map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let file_size = metadata.len();

        let bytes_to_encrypt = self.calculate_bytes_to_encrypt(file_size, false);

        if file_size < 1024 * 1024 {
            self.encrypt_small_file(input_path, output_path, bytes_to_encrypt)
        } else {
            self.encrypt_large_file(input_path, output_path, file_size, bytes_to_encrypt)
        }
    }

    fn calculate_bytes_to_encrypt(&self, file_size: u64, _is_database_file: bool) -> u64 {
        if !self.config.enable_partial_encrypt {
            file_size
        } else {
            const FIXED_ENCRYPT_SIZE: u64 = 4 * 1024;

            if file_size <= FIXED_ENCRYPT_SIZE {
                file_size
            } else {
                FIXED_ENCRYPT_SIZE
            }
        }
    }

    /// Encrypt small files entirely in memory
    fn encrypt_small_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: Q,
        bytes_to_encrypt: u64,
    ) -> Result<(), String> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        const MAX_IN_MEMORY_FILE_SIZE: u64 = 512 * 1024;

        if bytes_to_encrypt > MAX_IN_MEMORY_FILE_SIZE {
            return self.encrypt_large_file(
                input_path,
                output_path,
                bytes_to_encrypt,
                bytes_to_encrypt,
            );
        }

        let mut buffer = allocate_buffer_smart_with_fallback(bytes_to_encrypt as usize);

        // 读取需要加密的部分
        let mut file =
            fs::File::open(input_path).map_err(|e| format!("Failed to open input file: {}", e))?;
        file.read_exact(&mut buffer)
            .map_err(|e| format!("Failed to read input file: {}", e))?;

        // 加密数据
        let result = self
            .encrypt_ctr(&buffer)
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // 如果启用了部分加密并且不是数据库文件，读取剩余未加密数据
        let mut remaining = Vec::new();
        if self.config.enable_partial_encrypt
            && bytes_to_encrypt
                < fs::metadata(input_path)
                    .map_err(|e| format!("Failed to get file metadata: {}", e))?
                    .len()
        {
            file.read_to_end(&mut remaining)
                .map_err(|e| format!("Failed to read remaining data: {}", e))?;
        }

        // 写入加密数据和剩余数据
        let mut output_file = fs::File::create(output_path)
            .map_err(|e| format!("Failed to create output file: {}", e))?;
        output_file
            .write_all(&result)
            .map_err(|e| format!("Failed to write encrypted data: {}", e))?;

        // 如果有剩余数据，写入剩余数据
        if !remaining.is_empty() {
            output_file
                .write_all(&remaining)
                .map_err(|e| format!("Failed to write remaining data: {}", e))?;
        }

        Ok(())
    }

    /// Encrypt large files using buffered approach or memory mapping
    fn encrypt_large_file<P: AsRef<Path>, Q: AsRef<Path>>(
        &self,
        input_path: P,
        output_path: Q,
        file_size: u64,
        bytes_to_encrypt: u64,
    ) -> Result<(), String> {
        let input_path = input_path.as_ref();
        let output_path = output_path.as_ref();

        let result = encrypt_file_with_mmap_partial(
            input_path,
            output_path,
            bytes_to_encrypt,
            |data| {
                self.encrypt_ctr(data)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            },
            None,
            self.config.mmap_memory_ratio,
            self.config.mmap_min_chunk_size,
            self.config.mmap_max_chunk_size,
        );

        if let Err(e) = result {
            return Err(format!("Streaming encryption failed: {}", e));
        }

        // 如果是部分加密，将剩余数据直接复制到输出文件
        if self.config.enable_partial_encrypt && bytes_to_encrypt < file_size {
            let mut input_file = fs::File::open(input_path)
                .map_err(|e| format!("Failed to open input file for copying: {}", e))?;
            let mut output_file = fs::OpenOptions::new()
                .write(true)
                .open(output_path)
                .map_err(|e| format!("Failed to open output file for copying: {}", e))?;
            self.copy_remaining_data(
                &mut input_file,
                &mut output_file,
                file_size - bytes_to_encrypt,
            )?;
        }

        Ok(())
    }

    /// 复制剩余未加密数据
    fn copy_remaining_data(
        &self,
        input_file: &mut fs::File,
        output_file: &mut fs::File,
        remaining_size: u64,
    ) -> Result<(), String> {
        const COPY_BUFFER_SIZE: usize = 8 * 1024 * 1024;

        let mut buffer = allocate_buffer_smart_with_fallback(COPY_BUFFER_SIZE);

        let mut total_copied = 0u64;

        // 获取输出文件当前大小，从该位置开始写入
        let output_size = output_file
            .metadata()
            .map_err(|e| format!("Failed to get output file metadata: {}", e))?
            .len();

        // 定位到输出文件的末尾
        output_file
            .seek(std::io::SeekFrom::Start(output_size))
            .map_err(|e| format!("Failed to seek in output file: {}", e))?;

        // 获取输入文件当前大小，从该位置开始读取
        let input_size = input_file
            .metadata()
            .map_err(|e| format!("Failed to get input file metadata: {}", e))?
            .len();

        // 计算需要读取的起始位置
        let read_start = input_size - remaining_size;
        input_file
            .seek(std::io::SeekFrom::Start(read_start))
            .map_err(|e| format!("Failed to seek in input file: {}", e))?;

        while total_copied < remaining_size {
            let to_copy =
                std::cmp::min(remaining_size - total_copied, COPY_BUFFER_SIZE as u64) as usize;

            let bytes_read = input_file
                .read(&mut buffer[..to_copy])
                .map_err(|e| format!("Failed to read remaining data: {}", e))?;

            if bytes_read == 0 {
                break;
            }

            output_file
                .write_all(&buffer[..bytes_read])
                .map_err(|e| format!("Failed to write remaining data: {}", e))?;

            total_copied += bytes_read as u64;
        }

        Ok(())
    }
}
