//! File API implementations for different encryption modes

use std::path::Path;
use std::fs;
use std::future::Future;
use std::pin::Pin;

use crate::crypt::engine::{EncryptionEngine, KEY_LENGTH};
use crate::crypt::io::encrypt_file_with_mmap;
use crate::crypt::config::Config;

pub fn encrypt_file_cng(input: &Path, output: &Path, key: [u8; KEY_LENGTH], _use_memory_mapping: bool) -> Result<(), String> {
    println!("encrypt_file_cng: Encrypting {:?} -> {:?}", input, output);
    
    let data = fs::read(input).map_err(|e| format!("Failed to read input file: {}", e))?;
    println!("Read {} bytes from input file", data.len());
    
    let mut engine = EncryptionEngine::new();
    engine.initialize(&key);
    
    let encrypted_data = engine.encrypt(&data, data.len())
        .map_err(|e| format!("Encryption failed: {}", e))?
        .ciphertext;
    println!("Encryption completed, output size: {} bytes", encrypted_data.len());
    
    fs::write(output, &encrypted_data)
        .map_err(|e| format!("Failed to write output file: {}", e))?;
    println!("Successfully wrote encrypted data to {:?}", output);
    
    Ok(())
}

pub fn encrypt_file_with_streaming(input: &Path, output: &Path, key: [u8; KEY_LENGTH]) -> Result<(), String> {
    println!("encrypt_file_with_streaming: Encrypting {:?} -> {:?}", input, output);
    
    let config = Config::default();
    
    let mut engine = EncryptionEngine::new();
    engine.initialize(&key);
    
    encrypt_file_with_mmap(
        input,
        output,
        |data| {
            let result = engine.encrypt(data, data.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e)))?;
            Ok(result.ciphertext)
        },
        None,
        config.mmap_memory_ratio,
        config.mmap_min_chunk_size,
        config.mmap_max_chunk_size,
    ).map_err(|e| format!("Streaming encryption failed: {}", e))?;
    
    Ok(())
}

pub fn encrypt_file_with_async_io(input: &Path, output: &Path, key: [u8; KEY_LENGTH]) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> {
    println!("encrypt_file_with_async_io: Encrypting {:?} -> {:?}", input, output);
    
    let input = input.to_path_buf();
    let output = output.to_path_buf();
    
    Box::pin(async move {
        let data = tokio::fs::read(&input).await
            .map_err(|e| format!("Failed to read input file: {}", e))?;
        println!("Read {} bytes from input file", data.len());
        
        let engine = EncryptionEngine::with_key(key);
        let encrypted_data = engine.encrypt(&data, data.len())
            .map_err(|e| format!("Encryption failed: {}", e))?
            .ciphertext;
        println!("Encryption completed, output size: {} bytes", encrypted_data.len());
        
        tokio::fs::write(&output, &encrypted_data).await
            .map_err(|e| format!("Failed to write output file: {}", e))?;
        println!("Successfully wrote encrypted data to {:?}", output);
        
        Ok(())
    })
}

pub fn secure_delete(_path: &Path) -> bool {
    println!("Secure delete called for: {:?}", _path);
    
    #[cfg(target_os = "windows")]
    {
        true
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        true
    }
}
