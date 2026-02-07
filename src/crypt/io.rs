use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 直接分配缓冲区，移除不必要的panic捕获开销
pub fn allocate_buffer_smart(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

pub fn allocate_buffer_smart_with_fallback(size: usize) -> Vec<u8> {
    let min_size = 64 * 1024;
    if size > min_size {
        vec![0u8; size]
    } else {
        vec![0u8; min_size]
    }
}

pub fn get_optimal_buffer_size_dynamic(file_size: u64, concurrent_tasks: usize) -> usize {
    let available_memory = get_available_memory();
    let per_task_memory = available_memory / concurrent_tasks.max(1);
    let max_per_task = per_task_memory / 20;
    let base_size = get_optimal_buffer_size(file_size);
    base_size.min(max_per_task)
}

/// 默认缓冲区大小常量
pub const DEFAULT_BUFFER_SIZE_SMALL: usize = 256 * 1024;       // 256KB - 小文件 (64KB → 256KB, 4倍)
pub const DEFAULT_BUFFER_SIZE_MEDIUM: usize = 1024 * 1024;     // 1MB - 中等文件 (256KB → 1MB, 4倍)
pub const DEFAULT_BUFFER_SIZE_LARGE: usize = 4 * 1024 * 1024;  // 4MB - 大文件 (1MB → 4MB, 4倍)
pub const DEFAULT_BUFFER_SIZE_XLARGE: usize = 16 * 1024 * 1024; // 16MB - 超大文件 (4MB → 16MB, 4倍)

/// 文件大小阈值常量
pub const FILE_SIZE_THRESHOLD_SMALL: u64 = 1 * 1024 * 1024;      // 1MB
pub const FILE_SIZE_THRESHOLD_MEDIUM: u64 = 100 * 1024 * 1024;   // 100MB

/// 根据文件大小获取最优缓冲区大小
pub fn get_optimal_buffer_size(file_size: u64) -> usize {
    if file_size < FILE_SIZE_THRESHOLD_SMALL {
        DEFAULT_BUFFER_SIZE_SMALL
    } else if file_size < FILE_SIZE_THRESHOLD_MEDIUM {
        DEFAULT_BUFFER_SIZE_MEDIUM
    } else {
        DEFAULT_BUFFER_SIZE_LARGE
    }
}

/// 获取系统可用内存（Windows平台）
#[cfg(target_os = "windows")]
fn get_available_memory() -> usize {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    
    unsafe {
        let mut status = MEMORYSTATUSEX::default();
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        
        if GlobalMemoryStatusEx(&mut status).is_ok() {
            status.ullAvailPhys as usize
        } else {
            4 * 1024 * 1024 * 1024 // 默认4GB
        }
    }
}

/// 获取系统可用内存（非Windows平台，使用sysinfo）
#[cfg(not(target_os = "windows"))]
fn get_available_memory() -> usize {
    use sysinfo::System;
    
    let mut sys = System::new_all();
    sys.refresh_all();
    
    sys.available_memory() as usize
}

/// 根据配置动态计算内存映射块大小
pub fn get_dynamic_chunk_size(
    memory_ratio: usize,
    min_chunk: usize,
    max_chunk: usize,
) -> usize {
    let available_memory = get_available_memory();
    
    let calculated_chunk = (available_memory * memory_ratio) / 100;
    
    let chunk_size = calculated_chunk.max(min_chunk).min(max_chunk);
    
    chunk_size
}

pub fn read_file_sync(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Async file encryption with streaming support and adaptive buffer sizing
pub async fn encrypt_file_streaming_async<P, F>(
    input_path: P, 
    output_path: P, 
    chunk_size: Option<usize>,
    mut encrypt_fn: F
) -> std::io::Result<()>
where
    P: AsRef<Path>,
    F: FnMut(&[u8]) -> std::io::Result<Vec<u8>>,
{
    use tokio::fs::File as TokioFile;
    use tokio::io::BufWriter;

    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();

    let input_file = TokioFile::open(input_path).await?;
    let output_file = TokioFile::create(output_path).await?;
    let mut output_writer = BufWriter::new(output_file);

    let metadata = input_file.metadata().await?;
    let file_size = metadata.len();

    let actual_chunk_size = chunk_size.unwrap_or_else(|| get_optimal_buffer_size(file_size));

    let buf = allocate_buffer_smart_with_fallback(actual_chunk_size);
    
    let mut buf = buf;
    let mut input_reader = tokio::io::BufReader::new(input_file);
    
    loop {
        let n = input_reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        
        let encrypted_chunk = encrypt_fn(&buf[..n])?;
        output_writer.write_all(&encrypted_chunk).await?;
    }
    
    output_writer.flush().await?;
    Ok(())
}

/// Async file copy with progress callback
pub async fn copy_file_with_progress_async<F>(
    src: &Path,
    dst: &Path,
    chunk_size: usize,
    mut progress_callback: F,
) -> std::io::Result<u64>
where
    F: FnMut(u64) -> std::io::Result<()>,
{
    use tokio::fs::File as TokioFile;

    let mut reader = TokioFile::open(src).await?;
    let mut writer = TokioFile::create(dst).await?;
    
    let buf = allocate_buffer_smart_with_fallback(chunk_size);
    
    let mut buf = buf;
    let mut total_bytes = 0u64;
    
    loop {
        let bytes_read = reader.read(&mut buf).await?;
        if bytes_read == 0 {
            break;
        }
        
        writer.write_all(&buf[..bytes_read]).await?;
        total_bytes += bytes_read as u64;
        
        progress_callback(total_bytes)?;
    }
    
    Ok(total_bytes)
}

pub fn write_file_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp_hyf");
    {
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// 使用内存映射加密文件（自动选择分块或流式）
#[inline(always)]
pub fn encrypt_file_with_mmap<P, F>(
    input_path: P,
    output_path: P,
    mut encrypt_fn: F,
    progress_callback: Option<Box<dyn Fn(u64) + Send>>,
    _memory_ratio: usize,
    _min_chunk: usize,
    _max_chunk: usize,
) -> std::io::Result<()>
where
    P: AsRef<Path>,
    F: FnMut(&[u8]) -> std::io::Result<Vec<u8>>,
{
    encrypt_file_streaming_small(input_path.as_ref(), output_path.as_ref(), encrypt_fn, progress_callback)
}

/// 使用内存映射加密文件的部分内容（用于部分加密）
#[inline(always)]
pub fn encrypt_file_with_mmap_partial<P, F>(
    input_path: P,
    output_path: P,
    bytes_to_encrypt: u64,
    mut encrypt_fn: F,
    progress_callback: Option<Box<dyn Fn(u64) + Send>>,
    _memory_ratio: usize,
    _min_chunk: usize,
    _max_chunk: usize,
) -> std::io::Result<()>
where
    P: AsRef<Path>,
    F: FnMut(&[u8]) -> std::io::Result<Vec<u8>>,
{
    let input_path = input_path.as_ref();
    let output_path = output_path.as_ref();
    
    let input_file = File::open(input_path)?;
    let file_size = input_file.metadata()?.len();
    
    let bytes_to_encrypt = std::cmp::min(bytes_to_encrypt, file_size);
    
    let mut output_file = OpenOptions::new().create(true).write(true).open(output_path)?;
    
    encrypt_mmap_partial_streaming(&input_file, &mut output_file, bytes_to_encrypt, encrypt_fn, progress_callback)
}

/// 使用流式方式加密文件的部分内容
fn encrypt_mmap_partial_streaming<F>(
    input_file: &File,
    output_file: &mut File,
    bytes_to_encrypt: u64,
    mut encrypt_fn: F,
    progress_callback: Option<Box<dyn Fn(u64) + Send>>,
) -> std::io::Result<()>
where
    F: FnMut(&[u8]) -> std::io::Result<Vec<u8>>,
{
    use std::io::{BufReader, BufWriter};
    
    let file_size = input_file.metadata()?.len();
    let buffer_size = get_optimal_buffer_size(bytes_to_encrypt);
    
    let mut buffer = allocate_buffer_smart_with_fallback(buffer_size);
    
    let mut reader = BufReader::with_capacity(buffer_size, input_file);
    let mut writer = BufWriter::with_capacity(buffer_size, output_file);
    
    let mut total_processed = 0u64;
    
    while total_processed < bytes_to_encrypt {
        let remaining = bytes_to_encrypt - total_processed;
        let to_read = std::cmp::min(remaining as usize, buffer_size);
        
        let bytes_read = reader.read(&mut buffer[..to_read])?;
        
        if bytes_read == 0 {
            break;
        }
        
        let encrypted = encrypt_fn(&buffer[..bytes_read])?;
        
        writer.write_all(&encrypted)?;
        
        total_processed += bytes_read as u64;
        
        if let Some(ref cb) = progress_callback {
            cb(total_processed);
        }
    }
    
    writer.flush()?;
    
    Ok(())
}

/// 流式加密小文件
fn encrypt_file_streaming_small<F>(
    input_path: &Path,
    output_path: &Path,
    mut encrypt_fn: F,
    progress_callback: Option<Box<dyn Fn(u64) + Send>>,
) -> std::io::Result<()>
where
    F: FnMut(&[u8]) -> std::io::Result<Vec<u8>>,
{
    use std::io::{Read, BufReader, BufWriter, Write};
    
    let input_file = File::open(input_path)?;
    let output_file = OpenOptions::new().create(true).write(true).open(output_path)?;
    let mut output_writer = BufWriter::new(output_file);
    
    let file_size = input_file.metadata()?.len();
    let buffer_size = get_optimal_buffer_size(file_size);
    
    let mut read_buffer = allocate_buffer_smart_with_fallback(buffer_size);
    
    let mut input_reader = BufReader::new(input_file);
    let mut total_bytes = 0u64;
    
    loop {
        let bytes_read = input_reader.read(&mut read_buffer)?;
        if bytes_read == 0 {
            break;
        }
        
        let encrypted = encrypt_fn(&read_buffer[..bytes_read])?;
        output_writer.write_all(&encrypted)?;
        total_bytes += bytes_read as u64;
        
        if let Some(ref cb) = progress_callback {
            cb(total_bytes);
        }
    }
    
    output_writer.flush()?;
    Ok(())
}

pub fn read_file_mmap(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::{BufReader, Read};
    
    let f = File::open(path)?;
    let metadata = f.metadata()?;
    let len = metadata.len() as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    
    let buffer_size = get_optimal_buffer_size(len as u64);
    let mut reader = BufReader::with_capacity(buffer_size, f);
    let mut buffer = vec![0u8; len];
    
    let mut total_read = 0;
    while total_read < len {
        let bytes_read = reader.read(&mut buffer[total_read..])?;
        if bytes_read == 0 {
            break;
        }
        total_read += bytes_read;
    }
    
    buffer.truncate(total_read);
    Ok(buffer)
}

// Async I/O helpers (requires `tokio` dependency)
pub async fn read_file_async(path: &Path) -> std::io::Result<Vec<u8>> {
    use tokio::fs::File as TokioFile;
    use tokio::io::AsyncReadExt;

    let mut f = TokioFile::open(path).await?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).await?;
    Ok(buf)
}

pub async fn write_file_atomic_async(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use tokio::fs::OpenOptions as TokioOpenOptions;
    use tokio::io::AsyncWriteExt;

    let tmp = path.with_extension("tmp_hyf");
    {
        let mut f = TokioOpenOptions::new().create(true).write(true).truncate(true).open(&tmp).await?;
        f.write_all(data).await?;
        f.sync_all().await?;
    }
    // rename is currently blocking std; use std rename to be platform-consistent
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Async stream read: yields chunks into provided buffer (useful for streaming encryption)
pub async fn read_file_stream_async<P, F>(path: P, mut on_chunk: F, chunk_size: usize) -> std::io::Result<()>
where
    P: AsRef<Path>,
    F: FnMut(&[u8]) -> std::io::Result<()>,
{
    use tokio::fs::File as TokioFile;
    use tokio::io::AsyncReadExt;

    let mut f = TokioFile::open(path.as_ref()).await?;
    
    let buf = allocate_buffer_smart_with_fallback(chunk_size);
    
    let mut buf = buf;
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        on_chunk(&buf[..n])?;
    }
    Ok(())
}

/// 使用流式读取文件（仅读取，不加密）
/// 
/// # 参数
/// - `path`: 文件路径
/// - `bytes_to_read`: 要读取的字节数
/// 
/// # 返回
/// 返回读取的数据
/// 
/// # 性能
/// 使用流式读取，内存占用可控，适合所有文件大小
pub fn read_file_with_mmap(path: &Path, bytes_to_read: usize) -> std::io::Result<Vec<u8>> {
    use std::fs::File;
    use std::io::{Read, BufReader};
    
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len() as usize;
    
    let actual_read = std::cmp::min(bytes_to_read, file_size);
    
    if actual_read == 0 {
        return Ok(Vec::new());
    }
    
    let buffer_size = get_optimal_buffer_size(actual_read as u64);
    let mut reader = BufReader::with_capacity(buffer_size, file);
    
    let mut buffer = vec![0u8; actual_read];
    let mut total_read = 0;
    
    while total_read < actual_read {
        let bytes_read = reader.read(&mut buffer[total_read..])?;
        if bytes_read == 0 {
            break;
        }
        total_read += bytes_read;
    }
    
    buffer.truncate(total_read);
    Ok(buffer)
}

/// 判断是否应该使用内存映射
/// 
/// # 参数
/// - `file_size`: 文件大小（字节）
/// - `threshold`: 使用mmap的阈值（字节）
/// 
/// # 返回
/// 如果文件大小大于等于阈值，返回true
pub fn should_use_mmap(file_size: u64, threshold: u64) -> bool {
    file_size >= threshold
}

/// 获取内存映射的分块大小
/// 
/// # 参数
/// - `memory_ratio`: 可用内存的使用比例（百分比，例如10表示10%）
/// - `min_chunk`: 最小块大小
/// - `max_chunk`: 最大块大小
/// 
/// # 返回
/// 返回计算出的块大小，保持原有性能配置
pub fn get_mmap_chunk_size(memory_ratio: usize, min_chunk: usize, max_chunk: usize) -> usize {
    let available_memory = get_available_memory();
    
    // 计算基于内存比例的块大小
    let calculated_chunk = (available_memory * memory_ratio) / 100;
    
    // 保持原有配置，不做性能限制
    let chunk_size = calculated_chunk.max(min_chunk).min(max_chunk);
    
    println!("[MMAP] Available memory: {}MB, Calculated chunk: {}MB, Final chunk: {}MB", 
        available_memory / 1024 / 1024,
        calculated_chunk / 1024 / 1024,
        chunk_size / 1024 / 1024);
    
    chunk_size
}

/// 获取默认的mmap阈值（100MB）
pub const fn get_default_mmap_threshold() -> u64 {
    100 * 1024 * 1024
}

/// 获取默认的mmap内存比例（5%）
pub const fn get_default_mmap_memory_ratio() -> usize {
    5
}

/// 获取默认的mmap最小块大小（1MB）
pub const fn get_default_mmap_min_chunk() -> usize {
    1 * 1024 * 1024
}

/// 获取默认的mmap最大块大小（16MB）
pub const fn get_default_mmap_max_chunk() -> usize {
    16 * 1024 * 1024
}
