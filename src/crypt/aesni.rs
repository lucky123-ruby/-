// Feature-gated AES-NI accelerated engine scaffold.
// This file is compiled only when the `aesni` Cargo feature is enabled.
//
// NOTE: For safety and portability this initial implementation acts as a
// thin wrapper around the existing `AesGcmEngine`. A true AES-NI native
// implementation can be placed here later (using `std::arch` intrinsics
// or an optimized crate). The wrapper will select the optimized path at
// runtime when `is_aesni_supported()` reports true.

#![cfg(feature = "aesni")]

use std::sync::Arc;
use std::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
    _mm_loadu_si128, _mm_storeu_si128, _mm_xor_si128, _mm_slli_si128, _mm_shuffle_epi32,
    _mm_prefetch, _MM_HINT_T0
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m256i, _mm256_loadu_si256, _mm256_storeu_si256, _mm256_xor_si256, 
    _mm256_aesenc_epi128, _mm256_aesenclast_epi128, _mm256_broadcastsi128_si256,
    _mm256_inserti128_si256, _mm256_castsi128_si256, _mm256_castsi256_si128, _mm256_extracti128_si256,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m512i, _mm512_loadu_si512, _mm512_storeu_si512, _mm512_xor_si512, _mm512_aesenc_epi128, 
    _mm512_aesenclast_epi128, _mm512_broadcast_i32x4
};
use crate::crypt::engine::{EncryptionAlgorithm, KEY_LENGTH, is_aesni_supported};

const AES_BLOCK_SIZE: usize = 16;
const AES_ROUNDS: usize = 10;
const PREFETCH_DISTANCE: usize = 8;

pub struct AesNiEngine {
    key: [u8; KEY_LENGTH],
    round_keys: [__m128i; 11],
    avx2_supported: bool,
    avx512_supported: bool,
}

impl AesNiEngine {
    pub fn new(key: [u8; KEY_LENGTH]) -> Self {
        let mut engine = Self {
            key,
            round_keys: [unsafe { std::mem::zeroed() }; 11],
            avx2_supported: cfg!(target_arch = "x86_64") && is_avx2_supported(),
            avx512_supported: cfg!(target_arch = "x86_64") && is_avx512_supported(),
        };
        
        if is_aesni_supported() {
            unsafe {
                engine.expand_key();
            }
        }
        
        engine
    }
    
    #[target_feature(enable = "aes")]
    unsafe fn expand_key(&mut self) {
        let key = _mm_loadu_si128(self.key.as_ptr() as *const __m128i);
        self.round_keys[0] = key;
        
        macro_rules! expand_round {
            ($rcon:expr) => {{
                let temp = _mm_aeskeygenassist_si128(key, $rcon);
                let temp = _mm_shuffle_epi32(temp, 0xff);
                let key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
                let key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
                _mm_xor_si128(key, temp)
            }};
        }
        
        let expanded_key = expand_round!(0x01);
        self.round_keys[1] = expanded_key;
        
        let expanded_key = expand_round!(0x02);
        self.round_keys[2] = expanded_key;
        
        let expanded_key = expand_round!(0x04);
        self.round_keys[3] = expanded_key;
        
        let expanded_key = expand_round!(0x08);
        self.round_keys[4] = expanded_key;
        
        let expanded_key = expand_round!(0x10);
        self.round_keys[5] = expanded_key;
        
        let expanded_key = expand_round!(0x20);
        self.round_keys[6] = expanded_key;
        
        let expanded_key = expand_round!(0x40);
        self.round_keys[7] = expanded_key;
        
        let expanded_key = expand_round!(0x80);
        self.round_keys[8] = expanded_key;
        
        let expanded_key = expand_round!(0x1B);
        self.round_keys[9] = expanded_key;
        
        let expanded_key = expand_round!(0x36);
        self.round_keys[10] = expanded_key;
    }
    
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_block(&self, block: __m128i) -> __m128i {
        let mut state = _mm_xor_si128(block, self.round_keys[0]);
        state = _mm_aesenc_si128(state, self.round_keys[1]);
        state = _mm_aesenc_si128(state, self.round_keys[2]);
        state = _mm_aesenc_si128(state, self.round_keys[3]);
        state = _mm_aesenc_si128(state, self.round_keys[4]);
        state = _mm_aesenc_si128(state, self.round_keys[5]);
        state = _mm_aesenc_si128(state, self.round_keys[6]);
        state = _mm_aesenc_si128(state, self.round_keys[7]);
        state = _mm_aesenc_si128(state, self.round_keys[8]);
        state = _mm_aesenc_si128(state, self.round_keys[9]);
        _mm_aesenclast_si128(state, self.round_keys[10])
    }
    
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_blocks_bulk(&self, input: &[u8], output: &mut [u8]) {
        let block_count = input.len() / AES_BLOCK_SIZE;
        
        for i in 0..block_count {
            // Prefetch data
            if i + PREFETCH_DISTANCE < block_count {
                _mm_prefetch(
                    input.as_ptr().add((i + PREFETCH_DISTANCE) * AES_BLOCK_SIZE) as *const i8,
                    _MM_HINT_T0,
                );
            }
            
            let input_ptr = input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i;
            let output_ptr = output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i;
            
            let block = _mm_loadu_si128(input_ptr);
            let encrypted = self.encrypt_block(block);
            _mm_storeu_si128(output_ptr, encrypted);
        }
    }
    
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "avx2")]
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_blocks_avx2(&self, input: &[u8], output: &mut [u8]) {
        let block_count = input.len() / AES_BLOCK_SIZE;
        let avx2_blocks = (block_count / 4) * 4; // Process in groups of 4 for better efficiency
        
        // Process 4 blocks at a time with AVX2
        for i in (0..avx2_blocks).step_by(4) {
            // 预取数据
            if i + PREFETCH_DISTANCE * 4 < block_count {
                _mm_prefetch(
                    input.as_ptr().add((i + PREFETCH_DISTANCE * 4) * AES_BLOCK_SIZE) as *const i8,
                    _MM_HINT_T0,
                );
            }
            
            let input_ptr1 = input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i;
            let input_ptr2 = input.as_ptr().add((i + 1) * AES_BLOCK_SIZE) as *const __m128i;
            let input_ptr3 = input.as_ptr().add((i + 2) * AES_BLOCK_SIZE) as *const __m128i;
            let input_ptr4 = input.as_ptr().add((i + 3) * AES_BLOCK_SIZE) as *const __m128i;
            
            let output_ptr1 = output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i;
            let output_ptr2 = output.as_mut_ptr().add((i + 1) * AES_BLOCK_SIZE) as *mut __m128i;
            let output_ptr3 = output.as_mut_ptr().add((i + 2) * AES_BLOCK_SIZE) as *mut __m128i;
            let output_ptr4 = output.as_mut_ptr().add((i + 3) * AES_BLOCK_SIZE) as *mut __m128i;
            
            // Load four blocks
            let data1 = _mm_loadu_si128(input_ptr1);
            let data2 = _mm_loadu_si128(input_ptr2);
            let data3 = _mm_loadu_si128(input_ptr3);
            let data4 = _mm_loadu_si128(input_ptr4);
            
            // Combine into AVX2 registers (2 blocks per register)
            let data_low = _mm256_inserti128_si256(_mm256_castsi128_si256(data1), data2, 1);
            let data_high = _mm256_inserti128_si256(_mm256_castsi128_si256(data3), data4, 1);
            
            // Initial XOR with round keys
            let key0 = _mm256_broadcastsi128_si256(self.round_keys[0]);
            let mut state_low = _mm256_xor_si256(data_low, key0);
            let mut state_high = _mm256_xor_si256(data_high, key0);
            
            // Main rounds with better pipelining
            for r in 1..10 {
                let round_key = _mm256_broadcastsi128_si256(self.round_keys[r]);
                state_low = _mm256_aesenc_epi128(state_low, round_key);
                state_high = _mm256_aesenc_epi128(state_high, round_key);
            }
            
            // Final round
            let final_key = _mm256_broadcastsi128_si256(self.round_keys[10]);
            state_low = _mm256_aesenclast_epi128(state_low, final_key);
            state_high = _mm256_aesenclast_epi128(state_high, final_key);
            
            // Extract and store the four blocks
            let out1 = _mm256_castsi256_si128(state_low);
            let out2 = _mm256_extracti128_si256(state_low, 1);
            let out3 = _mm256_castsi256_si128(state_high);
            let out4 = _mm256_extracti128_si256(state_high, 1);
            
            _mm_storeu_si128(output_ptr1, out1);
            _mm_storeu_si128(output_ptr2, out2);
            _mm_storeu_si128(output_ptr3, out3);
            _mm_storeu_si128(output_ptr4, out4);
        }
        
        // Handle remaining blocks with regular AES-NI
        for i in avx2_blocks..block_count {
            let input_block = _mm_loadu_si128(input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i);
            let output_block = self.encrypt_block(input_block);
            _mm_storeu_si128(output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i, output_block);
        }
    }
    
    #[target_feature(enable = "aes")]
    #[target_feature(enable = "avx512f")]
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_blocks_avx512(&self, input: &[u8], output: &mut [u8]) {
        let block_count = input.len() / AES_BLOCK_SIZE;
        let avx512_blocks = (block_count / 8) * 8; // Process in groups of 8
        
        // Process 8 blocks at a time with AVX-512
        for i in (0..avx512_blocks).step_by(8) {
            // 预取数据
            if i + PREFETCH_DISTANCE * 8 < block_count {
                _mm_prefetch(
                    input.as_ptr().add((i + PREFETCH_DISTANCE * 8) * AES_BLOCK_SIZE) as *const i8,
                    _MM_HINT_T0,
                );
            }
            
            let input_ptr = input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m512i;
            let output_ptr = output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m512i;
            
            // Load 8 blocks
            let data = _mm512_loadu_si512(input_ptr);
            
            // Initial XOR with round key
            let key0 = _mm512_broadcast_i32x4(self.round_keys[0]);
            let mut state = _mm512_xor_si512(data, key0);
            
            // Main rounds (manually unrolled for better performance)
            let key1 = _mm512_broadcast_i32x4(self.round_keys[1]);
            state = _mm512_aesenc_epi128(state, key1);
            
            let key2 = _mm512_broadcast_i32x4(self.round_keys[2]);
            state = _mm512_aesenc_epi128(state, key2);
            
            let key3 = _mm512_broadcast_i32x4(self.round_keys[3]);
            state = _mm512_aesenc_epi128(state, key3);
            
            let key4 = _mm512_broadcast_i32x4(self.round_keys[4]);
            state = _mm512_aesenc_epi128(state, key4);
            
            let key5 = _mm512_broadcast_i32x4(self.round_keys[5]);
            state = _mm512_aesenc_epi128(state, key5);
            
            let key6 = _mm512_broadcast_i32x4(self.round_keys[6]);
            state = _mm512_aesenc_epi128(state, key6);
            
            let key7 = _mm512_broadcast_i32x4(self.round_keys[7]);
            state = _mm512_aesenc_epi128(state, key7);
            
            let key8 = _mm512_broadcast_i32x4(self.round_keys[8]);
            state = _mm512_aesenc_epi128(state, key8);
            
            let key9 = _mm512_broadcast_i32x4(self.round_keys[9]);
            state = _mm512_aesenc_epi128(state, key9);
            
            // Final round
            let final_key = _mm512_broadcast_i32x4(self.round_keys[10]);
            state = _mm512_aesenclast_epi128(state, final_key);
            
            // Store results
            _mm512_storeu_si512(output_ptr, state);
        }
        
        // Handle remaining blocks with AVX2 if supported
        if self.avx2_supported {
            self.encrypt_blocks_avx2(
                &input[avx512_blocks * AES_BLOCK_SIZE..],
                &mut output[avx512_blocks * AES_BLOCK_SIZE..]
            );
        } else {
            // Fallback to regular AES-NI for remaining blocks
            for i in avx512_blocks..block_count {
                let input_block = _mm_loadu_si128(
                    input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i
                );
                let output_block = self.encrypt_block(input_block);
                _mm_storeu_si128(
                    output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i,
                    output_block
                );
            }
        }
    }
    
    #[target_feature(enable = "aes")]
    unsafe fn encrypt_blocks_unroll8(&self, input: &[u8], output: &mut [u8]) {
        let block_count = input.len() / AES_BLOCK_SIZE;
        let mut i = 0;
        
        // Process 8 blocks at a time with loop unrolling
        while i + 7 < block_count {
            // 预取数据
            if i + PREFETCH_DISTANCE * 8 < block_count {
                _mm_prefetch(
                    input.as_ptr().add((i + PREFETCH_DISTANCE * 8) * AES_BLOCK_SIZE) as *const i8,
                    _MM_HINT_T0,
                );
            }
            
            let b0 = _mm_loadu_si128(input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i);
            let b1 = _mm_loadu_si128(input.as_ptr().add((i + 1) * AES_BLOCK_SIZE) as *const __m128i);
            let b2 = _mm_loadu_si128(input.as_ptr().add((i + 2) * AES_BLOCK_SIZE) as *const __m128i);
            let b3 = _mm_loadu_si128(input.as_ptr().add((i + 3) * AES_BLOCK_SIZE) as *const __m128i);
            let b4 = _mm_loadu_si128(input.as_ptr().add((i + 4) * AES_BLOCK_SIZE) as *const __m128i);
            let b5 = _mm_loadu_si128(input.as_ptr().add((i + 5) * AES_BLOCK_SIZE) as *const __m128i);
            let b6 = _mm_loadu_si128(input.as_ptr().add((i + 6) * AES_BLOCK_SIZE) as *const __m128i);
            let b7 = _mm_loadu_si128(input.as_ptr().add((i + 7) * AES_BLOCK_SIZE) as *const __m128i);
            
            let mut s0 = _mm_xor_si128(b0, self.round_keys[0]);
            let mut s1 = _mm_xor_si128(b1, self.round_keys[0]);
            let mut s2 = _mm_xor_si128(b2, self.round_keys[0]);
            let mut s3 = _mm_xor_si128(b3, self.round_keys[0]);
            let mut s4 = _mm_xor_si128(b4, self.round_keys[0]);
            let mut s5 = _mm_xor_si128(b5, self.round_keys[0]);
            let mut s6 = _mm_xor_si128(b6, self.round_keys[0]);
            let mut s7 = _mm_xor_si128(b7, self.round_keys[0]);
            
            // Main encryption rounds (unrolled)
            for r in 1..10 {
                s0 = _mm_aesenc_si128(s0, self.round_keys[r]);
                s1 = _mm_aesenc_si128(s1, self.round_keys[r]);
                s2 = _mm_aesenc_si128(s2, self.round_keys[r]);
                s3 = _mm_aesenc_si128(s3, self.round_keys[r]);
                s4 = _mm_aesenc_si128(s4, self.round_keys[r]);
                s5 = _mm_aesenc_si128(s5, self.round_keys[r]);
                s6 = _mm_aesenc_si128(s6, self.round_keys[r]);
                s7 = _mm_aesenc_si128(s7, self.round_keys[r]);
            }
            
            // Final round
            s0 = _mm_aesenclast_si128(s0, self.round_keys[10]);
            s1 = _mm_aesenclast_si128(s1, self.round_keys[10]);
            s2 = _mm_aesenclast_si128(s2, self.round_keys[10]);
            s3 = _mm_aesenclast_si128(s3, self.round_keys[10]);
            s4 = _mm_aesenclast_si128(s4, self.round_keys[10]);
            s5 = _mm_aesenclast_si128(s5, self.round_keys[10]);
            s6 = _mm_aesenclast_si128(s6, self.round_keys[10]);
            s7 = _mm_aesenclast_si128(s7, self.round_keys[10]);
            
            // Store results
            _mm_storeu_si128(output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i, s0);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 1) * AES_BLOCK_SIZE) as *mut __m128i, s1);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 2) * AES_BLOCK_SIZE) as *mut __m128i, s2);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 3) * AES_BLOCK_SIZE) as *mut __m128i, s3);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 4) * AES_BLOCK_SIZE) as *mut __m128i, s4);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 5) * AES_BLOCK_SIZE) as *mut __m128i, s5);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 6) * AES_BLOCK_SIZE) as *mut __m128i, s6);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 7) * AES_BLOCK_SIZE) as *mut __m128i, s7);
            
            i += 8;
        }
        
        // Handle remaining blocks (4 at a time)
        while i + 3 < block_count {
            let b0 = _mm_loadu_si128(input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i);
            let b1 = _mm_loadu_si128(input.as_ptr().add((i + 1) * AES_BLOCK_SIZE) as *const __m128i);
            let b2 = _mm_loadu_si128(input.as_ptr().add((i + 2) * AES_BLOCK_SIZE) as *const __m128i);
            let b3 = _mm_loadu_si128(input.as_ptr().add((i + 3) * AES_BLOCK_SIZE) as *const __m128i);
            
            let mut s0 = _mm_xor_si128(b0, self.round_keys[0]);
            let mut s1 = _mm_xor_si128(b1, self.round_keys[0]);
            let mut s2 = _mm_xor_si128(b2, self.round_keys[0]);
            let mut s3 = _mm_xor_si128(b3, self.round_keys[0]);
            
            // Main encryption rounds (unrolled)
            for r in 1..10 {
                s0 = _mm_aesenc_si128(s0, self.round_keys[r]);
                s1 = _mm_aesenc_si128(s1, self.round_keys[r]);
                s2 = _mm_aesenc_si128(s2, self.round_keys[r]);
                s3 = _mm_aesenc_si128(s3, self.round_keys[r]);
            }
            
            // Final round
            s0 = _mm_aesenclast_si128(s0, self.round_keys[10]);
            s1 = _mm_aesenclast_si128(s1, self.round_keys[10]);
            s2 = _mm_aesenclast_si128(s2, self.round_keys[10]);
            s3 = _mm_aesenclast_si128(s3, self.round_keys[10]);
            
            // Store results
            _mm_storeu_si128(output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i, s0);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 1) * AES_BLOCK_SIZE) as *mut __m128i, s1);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 2) * AES_BLOCK_SIZE) as *mut __m128i, s2);
            _mm_storeu_si128(output.as_mut_ptr().add((i + 3) * AES_BLOCK_SIZE) as *mut __m128i, s3);
            
            i += 4;
        }
        
        // Handle remaining single blocks
        while i < block_count {
            let input_ptr = input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i;
            let output_ptr = output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i;
            
            let block = _mm_loadu_si128(input_ptr);
            let encrypted = self.encrypt_block(block);
            _mm_storeu_si128(output_ptr, encrypted);
            
            i += 1;
        }
    }
}

impl EncryptionAlgorithm for AesNiEngine {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        // 设置更高的阈值以更好地利用硬件加速
        if is_aesni_supported() && data.len() >= 1024 {
            let mut output = vec![0u8; data.len()];
            
            unsafe {
                // 使用预取技术提高缓存命中率
                self.prefetch_data(data);
                
                // 根据数据大小和可用的指令集选择最优加密方法
                #[cfg(target_arch = "x86_64")]
                {
                    if self.avx512_supported && data.len() >= 4096 {
                        self.encrypt_blocks_avx512(data, &mut output);
                    } else if self.avx2_supported && data.len() >= 2048 {
                        self.encrypt_blocks_avx2(data, &mut output);
                    } else {
                        self.encrypt_blocks_unroll8(data, &mut output);
                    }
                }
                
                #[cfg(not(target_arch = "x86_64"))]
                {
                    self.encrypt_blocks_unroll8(data, &mut output);
                }
            }
            
            Ok(output)
        } else {
            // 对于较小的数据或者不支持AES-NI的情况，返回错误让上层使用软件实现
            Err("Data too small for AES-NI or AES-NI not supported".into())
        }
    }

    fn decrypt(&self, _data: &[u8], _tag: &[u8]) -> Result<Vec<u8>, String> {
        // Placeholder for decrypt implementation
        Err("AES-NI decrypt not implemented".into())
    }
}

impl AesNiEngine {
    // 添加数据预取函数以提高性能
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "sse")]
    unsafe fn prefetch_data(&self, data: &[u8]) {
        let stride = 64; // 缓存行大小
        for i in (0..data.len()).step_by(stride * PREFETCH_DISTANCE) {
            _mm_prefetch(data.as_ptr().add(i) as *const i8, _MM_HINT_T0);
        }
    }
    
    #[cfg(not(target_arch = "x86_64"))]
    unsafe fn prefetch_data(&self, _data: &[u8]) {
        // 在非x86_64平台上不进行预取
    }
}

// Helper functions to detect CPU features
#[cfg(target_arch = "x86_64")]
fn is_avx2_supported() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(target_arch = "x86_64")]
fn is_avx512_supported() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

/// Expose a boxed engine for convenience
pub fn create_aesni_engine(key: [u8; KEY_LENGTH]) -> Arc<dyn EncryptionAlgorithm> {
    Arc::new(AesNiEngine::new(key))
}