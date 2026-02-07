use crate::crypt::engine::{is_aesni_supported, EncryptionAlgorithm, KEY_LENGTH};
use rand::RngCore;
use std::arch::x86_64::{
    __m128i, _mm_add_epi64, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
    _mm_cvtsi64_si128, _mm_loadu_si128, _mm_prefetch, _mm_set_epi64x, _mm_shuffle_epi32,
    _mm_slli_si128, _mm_storeu_si128, _mm_xor_si128,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m256i, _mm256_aesenc_epi128, _mm256_aesenclast_epi128, _mm256_broadcastsi128_si256,
    _mm256_castsi128_si256, _mm256_castsi256_si128, _mm256_extracti128_si256,
    _mm256_inserti128_si256, _mm256_loadu_si256, _mm256_storeu_si256, _mm256_xor_si256,
};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m512i, _mm512_aesenc_epi128, _mm512_aesenclast_epi128, _mm512_broadcast_i32x4,
    _mm512_loadu_si512, _mm512_storeu_si512, _mm512_xor_si512,
};
use std::sync::Arc;

const AES_BLOCK_SIZE: usize = 16;
const AES_ROUNDS: usize = 10;
const PREFETCH_DISTANCE: usize = 8;
const HEADER_SIZE: usize = 8;

type EncryptFn = unsafe fn(&AesCtrNiEngine, input: &[u8], output: &mut [u8], nonce: &[u8; 16]);

pub struct AesCtrNiEngine {
    key: [u8; KEY_LENGTH],
    round_keys: [__m128i; 11],
    avx2_supported: bool,
    avx512_supported: bool,
    encrypt_fn: EncryptFn,
}

impl AesCtrNiEngine {
    #[inline(always)]
    unsafe fn encrypt_blocks_sse_wrapper(&self, input: &[u8], output: &mut [u8], nonce: &[u8; 16]) {
        self.encrypt_blocks_sse(input, output, nonce);
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn encrypt_blocks_avx2_wrapper(
        &self,
        input: &[u8],
        output: &mut [u8],
        nonce: &[u8; 16],
    ) {
        self.encrypt_blocks_avx2(input, output, nonce);
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn encrypt_blocks_avx512_wrapper(
        &self,
        input: &[u8],
        output: &mut [u8],
        nonce: &[u8; 16],
    ) {
        self.encrypt_blocks_avx512(input, output, nonce);
    }

    pub fn new(key: [u8; KEY_LENGTH]) -> Self {
        let avx2_supported = cfg!(target_arch = "x86_64") && is_avx2_supported();
        let avx512_supported = cfg!(target_arch = "x86_64") && is_avx512_supported();

        let encrypt_fn: EncryptFn = if avx512_supported {
            Self::encrypt_blocks_avx512_wrapper
        } else if avx2_supported {
            Self::encrypt_blocks_avx2_wrapper
        } else {
            Self::encrypt_blocks_sse_wrapper
        };

        let mut engine = Self {
            key,
            round_keys: [unsafe { std::mem::zeroed() }; 11],
            avx2_supported,
            avx512_supported,
            encrypt_fn,
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
        let key_ptr = self.key.as_ptr() as *const __m128i;
        self.round_keys[0] = _mm_loadu_si128(key_ptr);

        let prev_key = self.round_keys[0];
        let temp = _mm_aeskeygenassist_si128(prev_key, 1);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[1] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[1];
        let temp = _mm_aeskeygenassist_si128(prev_key, 2);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[2] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[2];
        let temp = _mm_aeskeygenassist_si128(prev_key, 4);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[3] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[3];
        let temp = _mm_aeskeygenassist_si128(prev_key, 8);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[4] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[4];
        let temp = _mm_aeskeygenassist_si128(prev_key, 16);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[5] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[5];
        let temp = _mm_aeskeygenassist_si128(prev_key, 32);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[6] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[6];
        let temp = _mm_aeskeygenassist_si128(prev_key, 64);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[7] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[7];
        let temp = _mm_aeskeygenassist_si128(prev_key, 128);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[8] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[8];
        let temp = _mm_aeskeygenassist_si128(prev_key, 27);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[9] = _mm_xor_si128(sub_word, rcon);

        let prev_key = self.round_keys[9];
        let temp = _mm_aeskeygenassist_si128(prev_key, 54);
        let rotated = _mm_slli_si128(temp, 4);
        let sub_word = _mm_aesenc_si128(_mm_xor_si128(prev_key, rotated), _mm_set_epi64x(0, 0));
        let rcon = _mm_shuffle_epi32(temp, 0xff);
        self.round_keys[10] = _mm_xor_si128(sub_word, rcon);
    }

    #[target_feature(enable = "aes")]
    unsafe fn aes_encrypt_block(&self, input: __m128i) -> __m128i {
        let mut state = _mm_xor_si128(input, self.round_keys[0]);

        for i in 1..10 {
            state = _mm_aesenc_si128(state, self.round_keys[i]);
        }

        _mm_aesenclast_si128(state, self.round_keys[10])
    }

    #[target_feature(enable = "aes")]
    unsafe fn increment_counter(&self, counter: __m128i) -> __m128i {
        _mm_add_epi64(counter, _mm_set_epi64x(0, 1))
    }

    #[target_feature(enable = "aes")]
    unsafe fn ctr_encrypt_block(&self, counter: __m128i, plaintext: __m128i) -> __m128i {
        let keystream = self.aes_encrypt_block(counter);
        _mm_xor_si128(plaintext, keystream)
    }

    #[target_feature(enable = "aes")]
    unsafe fn encrypt_blocks_sse(&self, input: &[u8], output: &mut [u8], nonce: &[u8; 16]) {
        let block_count = input.len() / AES_BLOCK_SIZE;

        let mut counter = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);

        for i in 0..block_count {
            let input_ptr = input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i;
            let output_ptr = output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i;

            if i + PREFETCH_DISTANCE < block_count {
                let prefetch_ptr =
                    input.as_ptr().add((i + PREFETCH_DISTANCE) * AES_BLOCK_SIZE) as *const i8;
                _mm_prefetch(prefetch_ptr, 0);
            }

            let plaintext = _mm_loadu_si128(input_ptr);
            let encrypted = self.ctr_encrypt_block(counter, plaintext);
            _mm_storeu_si128(output_ptr, encrypted);

            counter = self.increment_counter(counter);
        }

        let remaining = input.len() % AES_BLOCK_SIZE;
        if remaining > 0 {
            let offset = block_count * AES_BLOCK_SIZE;
            let mut keystream_block = [0u8; AES_BLOCK_SIZE];
            let ks_ptr = keystream_block.as_mut_ptr() as *mut __m128i;
            let keystream = self.aes_encrypt_block(counter);
            _mm_storeu_si128(ks_ptr, keystream);

            for i in 0..remaining {
                output[offset + i] = input[offset + i] ^ keystream_block[i];
            }
        }
    }

    #[target_feature(enable = "aes")]
    #[target_feature(enable = "avx2")]
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_blocks_avx2(&self, input: &[u8], output: &mut [u8], nonce: &[u8; 16]) {
        let block_count = input.len() / AES_BLOCK_SIZE;
        let avx2_blocks = (block_count / 2) * 2;

        let mut counter0 = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);
        let mut counter1 = self.increment_counter(counter0);

        for i in (0..avx2_blocks).step_by(2) {
            let input_ptr0 = input.as_ptr().add(i * AES_BLOCK_SIZE) as *const __m128i;
            let input_ptr1 = input.as_ptr().add((i + 1) * AES_BLOCK_SIZE) as *const __m128i;
            let output_ptr0 = output.as_mut_ptr().add(i * AES_BLOCK_SIZE) as *mut __m128i;
            let output_ptr1 = output.as_mut_ptr().add((i + 1) * AES_BLOCK_SIZE) as *mut __m128i;

            if i + PREFETCH_DISTANCE < avx2_blocks {
                let prefetch_ptr =
                    input.as_ptr().add((i + PREFETCH_DISTANCE) * AES_BLOCK_SIZE) as *const i8;
                _mm_prefetch(prefetch_ptr, 0);
            }

            let plaintext0 = _mm_loadu_si128(input_ptr0);
            let plaintext1 = _mm_loadu_si128(input_ptr1);

            let encrypted0 = self.ctr_encrypt_block(counter0, plaintext0);
            let encrypted1 = self.ctr_encrypt_block(counter1, plaintext1);

            _mm_storeu_si128(output_ptr0, encrypted0);
            _mm_storeu_si128(output_ptr1, encrypted1);

            counter0 = self.increment_counter(self.increment_counter(counter0));
            counter1 = self.increment_counter(self.increment_counter(counter1));
        }

        let remaining = block_count - avx2_blocks;
        if remaining > 0 {
            let offset = avx2_blocks * AES_BLOCK_SIZE;
            let mut nonce_array = [0u8; 16];
            unsafe {
                _mm_storeu_si128(nonce_array.as_mut_ptr() as *mut __m128i, counter0);
            }
            self.encrypt_blocks_sse(&input[offset..], &mut output[offset..], &nonce_array);
        }
    }

    #[target_feature(enable = "aes")]
    #[target_feature(enable = "avx512f")]
    #[cfg(target_arch = "x86_64")]
    unsafe fn encrypt_blocks_avx512(&self, input: &[u8], output: &mut [u8], nonce: &[u8; 16]) {
        let block_count = input.len() / AES_BLOCK_SIZE;
        let avx512_blocks = (block_count / 4) * 4;

        let mut counters = [_mm_set_epi64x(0, 0); 4];
        counters[0] = _mm_loadu_si128(nonce.as_ptr() as *const __m128i);
        for i in 1..4 {
            counters[i] = self.increment_counter(counters[i - 1]);
        }

        for i in (0..avx512_blocks).step_by(4) {
            let input_ptrs: [*const u8; 4] = [
                input.as_ptr().add(i * AES_BLOCK_SIZE),
                input.as_ptr().add((i + 1) * AES_BLOCK_SIZE),
                input.as_ptr().add((i + 2) * AES_BLOCK_SIZE),
                input.as_ptr().add((i + 3) * AES_BLOCK_SIZE),
            ];
            let output_ptrs: [*mut u8; 4] = [
                output.as_mut_ptr().add(i * AES_BLOCK_SIZE),
                output.as_mut_ptr().add((i + 1) * AES_BLOCK_SIZE),
                output.as_mut_ptr().add((i + 2) * AES_BLOCK_SIZE),
                output.as_mut_ptr().add((i + 3) * AES_BLOCK_SIZE),
            ];

            if i + PREFETCH_DISTANCE < avx512_blocks {
                let prefetch_ptr =
                    input.as_ptr().add((i + PREFETCH_DISTANCE) * AES_BLOCK_SIZE) as *const i8;
                _mm_prefetch(prefetch_ptr, 0);
            }

            for j in 0..4 {
                let plaintext = _mm_loadu_si128(input_ptrs[j] as *const __m128i);
                let encrypted = self.ctr_encrypt_block(counters[j], plaintext);
                _mm_storeu_si128(output_ptrs[j] as *mut __m128i, encrypted);
            }

            for j in 0..4 {
                counters[j] = self.increment_counter(self.increment_counter(counters[j]));
            }
        }

        let remaining = block_count - avx512_blocks;
        if remaining > 0 {
            let offset = avx512_blocks * AES_BLOCK_SIZE;
            let mut nonce_array = [0u8; 16];
            unsafe {
                _mm_storeu_si128(nonce_array.as_mut_ptr() as *mut __m128i, counters[0]);
            }
            self.encrypt_blocks_sse(&input[offset..], &mut output[offset..], &nonce_array);
        }
    }
}

impl EncryptionAlgorithm for AesCtrNiEngine {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let original_size = plaintext.len() as u64;

        if is_aesni_supported() && plaintext.len() >= 128 {
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);

            let mut result = Vec::with_capacity(HEADER_SIZE + 16 + plaintext.len());
            result.extend_from_slice(&original_size.to_le_bytes());
            result.extend_from_slice(&nonce);
            unsafe {
                result.set_len(HEADER_SIZE + 16 + plaintext.len());
            }

            unsafe {
                (self.encrypt_fn)(self, plaintext, &mut result[HEADER_SIZE + 16..], &nonce);
            }

            Ok(result)
        } else {
            use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
            use aes_ctr::Aes128Ctr;

            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let mut cipher = Aes128Ctr::new((&self.key).into(), (&nonce).into());

            let mut result = Vec::with_capacity(HEADER_SIZE + 16 + plaintext.len());
            result.extend_from_slice(&original_size.to_le_bytes());
            result.extend_from_slice(&nonce);
            result.extend_from_slice(plaintext);
            cipher.apply_keystream(&mut result[HEADER_SIZE + 16..]);
            Ok(result)
        }
    }

    fn decrypt(&self, data: &[u8], _tag: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < HEADER_SIZE + 16 {
            return Err("Ciphertext too short".to_string());
        }

        let original_size = u64::from_le_bytes(data[0..HEADER_SIZE].try_into().unwrap()) as usize;
        let nonce = &data[HEADER_SIZE..HEADER_SIZE + 16];
        let encrypted = &data[HEADER_SIZE + 16..];

        if is_aesni_supported() && encrypted.len() >= 1024 {
            let mut output = Vec::with_capacity(encrypted.len());
            unsafe {
                output.set_len(encrypted.len());
            }

            unsafe {
                (self.encrypt_fn)(self, encrypted, &mut output, &nonce.try_into().unwrap());
            }

            output.truncate(original_size);
            Ok(output)
        } else {
            use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
            use aes_ctr::Aes128Ctr;

            let mut cipher = Aes128Ctr::new((&self.key).into(), nonce.try_into().unwrap());
            let mut plaintext = Vec::from(encrypted);
            cipher.apply_keystream(&mut plaintext);

            plaintext.truncate(original_size);
            Ok(plaintext)
        }
    }

    fn encrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        if is_aesni_supported() && data.len() >= 128 {
            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            unsafe {
                let data_ptr = data.as_ptr();
                let data_len = data.len();
                (self.encrypt_fn)(self, std::slice::from_raw_parts(data_ptr, data_len), data, &nonce);
            }
            Ok(())
        } else {
            use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
            use aes_ctr::Aes128Ctr;

            let mut nonce = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let mut cipher = Aes128Ctr::new((&self.key).into(), (&nonce).into());
            cipher.apply_keystream(data);
            Ok(())
        }
    }

    fn decrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        if data.len() < HEADER_SIZE + 16 {
            return Err("Data too short to contain header and nonce".to_string());
        }

        let (header_and_nonce, ciphertext) = data.split_at_mut(HEADER_SIZE + 16);
        let original_size = u64::from_le_bytes(header_and_nonce[0..HEADER_SIZE].try_into().unwrap()) as usize;
        let nonce_array: [u8; 16] = header_and_nonce[HEADER_SIZE..HEADER_SIZE + 16].try_into().unwrap();

        if is_aesni_supported() && ciphertext.len() >= 1024 {
            unsafe {
                let ciphertext_ptr = ciphertext.as_ptr();
                let ciphertext_len = ciphertext.len();
                (self.encrypt_fn)(self, std::slice::from_raw_parts(ciphertext_ptr, ciphertext_len), ciphertext, &nonce_array);
            }
            Ok(())
        } else {
            use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
            use aes_ctr::Aes128Ctr;

            let mut cipher = Aes128Ctr::new((&self.key).into(), (&nonce_array).into());
            cipher.apply_keystream(ciphertext);
            Ok(())
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn is_avx2_supported() -> bool {
    std::is_x86_feature_detected!("avx2")
}

#[cfg(target_arch = "x86_64")]
fn is_avx512_supported() -> bool {
    std::is_x86_feature_detected!("avx512f")
}

pub fn create_aes_ctr_ni_engine(key: [u8; KEY_LENGTH]) -> Arc<dyn EncryptionAlgorithm> {
    Arc::new(AesCtrNiEngine::new(key))
}
