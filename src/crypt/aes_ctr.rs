use crate::crypt::engine::{EncryptionAlgorithm, KEY_LENGTH};
use aes_ctr::cipher::{NewStreamCipher, SyncStreamCipher};
use aes_ctr::Aes128Ctr;
use rand::RngCore;
use std::sync::Arc;

pub const IV_LENGTH: usize = 16;
pub const HEADER_SIZE: usize = 8;

pub struct AesCtrEngine {
    key: [u8; KEY_LENGTH],
}

impl AesCtrEngine {
    pub fn new(key: [u8; KEY_LENGTH]) -> Self {
        Self { key }
    }
}

impl EncryptionAlgorithm for AesCtrEngine {
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let mut nonce = [0u8; IV_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut cipher = Aes128Ctr::new((&self.key).into(), (&nonce).into());

        let original_size = plaintext.len() as u64;
        let mut result = Vec::with_capacity(HEADER_SIZE + IV_LENGTH + plaintext.len());
        result.extend_from_slice(&original_size.to_le_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(plaintext);
        cipher.apply_keystream(&mut result[HEADER_SIZE + IV_LENGTH..]);

        Ok(result)
    }

    fn decrypt(&self, data: &[u8], _tag: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < HEADER_SIZE + IV_LENGTH {
            return Err("Data too short to contain header and nonce".to_string());
        }

        let original_size = u64::from_le_bytes(data[0..HEADER_SIZE].try_into().unwrap()) as usize;
        let nonce = &data[HEADER_SIZE..HEADER_SIZE + IV_LENGTH];
        let ciphertext = &data[HEADER_SIZE + IV_LENGTH..];

        let mut cipher = Aes128Ctr::new((&self.key).into(), nonce.into());
        let mut plaintext = Vec::from(ciphertext);
        cipher.apply_keystream(&mut plaintext);
        
        plaintext.truncate(original_size);
        Ok(plaintext)
    }

    fn encrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        let mut nonce = [0u8; IV_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut cipher = Aes128Ctr::new((&self.key).into(), (&nonce).into());
        
        cipher.apply_keystream(data);
        Ok(())
    }

    fn decrypt_in_place(&self, data: &mut [u8]) -> Result<(), String> {
        if data.len() < HEADER_SIZE + IV_LENGTH {
            return Err("Data too short to contain header and nonce".to_string());
        }

        let (header_and_nonce, ciphertext) = data.split_at_mut(HEADER_SIZE + IV_LENGTH);
        let original_size = u64::from_le_bytes(header_and_nonce[0..HEADER_SIZE].try_into().unwrap()) as usize;
        let nonce = &header_and_nonce[HEADER_SIZE..HEADER_SIZE + IV_LENGTH];

        let mut cipher = Aes128Ctr::new((&self.key).into(), nonce.into());
        cipher.apply_keystream(ciphertext);
        
        Ok(())
    }
}

pub fn create_aes_ctr_engine(key: [u8; KEY_LENGTH]) -> Arc<dyn EncryptionAlgorithm> {
    Arc::new(AesCtrEngine::new(key))
}
