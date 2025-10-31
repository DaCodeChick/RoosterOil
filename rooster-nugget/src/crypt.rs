use aes::Aes256;
use bytes::{Bytes, BytesMut};
use cfb_mode::{Decryptor, Encryptor};
use cipher::{AsyncStreamCipher, KeyIvInit};

use crate::{MsgError, MsgResult};

/// Represents a cryptographic context for message encryption and decryption.
#[derive(Debug)]
pub struct CryptoContext {
    session_key: Option<Bytes>,
    encrypt_counter: u64,
    decrypt_counter: u64,
}

impl CryptoContext {
    /// Creates a new cryptographic context with no session key.
    pub fn new() -> Self {
        Self {
            session_key: None,
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }

    /// Sets the session key for encryption and decryption.
    pub fn set_session_key(&mut self, key: BytesMut) -> MsgResult<()> {
        if ![16, 24, 32].contains(&key.len()) {
            return Err(MsgError::KeyLength(key.len()));
        }

        let mut padded_key = key;
        if padded_key.len() < 32 {
            padded_key.resize(32, 0);
        }

        self.session_key = Some(padded_key.freeze());
        Ok(())
    }

    /// Checks if a session key is set.
    pub fn has_key(&self) -> bool {
        self.session_key.is_some()
    }

    /// Encrypts the given data using AES CFB mode.
    pub fn encrypt(&mut self, data: &mut [u8]) -> MsgResult<()> {
        let key = match &self.session_key {
            Some(k) => k,
            None => return Err(MsgError::KeyInit),
        };

        let iv = counter_to_iv(self.encrypt_counter);
        let cipher = Encryptor::<Aes256>::new_from_slices(key, &iv)
            .map_err(|e| MsgError::CipherInit(e.to_string()))?;

        cipher.encrypt(data);
        self.encrypt_counter += 1;
        Ok(())
    }

    /// Decrypts the given data using AES CFB mode.
    pub fn decrypt(&mut self, data: &mut [u8]) -> MsgResult<()> {
        let key = match &self.session_key {
            Some(k) => k,
            None => return Err(MsgError::KeyInit),
        };

        let iv = counter_to_iv(self.decrypt_counter);
        let cipher = Decryptor::<Aes256>::new_from_slices(key, &iv)
            .map_err(|e| MsgError::CipherInit(e.to_string()))?;

        cipher.decrypt(data);
        self.decrypt_counter += 1;
        Ok(())
    }

    /// Resets the encryption and decryption counters.
    pub fn reset_counters(&mut self) {
        self.encrypt_counter = 0;
        self.decrypt_counter = 0;
    }

    /// Gets the current encryption counter.
    pub fn get_encrypt_counter(&self) -> u64 {
        self.encrypt_counter
    }

    /// Gets the current decryption counter.
    pub fn get_decrypt_counter(&self) -> u64 {
        self.decrypt_counter
    }
}

impl Default for CryptoContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a counter value to a 16-byte IV for AES CFB mode.
fn counter_to_iv(counter: u64) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..8].copy_from_slice(&counter.to_le_bytes());
    iv
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_cipher() {
        let mut crypto = CryptoContext::new();
        let key = vec![
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c, 0x45, 0x91, 0x82, 0x73, 0xde, 0xf1, 0xa8, 0x9c,
        ];
        crypto.set_session_key(BytesMut::from(&key[..])).unwrap();

        let mut plaintext = b"Hello, World!".to_vec();
        crypto.encrypt(&mut plaintext).unwrap();
        crypto.reset_counters();
        crypto.decrypt(&mut plaintext).unwrap();

        assert_eq!(plaintext, b"Hello, World!");
    }
}
