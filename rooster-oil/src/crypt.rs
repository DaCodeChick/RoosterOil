use aes::{Aes128, Aes256};
use bytes::{Bytes, BytesMut};
use cbc::{Decryptor as CBCDec, Encryptor as CBCEnc};
use cfg_if::cfg_if;
use cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher, block_padding::Pkcs7,
};
use crc32fast;
use ctr::Ctr128BE;
use ecb::{Decryptor as ECBDec, Encryptor as ECBEnc};
use rand::RngCore;
use rc4::{Key, Rc4};
use rsa::{
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    pkcs8::EncodePublicKey,
    sha2::{Digest, Sha256},
};

use crate::{MsgError, MsgResult};

/// Supported cipher modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// Electronic Codebook mode
    Ecb = 0,
    /// Cipher Block Chaining mode
    Cbc,
    /// Counter mode
    Ctr,
}

/// Represents a keyring containing strong and fast keys along with an initialization vector.
#[derive(Debug, Clone)]
pub struct Keyring {
    strong: [u8; 32],
    fast: [u8; 16],
    iv: [u8; 16],
    rc4: Rc4Context,
}

impl Keyring {
    /// Creates a new keyring with random keys.
    pub fn new() -> Self {
        let mut strong = [0u8; 32];
        let mut fast = [0u8; 16];
        let mut iv = [0u8; 16];
        let mut rng = rand::thread_rng();

        rng.fill(&mut strong);
        rng.fill(&mut fast);
        rng.fill(&mut iv);

        Self {
            strong,
            fast,
            iv,
            rc4: Rc4Context::new(&fast),
        }
    }

    /// Applies RC4 encryption/decryption to the provided data in place.
    pub fn crypt_rc4(&mut self, data: &mut [u8]) {
        self.rc4.crypt(data);
    }

    /// Returns the session key (fast key) from the keyring.
    pub const fn get_session_key(&self) -> [u8; 16] {
        self.fast
    }
}

/// Represents the AES cryptographic context.
#[derive(Debug, Clone)]
pub struct AesContext(Keyring);

impl AesContext {
    /// Creates a new AES context with the provided keyring.
    pub fn new(keyring: Keyring) -> Self {
        Self(keyring)
    }

    /// Decrypts data using AES-128 in fast mode.
    pub fn decrypt_fast(&self, data: &[u8], mode: CipherMode) -> MsgResult<Bytes> {
        match mode {
            CipherMode::Ecb => self.aes128_ecb_decrypt(data),
            CipherMode::Cbc => self.aes128_cbc_decrypt(data),
            CipherMode::Ctr => self.aes128_ctr_crypt(data),
        }
        .map(Bytes::from)
    }

    /// Decrypts data using AES-256 with CRC32 checksum verification.
    pub fn decrypt_strong(&self, data: &[u8], mode: CipherMode) -> MsgResult<Bytes> {
        let decrypted_data = match mode {
            CipherMode::Ecb => self.aes256_ecb_decrypt(data)?,
            CipherMode::Cbc => self.aes256_cbc_decrypt(data)?,
            CipherMode::Ctr => self.aes256_ctr_crypt(data)?,
        };

        if decrypted_data.len() < 4 {
            return Err(MsgError::Aes);
        }

        let (crc_bytes, payload) = decrypted_data.split_at(4);
        let received_crc =
            u32::from_le_bytes([crc_bytes[0], crc_bytes[1], crc_bytes[2], crc_bytes[3]]);
        let computed_crc = crc32fast::hash(payload);

        if received_crc != computed_crc {
            return Err(MsgError::CrcMismatch(computed_crc, received_crc));
        }

        Ok(Bytes::from(payload.to_vec()))
    }

    /// Encrypts data using AES-128 in fast mode.
    pub fn encrypt_fast(&self, data: &[u8], mode: CipherMode) -> MsgResult<Bytes> {
        match mode {
            CipherMode::Ecb => self.aes128_ecb_encrypt(data),
            CipherMode::Cbc => self.aes128_cbc_encrypt(data),
            CipherMode::Ctr => self.aes128_ctr_crypt(data),
        }
        .map(Bytes::from)
    }

    /// Encrypts data using AES-256 with CRC32 checksum prepended.
    pub fn encrypt_strong(&self, data: &[u8], mode: CipherMode) -> MsgResult<Bytes> {
        let crc = crc32fast::hash(data);
        let mut buffer = BytesMut::with_capacity(data.len() + 4);

        buffer.extend_from_slice(&crc.to_le_bytes());
        buffer.extend_from_slice(data);

        match mode {
            CipherMode::Ecb => self.aes256_ecb_encrypt(&buffer),
            CipherMode::Cbc => self.aes256_cbc_encrypt(&buffer),
            CipherMode::Ctr => self.aes256_ctr_crypt(&buffer),
        }
        .map(Bytes::from)
    }

    /// Decrypts data using AES-128 in CBC mode.
    fn aes128_cbc_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCDec::<Aes128>::new_from_slices(&self.0.fast, &self.0.iv[..16])
            .map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-128 in CBC mode.
    fn aes128_cbc_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCEnc::<Aes128>::new_from_slices(&self.0.fast, &self.0.iv[..16])
            .map_err(|_| MsgError::KeyLength)?;
        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
    }

    /// Encrypts and decrypts data using AES-128 in CTR mode.
    fn aes128_ctr_crypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let mut cipher = Ctr128BE::<Aes128>::new_from_slices(&self.0.fast, &self.0.iv[..16])
            .map_err(|_| MsgError::KeyLength)?;
        let mut buffer = data.to_vec();

        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    /// Decrypts data using AES-128 in ECB mode.
    fn aes128_ecb_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBDec::<Aes128>::new_from_slice(&self.0.fast).map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-128 in ECB mode.
    fn aes128_ecb_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBEnc::<Aes128>::new_from_slice(&self.0.fast).map_err(|_| MsgError::KeyLength)?;
        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
    }

    /// Decrypts data using AES-256 in CBC mode.
    fn aes256_cbc_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCDec::<Aes256>::new_from_slices(&self.0.strong, &self.0.iv)
            .map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-256 in CBC mode.
    fn aes256_cbc_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCEnc::<Aes256>::new_from_slices(&self.0.strong, &self.0.iv)
            .map_err(|_| MsgError::KeyLength)?;
        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
    }

    /// Encrypts and decrypts data using AES-256 in CTR mode.
    fn aes256_ctr_crypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let mut cipher = Ctr128BE::<Aes256>::new_from_slices(&self.0.strong, &self.0.iv)
            .map_err(|_| MsgError::KeyLength)?;
        let mut buffer = data.to_vec();

        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    /// Decrypts data using AES-256 in ECB mode.
    fn aes256_ecb_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBDec::<Aes256>::new_from_slice(&self.0.strong).map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-256 in ECB mode.
    fn aes256_ecb_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBEnc::<Aes256>::new_from_slice(&self.0.strong).map_err(|_| MsgError::KeyLength)?;
        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
    }
}

/// Represents the RC4 cryptographic context.
#[derive(Debug, Clone)]
pub struct Rc4Context(Rc4);

impl Rc4Context {
    /// Creates a new RC4 context with the provided key.
    pub fn new(key: &[u8]) -> Self {
        let key = Key::from_slice(key);

        Self(Rc4::new(key))
    }

    /// Applies the RC4 keystream to the provided data in place.
    pub fn crypt(&mut self, data: &mut [u8]) {
        self.0.apply_keystream(data);
    }
}

/// Represents the RSA cryptographic context.
#[derive(Debug, Clone)]
pub struct RsaContext {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaContext {
    pub fn new(key_size: usize) -> MsgResult<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, key_size)?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    cfg_if! {
        if #[cfg(feature = "server")] {
            /// Decrypts an encrypted keyring using the RSA private key.
            pub fn decrypt_keyring(&self, data: &[u8]) -> MsgResult<Keyring> {
                let decrypted = self
                    .private_key
                    .decrypt(Pkcs1v15Encrypt::default(), data)?;

                if decrypted.len() != 64 {
                    return Err(MsgError::KeyLength);
                }

                let mut strong = [0u8; 32];
                let mut fast = [0u8; 16];
                let mut iv = [0u8; 16];

                strong.copy_from_slice(&decrypted[0..32]);
                fast.copy_from_slice(&decrypted[32..48]);
                iv.copy_from_slice(&decrypted[48..64]);

                Ok(Keyring { strong, fast, iv })
            }

            /// Signs data using the RSA private key.
            pub fn sign_data(&self, data: &[u8]) -> MsgResult<Bytes> {
                let digest = Sha256::digest(data);

                let signature = self.private_key.sign(
                    Pkcs1v15Sign::new::<Sha256>(),
                    &digest,
                )?;

                Ok(Bytes::from(signature))
            }
        }
    }

    /// Encrypts a keyring using the RSA public key.
    pub fn encrypt_keyring(&self, keyring: &Keyring) -> MsgResult<Bytes> {
        let mut buffer = BytesMut::with_capacity(64);
        let mut rng = rand::thread_rng();

        buffer.extend_from_slice(&keyring.strong);
        buffer.extend_from_slice(&keyring.fast);
        buffer.extend_from_slice(&keyring.iv);

        let encrypted = self
            .public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt::default(), &buffer)?;

        Ok(Bytes::from(encrypted))
    }

    /// Retrieves the RSA public key in DER format.
    pub fn get_public_key_der(&self) -> MsgResult<Bytes> {
        self.public_key
            .to_public_key_der()
            .map(|der| Bytes::from(der.as_bytes().to_vec()))
            .map_err(|_| MsgError::Rsa(rsa::Error::Internal))
    }

    /// Verifies the signature of a message using the RSA public key.
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> MsgResult<()> {
        let digest = Sha256::digest(data);
        self.public_key
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, signature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128cbc() {
        let keyring = Keyring::new();
        let aes_context = AesContext::new(keyring.clone());

        let data = b"Hello, World! This is a test message.";

        let encrypted_strong = aes_context.encrypt_strong(data, CipherMode::Cbc).unwrap();
        let decrypted_strong = aes_context
            .decrypt_strong(&encrypted_strong, CipherMode::Cbc)
            .unwrap();
        assert_eq!(data.to_vec(), decrypted_strong.to_vec());
    }

    #[test]
    fn test_aes128ebc() {
        let keyring = Keyring::new();
        let aes_context = AesContext::new(keyring.clone());

        let data = b"Hello, World! This is a test message.";

        let encrypted_fast = aes_context.encrypt_fast(data, CipherMode::Ecb).unwrap();
        let decrypted_fast = aes_context
            .decrypt_fast(&encrypted_fast, CipherMode::Ecb)
            .unwrap();
        assert_eq!(data.to_vec(), decrypted_fast.to_vec());
    }

    #[test]
    fn test_rsa_encrypt_decrypt_keyring() {
        let rsa_context = RsaContext::new(2048).unwrap();
        let keyring = Keyring::new();

        let encrypted_keyring = rsa_context.encrypt_keyring(&keyring).unwrap();
        let decrypted_keyring = rsa_context.decrypt_keyring(&encrypted_keyring).unwrap();

        assert_eq!(keyring.strong.to_vec(), decrypted_keyring.strong.to_vec());
        assert_eq!(keyring.fast.to_vec(), decrypted_keyring.fast.to_vec());
        assert_eq!(keyring.iv.to_vec(), decrypted_keyring.iv.to_vec());
    }
}
