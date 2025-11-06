use std::io::Bytes;

use aes::{Aes128, Aes256, KeyInit};
use bytes::{Bytes, BytesMut};
use cbc::{Decryptor as CBCDec, Encryptor as CBCEnc};
use cfg_if::cfg_if;
use cipher::{BlockDecrypt, BlockEncrypt, block_padding::Pkcs7};
use crc32fast;
use ctr::Ctr128BE;
use ecb::{Decryptor as ECBDec, Encryptor as ECBEnc};
use rand::{RngCore, rngs::OsRng};
use rsa::{Hash, PaddingScheme, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey};
use sha2::Sha256;

use crate::{MsgError, MsgResult};

/// Supported cipher modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Ecb = 0,
    Cbc,
    Ctr,
}

/// Represents a keyring containing strong and fast keys along with an initialization vector.
#[derive(Debug, Clone)]
pub struct Keyring {
    strong: [u8; 32],
    fast: [u8; 16],
    iv: [u8; 16],
}

impl Keyring {
    /// Creates a new keyring with random keys.
    pub fn new() -> Self {
        let mut strong = [0u8; 32];
        let mut fast = [0u8; 16];
        let mut iv = [0u8; 16];

        RngCore::fill_bytes(&mut OsRng, &mut strong);
        RngCore::fill_bytes(&mut OsRng, &mut fast);
        RngCore::fill_bytes(&mut OsRng, &mut iv);

        Self { strong, fast, iv }
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
        let cipher = CBCDec::<Aes128>::new_from_slice(&self.fast, &self.iv[..16])
            .map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-128 in CBC mode.
    fn aes128_cbc_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCEnc::<Aes128>::new_from_slice(&self.fast, &self.iv[..16])
            .map_err(|_| MsgError::KeyLength)?;
        cipher
            .encrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts and decrypts data using AES-128 in CTR mode.
    fn aes128_ctr_crypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = Ctr128BE::new_from_slices(&self.fast, &self.iv[..16])
            .map_err(|_| MsgError::KeyLength)?;
        let mut buffer = data.to_vec();

        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    /// Decrypts data using AES-128 in ECB mode.
    fn aes128_ecb_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBDec::<Aes128>::new_from_slice(&self.fast).map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-128 in ECB mode.
    fn aes128_ecb_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBEnc::<Aes128>::new_from_slice(&self.fast).map_err(|_| MsgError::KeyLength)?;
        cipher
            .encrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Decrypts data using AES-256 in CBC mode.
    fn aes256_cbc_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCDec::<Aes256>::new_from_slices(&self.strong, &self.iv)
            .map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-256 in CBC mode.
    fn aes256_cbc_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher = CBCEnc::<Aes256>::new_from_slices(&self.strong, &self.iv)
            .map_err(|_| MsgError::KeyLength)?;
        cipher
            .encrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts and decrypts data using AES-256 in CTR mode.
    fn aes256_ctr_crypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            Ctr128BE::new_from_slices(&self.strong, &self.iv).map_err(|_| MsgError::KeyLength)?;
        let mut buffer = data.to_vec();

        cipher.apply_keystream(&mut buffer);
        Ok(buffer)
    }

    /// Decrypts data using AES-256 in ECB mode.
    fn aes256_ecb_decrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBDec::<Aes256>::new_from_slice(&self.strong).map_err(|_| MsgError::KeyLength)?;
        cipher
            .decrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
    }

    /// Encrypts data using AES-256 in ECB mode.
    fn aes256_ecb_encrypt(&self, data: &[u8]) -> MsgResult<Vec<u8>> {
        let cipher =
            ECBEnc::<Aes256>::new_from_slice(&self.strong).map_err(|_| MsgError::KeyLength)?;
        cipher
            .encrypt_padded_vec_mut::<Pkcs7>(data)
            .map_err(|_| MsgError::Aes)
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
        let private_key = RsaPrivateKey::new(&mut OsRng, key_size)?;
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
                    .decrypt(PaddingScheme::new_pkcs1v15_encrypt(), data)?;

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
                    PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
                    &digest,
                )?;

                Ok(Bytes::from(signature))
            }
        }
    }

    /// Encrypts a keyring using the RSA public key.
    pub fn encrypt_keyring(&self, keyring: &Keyring) -> MsgResult<Bytes> {
        let mut buffer = BytesMut::with_capacity(64);

        buffer.extend_from_slice(&keyring.strong);
        buffer.extend_from_slice(&keyring.fast);
        buffer.extend_from_slice(&keyring.iv);

        let encrypted =
            self.public_key
                .encrypt(&mut OsRng, PaddingScheme::new_pkcs1v15_encrypt(), &buffer)?;

        Ok(Bytes::from(encrypted))
    }

    /// Retrieves the RSA public key in DER format.
    pub fn get_public_key_der(&self) -> MsgResult<Bytes> {
        self.public_key
            .to_public_key_der()
            .map(|der| Bytes::from(der.as_bytes()))
            .map_err(|_| MsgError::Rsa(rsa::Error::Internal))
    }

    /// Verifies the signature of a message using the RSA public key.
    pub fn verify_signature(&self, data: &[u8], signature: &[u8]) -> MsgResult<()> {
        let digest = Sha256::digest(data);
        self.public_key.verify(
            PaddingScheme::new_pkcs1v15_sign::<Sha256>(),
            &digest,
            signature,
        )?;

        Ok(())
    }
}
