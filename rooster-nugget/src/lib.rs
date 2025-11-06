use flate2::{CompressError, DecompressError};
use rsa;
use std::io;
use std::string::{FromUtf8Error, FromUtf16Error};
use thiserror::Error;

pub mod crypt;
pub mod msg;
pub mod net;

pub use crypt::*;
pub use msg::*;
pub use net::*;

/// Error type for message operations.
#[derive(Debug, Error)]
pub enum MsgError {
    #[error("AES encryption/decryption error")]
    Aes,
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("Bit count exceeds 32-bit boundary: {0}")]
    Bits(u8),
    #[error("Compression error")]
    Compress(#[from] CompressError),
    #[error("CRC mismatch: expected {0}, got {1}")]
    CrcMismatch(u32, u32),
    #[error("Decompression error")]
    Decompress(#[from] DecompressError),
    #[error("Invalid key length")]
    KeyLength,
    #[error("Unknown opcode: {0}")]
    Opcode(u16),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("Underflow error, bytes Reqed: {0}")]
    Underflow(usize),
    #[error("UTF-16 conversion error: {0}")]
    Utf16(#[from] FromUtf16Error),
    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] FromUtf8Error),
}

/// Result type for message operations.
pub type MsgResult<T> = Result<T, MsgError>;

pub const LOBBY_PORT: u16 = 7201;
pub const LOGIN_PORT: u16 = 7101;
pub const WORLD_PORT: u16 = 7401;
