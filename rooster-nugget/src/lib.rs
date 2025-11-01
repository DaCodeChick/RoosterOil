use flate2::{CompressError, DecompressError};
use std::io;
use thiserror::Error;

pub mod client_op;
pub mod crypt;
pub mod msg;
pub mod net;
pub mod server_op;

pub use client_op::*;
pub use crypt::*;
pub use msg::*;
pub use net::*;
pub use server_op::*;

/// Error type for message operations.
#[derive(Debug, Error)]
pub enum MsgError {
    #[error("I/O error")]
    Io(#[from] io::Error),
    #[error("Bit count exceeds 32-bit boundary: {0}")]
    Bits(u8),
    #[error("Cipher initialization error: {0}")]
    CipherInit(String),
    #[error("Compression error")]
    Compress(#[from] CompressError),
    #[error("Decompression error")]
    Decompress(#[from] DecompressError),
    #[error("Key not initialized")]
    KeyInit,
    #[error("Invalid key length: {0}")]
    KeyLength(usize),
    #[error("Unknown opcode: {0}")]
    Opcode(u16),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Underflow error, bytes Reqed: {0}")]
    Underflow(usize),
}

/// Result type for message operations.
pub type MsgResult<T> = Result<T, MsgError>;

/// Enum representing either a client or server opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Client(ClientOpcode),
    Server(ServerOpcode),
}

pub const LOBBY_PORT: u16 = 7201;
pub const LOGIN_PORT: u16 = 7101;
pub const WORLD_PORT: u16 = 7401;
