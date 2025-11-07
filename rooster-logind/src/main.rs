use bytes::Bytes;
use dashmap::DashMap;

use rooster_oil::{AesContext, Keyring, MsgResult, RsaContext};

/// Number of bits for RSA keys.
const RSA_BITS: usize = 2048;

#[derive(Debug)]
pub struct Server {
    rsa: RsaContext,
    sessions: DashMap<u32, AesContext>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            rsa: RsaContext::new(RSA_BITS),
            sessions: DashMap::new(),
        }
    }
}

#[tokio::main]
async fn main() {}
