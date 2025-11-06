use bytes::Bytes;
use dashmap::DashMap;

use rooster_nugget::{AesContext, Keyring, MsgResult, RsaContext};

#[derive(Debug)]
pub struct Server {
    rsa: RsaContext,
    sessions: DashMap<u32, AesContext>,
}

impl Server {
    pub fn new() -> Self {
        Self {
            rsa: RsaContext::new(2048),
            sessions: DashMap::new(),
        }
    }
}

#[tokio::main]
async fn main() {}
