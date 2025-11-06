use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{AesContext, Message, MsgError, MsgResult};

/// Represents a Remote Method Invocation (RMI) packet.
#[derive(Debug)]
pub struct RMIPacket(Message);

impl RMIPacket {
    /// Creates a new RMI packet with the specified opcode.
    pub fn new(_opcode: u16) -> Self {
        Self(Message::with_capacity(64))
    }

    /// Finalizes and returns the constructed RMI packet.
    pub fn build(mut self) -> MsgResult<Message> {
        if self.0.should_compress() {
            self.0.compress()?;
        }

        Ok(self.0)
    }

    /// Adds an i64 payload to the RMI packet.
    pub fn with_i64(&mut self, value: i64) {
        self.0.write_i64(value);
    }

    /// Adds a string payload to the RMI packet.
    pub fn with_string(mut self, value: &str) -> Self {
        self.0.write_string(value);
        self
    }

    /// Adds a u16 payload to the RMI packet.
    pub fn with_u16(mut self, value: u16) -> Self {
        self.0.write_u16(value);
        self
    }

    /// Adds a u32 payload to the RMI packet.
    pub fn with_u32(mut self, value: u32) -> Self {
        self.0.write_u32(value);
        self
    }

    /// Adds a u64 payload to the RMI packet.
    pub fn with_u64(mut self, value: u64) -> Self {
        self.0.write_u64(value);
        self
    }

    /// Adds a Unicode string payload to the RMI packet.
    pub fn with_unicode(mut self, value: &str) -> Self {
        self.0.write_unicode(value);
        self
    }
}

/*
/// Codec for encoding and decoding messages with optional encryption.
#[derive(Debug)]
pub struct Codec(AesContext);

impl Decoder for Codec {
    type Item = Message;
    type Error = MsgError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }
        let msg_len = (&src[..4]).get_u32_le() as usize;
        if src.len() < 4 + msg_len {
            src.reserve(4 + msg_len);
            return Ok(None);
        }

        src.advance(4);
        let mut msg_bytes = src.split_to(msg_len);

        let payload = if self.0.has_key() {
            self.0.decrypt(&mut msg_bytes)?;
            msg_bytes.freeze()
        } else {
            msg_bytes.freeze()
        };

        Ok(Some(Message::from(payload)))
    }
}

impl Encoder<Message> for Codec {
    type Error = MsgError;

    fn encode(&mut self, mut item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload = if self.0.has_key() {
            self.0.encrypt(item.as_mut())?;
            item.as_ref()
        } else {
            item.as_ref()
        };

        dst.reserve(4 + payload.len());
        dst.put_u32_le(payload.len() as u32);
        dst.put_slice(&payload);
        Ok(())
    }
}*/
