use bytes::{Buf, BufMut, BytesMut};
use flate2::{Compress, Compression, FlushCompress};
use tokio_util::codec::{Decoder, Encoder};

use crate::{CryptoContext, Message, MsgError, MsgResult, MsgType};

/// Represents a Remote Method Invocation (RMI) packet.
#[derive(Debug)]
pub struct RMIPacket(Message);

impl RMIPacket {
    /// Creates a new RMI packet with the specified opcode.
    pub fn new(opcode: u16) -> Self {
        let mut msg = Message::with_capacity(64);
        msg.write_u8(MsgType::RemoteMethodInvocation as u8);
        msg.write_u16(opcode);
        Self(msg)
    }

    /// Finalizes and returns the constructed RMI packet.
    pub fn build(mut self) -> MsgResult<Message> {
        if self.0.should_compress() {
            self.compress()?;
        }

        Ok(self.0)
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

    /// Compresses the RMI packet using the specified compression level.
    fn compress(&mut self) -> MsgResult<()> {
        let mut compressor = Compress::new(Compression::new(4), false);
        let mut compressed = Vec::new();
        let input = self.0.as_ref();

        compressor
            .compress_vec(input, &mut compressed, FlushCompress::Finish)
            .map_err(|e| MsgError::Compress(e))?;
        self.0 = Message::from(&compressed[..]);
        Ok(())
    }
}

/// Codec for encoding and decoding messages with optional encryption.
#[derive(Debug)]
pub struct Codec(CryptoContext);

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
}
