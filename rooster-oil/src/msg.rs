use bitflags::bitflags;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use flate2::{Compress, Compression, FlushCompress};
use uuid::Uuid;

use crate::{MsgError, MsgResult};

/// The length of the message header in bytes.
const HEADER_LEN: usize = 4;

/// The magic number used to identify valid packets.
const PACKET_MAGIC: u16 = 0x5713;

/// The threshold above which messages are compressed.
const UNCOMPRESSED_THRESHOLD: usize = 50;

bitflags! {
    /// Represents the capabilities of a message.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Capabilities: u32 {
        /// Indicates support for compression.
        const COMPRESSION = 16;

        /// Indicates support for encryption.
        const ENCRYPTION = 32;

        /// Indicates support for UDP transport.
        const UDP = 64;

        /// Indicates support for P2P transport.
        const P2P = 128;
    }
}

/// Represents a message with a byte buffer and bit-level access.
#[derive(Debug)]
pub struct Message {
    buffer: BytesMut,
    read_pos: usize,
    capabilities: Capabilities,
    bit_buffer: u8,
    bit_offset: u8,
}

impl Message {
    /// Creates a new empty message.
    pub fn new() -> Self {
        let mut msg = Message {
            buffer: BytesMut::new(),
            read_pos: 0,
            capabilities: Capabilities::empty(),
            bit_buffer: 0,
            bit_offset: 0,
        };

        msg.write_u16(PACKET_MAGIC);
        msg
    }

    /// Creates a new message with the specified capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut msg = Message {
            buffer: BytesMut::with_capacity(capacity),
            read_pos: 0,
            capabilities: Capabilities::empty(),
            bit_buffer: 0,
            bit_offset: 0,
        };

        msg.write_u16(PACKET_MAGIC);
        msg
    }

    /// Compresses the message buffer using DEFLATE compression.
    pub fn compress(&mut self) -> MsgResult<()> {
        let mut compressor = Compress::new(Compression::new(4), false);
        let mut compressed = Vec::new();

        compressor
            .compress_vec(
                &self.buffer[HEADER_LEN..],
                &mut compressed,
                FlushCompress::Finish,
            )
            .map_err(|e| MsgError::Compress(e))?;
        self.buffer[HEADER_LEN..].fill(0);
        self.buffer[HEADER_LEN..].copy_from_slice(&compressed);

        Ok(())
    }

    /// Retrieves the capabilities of the message as a u32.
    pub const fn get_capabilities_u32(&self) -> u32 {
        self.capabilities.bits()
    }

    /// Checks if the message buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Checks if the message is marked for UDP transport.
    pub const fn is_udp(&self) -> bool {
        self.capabilities.contains(Capabilities::UDP)
    }

    /// Returns the length of the message buffer.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Reads a byte vector from the message buffer.
    pub fn read_bytes(&mut self) -> MsgResult<Vec<u8>> {
        let length = self.read_u32()? as usize;
        if self.read_pos + length > self.buffer.len() {
            return Err(MsgError::Underflow(length));
        }
        let bytes = self.buffer[self.read_pos..self.read_pos + length].to_vec();
        self.read_pos += length;
        Ok(bytes)
    }

    /// Reads a 32-bit floating point number from the message buffer.
    pub fn read_f32(&mut self) -> MsgResult<f32> {
        if self.read_pos + 4 > self.buffer.len() {
            return Err(MsgError::Underflow(4));
        }
        let value = (&self.buffer[self.read_pos..self.read_pos + 4]).get_f32_le();
        self.read_pos += 4;
        Ok(value)
    }

    /// Reads a 64-bit floating point number from the message buffer.
    pub fn read_f64(&mut self) -> MsgResult<f64> {
        if self.read_pos + 8 > self.buffer.len() {
            return Err(MsgError::Underflow(8));
        }
        let value = (&self.buffer[self.read_pos..self.read_pos + 8]).get_f64_le();
        self.read_pos += 8;
        Ok(value)
    }

    /// Reads a GUID from the message buffer.
    pub fn read_guid(&mut self) -> MsgResult<Uuid> {
        let bytes = self.read_raw(16)?;
        let uuid = Uuid::from_slice(&bytes).map_err(|e| MsgError::Guid(e))?;
        Ok(uuid)
    }

    /// Reads a 32-bit signed integer from the message buffer.
    pub fn read_i32(&mut self) -> MsgResult<i32> {
        if self.read_pos + 4 > self.buffer.len() {
            return Err(MsgError::Underflow(4));
        }
        let value = (&self.buffer[self.read_pos..self.read_pos + 4]).get_i32_le();
        self.read_pos += 4;
        Ok(value)
    }

    /// Reads raw bytes from the message buffer.
    pub fn read_raw(&mut self, length: usize) -> MsgResult<Bytes> {
        if self.read_pos + length > self.buffer.len() {
            return Err(MsgError::Underflow(length));
        }
        let bytes = self.buffer.slice(self.read_pos..self.read_pos + length);
        self.read_pos += length;
        Ok(bytes)
    }

    /// Reads a string from the message buffer.
    pub fn read_string(&mut self) -> MsgResult<String> {
        let length = self.read_u16()? as usize;
        if self.read_pos + length > self.buffer.len() {
            return Err(MsgError::Underflow(length));
        }
        let string_bytes = &self.buffer[self.read_pos..self.read_pos + length];
        self.read_pos += length;
        let string = String::from_utf8(string_bytes.to_vec()).map_err(|e| MsgError::Utf8(e))?;
        Ok(string)
    }

    /// Reads a single byte from the message buffer.
    pub fn read_u8(&mut self) -> MsgResult<u8> {
        if self.read_pos + 1 > self.buffer.len() {
            return Err(MsgError::Underflow(1));
        }
        let value = self.buffer[self.read_pos];
        self.read_pos += 1;
        Ok(value)
    }

    /// Reads a 16-bit unsigned integer from the message buffer.
    pub fn read_u16(&mut self) -> MsgResult<u16> {
        if self.read_pos + 2 > self.buffer.len() {
            return Err(MsgError::Underflow(2));
        }
        let value = (&self.buffer[self.read_pos..self.read_pos + 2]).get_u16_le();
        self.read_pos += 2;
        Ok(value)
    }

    /// Reads a 32-bit unsigned integer from the message buffer.
    pub fn read_u32(&mut self) -> MsgResult<u32> {
        if self.read_pos + 4 > self.buffer.len() {
            return Err(MsgError::Underflow(4));
        }
        let value = (&self.buffer[self.read_pos..self.read_pos + 4]).get_u32_le();
        self.read_pos += 4;
        Ok(value)
    }

    /// Reads a 64-bit unsigned integer from the message buffer.
    pub fn read_u64(&mut self) -> MsgResult<u64> {
        if self.read_pos + 8 > self.buffer.len() {
            return Err(MsgError::Underflow(8));
        }
        let value = (&self.buffer[self.read_pos..self.read_pos + 8]).get_u64_le();
        self.read_pos += 8;
        Ok(value)
    }

    /// Reads a Unicode string from the message buffer in UTF-16 encoding.
    pub fn read_unicode(&mut self) -> MsgResult<String> {
        let length = self.read_u16()? as usize;
        let byte_length = length * 2;

        if self.read_pos + byte_length > self.buffer.len() {
            return Err(MsgError::Underflow(byte_length));
        }

        let mut utf16: Vec<u16> = Vec::with_capacity(length);
        for _ in 0..length {
            let code_unit = self.read_u16()?;
            utf16.push(code_unit);
        }

        String::from_utf16(&utf16).map_err(|e| MsgError::Utf16(e))
    }

    /// Reads a variable-length integer from the message buffer.
    pub fn read_var(&mut self) -> MsgResult<u64> {
        let size = self.read_u8()?;

        match size {
            1 => Ok(self.read_i8()? as u64),
            2 => Ok(self.read_i16()? as u64),
            4 => Ok(self.read_i32()? as u64),
            8 => Ok(self.read_i64()? as u64),
            _ => Err(MsgError::VarLength(size)),
        }
    }

    /// Returns the number of remaining unread bytes in the message buffer.
    pub fn remaining(&self) -> usize {
        self.buffer.len().saturating_sub(self.read_pos)
    }

    /// Resets the read position to the beginning of the message buffer.
    pub fn reset_read(&mut self) {
        self.read_pos = 0;
    }

    /// Determines if the message should be compressed based on its length.
    pub fn should_compress(&self) -> bool {
        (self.buffer.len() - HEADER_LEN) > UNCOMPRESSED_THRESHOLD
    }

    /// Enables or disables UDP capability for the message.
    pub fn set_udp(&mut self, enabled: bool) {
        if enabled {
            self.capabilities.insert(Capabilities::UDP);
        } else {
            self.capabilities.remove(Capabilities::UDP);
        }
    }

    /// Writes a specified number of bits from a u32 value to the message buffer.
    pub fn write_bits(&mut self, value: u32, bit_count: u8) -> MsgResult<()> {
        if bit_count > 32 {
            return Err(MsgError::Bits(bit_count));
        }

        for i in 0..bit_count {
            let bit = (value >> i) & 1;
            self.bit_buffer |= (bit as u8) << self.bit_offset;
            self.bit_offset += 1;

            if self.bit_offset == 8 {
                self.buffer.put_u8(self.bit_buffer);
                self.bit_buffer = 0;
                self.bit_offset = 0;
            }
        }

        Ok(())
    }

    /// Writes a boolean value to the message buffer.
    pub fn write_bool(&mut self, value: bool) {
        self.flush_bits();
        self.write_u8(if value { 1 } else { 0 });
    }

    /// Writes a byte slice to the message buffer, prefixed with its length as a 32-bit unsigned integer.
    pub fn write_bytes(&mut self, data: &[u8]) {
        self.flush_bits();
        self.write_u32(data.len() as u32);
        self.buffer.put_slice(data);
    }

    /// Writes a 32-bit floating point number to the message buffer.
    pub fn write_f32(&mut self, value: f32) {
        self.flush_bits();
        self.buffer.put_f32_le(value);
    }

    /// Writes a 64-bit floating point number to the message buffer.
    pub fn write_f64(&mut self, value: f64) {
        self.flush_bits();
        self.buffer.put_f64_le(value);
    }

    /// Writes a GUID to the message buffer.
    pub fn write_guid(&mut self, value: &Uuid) {
        self.flush_bits();
        self.buffer.put_slice(value.as_bytes());
    }

    /// Writes a 16-bit signed integer to the message buffer.
    pub fn write_i16(&mut self, value: i16) {
        self.flush_bits();
        self.buffer.put_i16_le(value);
    }

    /// Writes a 32-bit signed integer to the message buffer.
    pub fn write_i32(&mut self, value: i32) {
        self.flush_bits();
        self.buffer.put_i32_le(value);
    }

    /// Writes a 64-bit signed integer to the message buffer.
    pub fn write_i64(&mut self, value: i64) {
        self.flush_bits();
        self.buffer.put_i64_le(value);
    }

    /// Writes raw bytes to the message buffer without any length prefix.
    pub fn write_raw(&mut self, data: &[u8]) {
        self.flush_bits();
        self.buffer.put_slice(data);
    }

    /// Writes a string to the message buffer, prefixed with its length as a 16-bit unsigned integer.
    pub fn write_string(&mut self, value: &str) {
        self.flush_bits();
        let bytes = value.as_bytes();
        self.write_u16(bytes.len() as u16);
        self.buffer.put_slice(bytes);
    }

    /// Writes a single byte to the message buffer.
    pub fn write_u8(&mut self, value: u8) {
        self.flush_bits();
        self.buffer.put_u8(value);
    }

    /// Writes a 16-bit unsigned integer to the message buffer.
    pub fn write_u16(&mut self, value: u16) {
        self.flush_bits();
        self.buffer.put_u16_le(value);
    }

    /// Writes a 32-bit unsigned integer to the message buffer.
    pub fn write_u32(&mut self, value: u32) {
        self.flush_bits();
        self.buffer.put_u32_le(value);
    }

    /// Writes a 64-bit unsigned integer to the message buffer.
    pub fn write_u64(&mut self, value: u64) {
        self.flush_bits();
        self.buffer.put_u64_le(value);
    }

    /// Writes a Unicode string to the message buffer in UTF-16 encoding,
    pub fn write_unicode(&mut self, value: &str) {
        self.flush_bits();
        let utf16: Vec<u16> = value.encode_utf16().collect();
        self.write_u16(utf16.len() as u16);
        for code_unit in utf16 {
            self.write_u16(code_unit);
        }
    }

    /// Writes a variable-length integer to the message buffer.
    pub fn write_var(&mut self, value: u64) {
        self.flush_bits();
        if value <= u8::MAX as u64 {
            self.write_u8(1);
            self.write_u8(value as u8);
        } else if value <= u16::MAX as u64 {
            self.write_u8(2);
            self.write_u16(value as u16);
        } else if value <= u32::MAX as u64 {
            self.write_u8(4);
            self.write_u32(value as u32);
        } else {
            self.write_u8(8);
            self.write_u64(value);
        }
    }

    /// Flushes any remaining bits in the bit buffer to the main buffer.
    fn flush_bits(&mut self) {
        if self.bit_offset > 0 {
            self.buffer.put_u8(self.bit_buffer);
            self.bit_buffer = 0;
            self.bit_offset = 0;
        }
    }
}

impl AsMut<[u8]> for Message {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl Default for Message {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&[u8]> for Message {
    fn from(data: &[u8]) -> Self {
        Self {
            buffer: BytesMut::from(data),
            read_pos: 0,
            capabilities: Capabilities::empty(),
            bit_buffer: 0,
            bit_offset: 0,
        }
    }
}

impl From<Bytes> for Message {
    fn from(data: Bytes) -> Self {
        Self {
            buffer: BytesMut::from(&data[..]),
            read_pos: 0,
            capabilities: Capabilities::empty(),
            bit_buffer: 0,
            bit_offset: 0,
        }
    }
}

impl From<Message> for Bytes {
    fn from(mut msg: Message) -> Self {
        msg.flush_bits();
        let total_len = msg.buffer.len();
        let mut buf = BytesMut::with_capacity(4 + total_len);
        buf.put_u32_le(total_len as u32);
        buf.put_slice(&msg.buffer);
        buf.freeze()
    }
}

impl From<Message> for Vec<u8> {
    fn from(mut msg: Message) -> Self {
        msg.flush_bits();
        msg.buffer.to_vec()
    }
}

impl TryFrom<BytesMut> for Message {
    type Error = MsgError;

    fn try_from(mut data: BytesMut) -> Result<Self, Self::Error> {
        if data.len() < 4 {
            return Err(MsgError::Underflow(4));
        }
        let msg_len = (&data[..4]).get_u32_le() as usize;
        if data.len() < 4 + msg_len {
            return Err(MsgError::Underflow(4 + msg_len));
        }

        data.advance(4);
        let msg_bytes = data.split_to(msg_len);
        Ok(Self::from(&msg_bytes[..]))
    }
}
