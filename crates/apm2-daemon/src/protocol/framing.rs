//! Length-prefixed frame codec for the UDS protocol.
//!
//! This module implements a [`tokio_util::codec`] compatible codec for
//! length-prefixed binary framing. Each frame consists of:
//!
//! ```text
//! +----------------------------+------------------+
//! | Length (4 bytes, BE)       | Payload          |
//! +----------------------------+------------------+
//! ```
//!
//! # Security Considerations
//!
//! Per [CTR-1603] and [RSK-1601], the codec enforces bounded reads:
//! - Frame length is validated BEFORE allocation
//! - Maximum frame size is [`MAX_FRAME_SIZE`] (16 MiB)
//! - Oversized frames are rejected with [`ProtocolError::FrameTooLarge`]
//!
//! # Contract: CTR-1601
//!
//! Protocol framing is explicit with:
//! - 4-byte big-endian length prefix
//! - Maximum frame size cap
//! - Deterministic encoding

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use super::error::{MAX_FRAME_SIZE, ProtocolError, ProtocolResult};

/// Length of the frame header (4 bytes for u32 length prefix).
const HEADER_LEN: usize = 4;

/// Frame codec implementing length-prefixed binary framing.
///
/// This codec is used with [`tokio_util::codec::Framed`] to provide
/// frame-based I/O over async streams.
///
/// # Invariants
///
/// - [INV-FRAME-001] Frames are at most [`MAX_FRAME_SIZE`] bytes.
/// - [INV-FRAME-002] Length prefix is always 4 bytes, big-endian.
/// - [INV-FRAME-003] Empty frames (length 0) are valid.
///
/// # Example
///
/// ```ignore
/// use tokio::net::UnixStream;
/// use tokio_util::codec::Framed;
/// use apm2_daemon::protocol::FrameCodec;
///
/// let stream = UnixStream::connect(path).await?;
/// let mut framed = Framed::new(stream, FrameCodec::new());
/// ```
#[derive(Debug, Clone, Default)]
pub struct FrameCodec {
    /// Maximum allowed frame size.
    max_frame_size: usize,
}

impl FrameCodec {
    /// Create a new frame codec with default maximum frame size.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
        }
    }

    /// Create a frame codec with a custom maximum frame size.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum frame size in bytes. Must not exceed
    ///   [`MAX_FRAME_SIZE`].
    ///
    /// # Panics
    ///
    /// Panics if `max_size` exceeds [`MAX_FRAME_SIZE`].
    #[must_use]
    pub fn with_max_size(max_size: usize) -> Self {
        assert!(
            max_size <= MAX_FRAME_SIZE,
            "max_size {max_size} exceeds protocol limit {MAX_FRAME_SIZE}"
        );
        Self {
            max_frame_size: max_size,
        }
    }

    /// Returns the maximum frame size for this codec.
    #[must_use]
    pub const fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Set the maximum frame size for this codec.
    ///
    /// # Arguments
    ///
    /// * `max_size` - New maximum frame size in bytes. Must not exceed
    ///   [`MAX_FRAME_SIZE`].
    ///
    /// # Panics
    ///
    /// Panics if `max_size` exceeds [`MAX_FRAME_SIZE`].
    pub fn set_max_frame_size(&mut self, max_size: usize) {
        assert!(
            max_size <= MAX_FRAME_SIZE,
            "max_size {max_size} exceeds protocol limit {MAX_FRAME_SIZE}"
        );
        self.max_frame_size = max_size;
    }
}

impl Decoder for FrameCodec {
    type Item = Bytes;
    type Error = ProtocolError;

    /// Decode a frame from the input buffer.
    ///
    /// # Contract: CTR-1603 (Bounded Reads)
    ///
    /// The frame length is validated against `max_frame_size` BEFORE
    /// any allocation occurs. This prevents memory exhaustion attacks
    /// where an attacker sends a large length prefix.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(frame))` if a complete frame was decoded
    /// - `Ok(None)` if more data is needed
    /// - `Err(ProtocolError::FrameTooLarge)` if frame exceeds max size
    fn decode(&mut self, src: &mut BytesMut) -> ProtocolResult<Option<Bytes>> {
        // Need at least the header to determine frame length
        if src.len() < HEADER_LEN {
            return Ok(None);
        }

        // Read length prefix without consuming
        let length = u32::from_be_bytes([src[0], src[1], src[2], src[3]]) as usize;

        // CTR-1603: Validate length BEFORE allocation
        if length > self.max_frame_size {
            return Err(ProtocolError::frame_too_large(length, self.max_frame_size));
        }

        // Check if we have the complete frame
        let total_len = HEADER_LEN + length;
        if src.len() < total_len {
            // Reserve capacity for the expected frame to reduce reallocations
            src.reserve(total_len - src.len());
            return Ok(None);
        }

        // Consume the header
        src.advance(HEADER_LEN);

        // Split off the payload
        let payload = src.split_to(length).freeze();

        Ok(Some(payload))
    }
}

impl Encoder<Bytes> for FrameCodec {
    type Error = ProtocolError;

    /// Encode a frame into the output buffer.
    ///
    /// # Contract: INV-FRAME-001
    ///
    /// Frames larger than `max_frame_size` are rejected to maintain
    /// protocol invariants.
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> ProtocolResult<()> {
        // Validate frame size
        if item.len() > self.max_frame_size {
            return Err(ProtocolError::FrameTooLarge {
                size: item.len(),
                max: self.max_frame_size,
            });
        }

        // Reserve space for header + payload
        dst.reserve(HEADER_LEN + item.len());

        // Write length prefix (big-endian u32)
        #[allow(clippy::cast_possible_truncation)] // Validated above
        let length = item.len() as u32;
        dst.put_u32(length);

        // Write payload
        dst.extend_from_slice(&item);

        Ok(())
    }
}

/// Encoder implementation for `&[u8]` slices.
impl Encoder<&[u8]> for FrameCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> ProtocolResult<()> {
        // Validate frame size
        if item.len() > self.max_frame_size {
            return Err(ProtocolError::FrameTooLarge {
                size: item.len(),
                max: self.max_frame_size,
            });
        }

        // Reserve space for header + payload
        dst.reserve(HEADER_LEN + item.len());

        // Write length prefix (big-endian u32)
        #[allow(clippy::cast_possible_truncation)] // Validated above
        let length = item.len() as u32;
        dst.put_u32(length);

        // Write payload
        dst.extend_from_slice(item);

        Ok(())
    }
}

/// Encoder implementation for `Vec<u8>`.
impl Encoder<Vec<u8>> for FrameCodec {
    type Error = ProtocolError;

    fn encode(&mut self, item: Vec<u8>, dst: &mut BytesMut) -> ProtocolResult<()> {
        self.encode(item.as_slice(), dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let mut codec = FrameCodec::new();
        let payload = Bytes::from_static(b"hello world");

        // Encode
        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).unwrap();

        // Verify wire format
        assert_eq!(buf.len(), HEADER_LEN + payload.len());
        assert_eq!(&buf[..4], &[0, 0, 0, 11]); // Big-endian 11

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded, payload);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_decode_partial_header() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::from(&[0u8, 0, 0][..]); // Only 3 bytes

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
        assert_eq!(buf.len(), 3); // Buffer unchanged
    }

    #[test]
    fn test_decode_partial_payload() {
        let mut codec = FrameCodec::new();
        // Header says 10 bytes, but only 5 provided
        let mut buf = BytesMut::from(&[0u8, 0, 0, 10, 1, 2, 3, 4, 5][..]);

        let result = codec.decode(&mut buf).unwrap();
        assert!(result.is_none());
        assert_eq!(buf.len(), 9); // Buffer unchanged
    }

    #[test]
    fn test_decode_frame_too_large() {
        let mut codec = FrameCodec::new();
        // Length prefix indicating 20 MiB (exceeds 16 MiB limit)
        let oversized_len = 20 * 1024 * 1024u32;
        let mut buf = BytesMut::new();
        buf.put_u32(oversized_len);
        buf.extend_from_slice(&[0u8; 100]); // Some payload bytes

        let result = codec.decode(&mut buf);
        assert!(matches!(
            result,
            Err(ProtocolError::FrameTooLarge { size, max })
            if size == oversized_len as usize && max == MAX_FRAME_SIZE
        ));
    }

    #[test]
    fn test_encode_frame_too_large() {
        let mut codec = FrameCodec::with_max_size(100);
        let large_payload = Bytes::from(vec![0u8; 200]);

        let mut buf = BytesMut::new();
        let result = codec.encode(large_payload, &mut buf);

        assert!(matches!(
            result,
            Err(ProtocolError::FrameTooLarge { size, max })
            if size == 200 && max == 100
        ));
    }

    #[test]
    fn test_empty_frame() {
        let mut codec = FrameCodec::new();
        let payload = Bytes::new();

        // Encode empty frame
        let mut buf = BytesMut::new();
        codec.encode(payload, &mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_LEN);
        assert_eq!(&buf[..4], &[0, 0, 0, 0]);

        // Decode empty frame
        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_multiple_frames() {
        let mut codec = FrameCodec::new();
        let frame1 = Bytes::from_static(b"first");
        let frame2 = Bytes::from_static(b"second");

        // Encode both frames
        let mut buf = BytesMut::new();
        codec.encode(frame1.clone(), &mut buf).unwrap();
        codec.encode(frame2.clone(), &mut buf).unwrap();

        // Decode first frame
        let decoded1 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded1, frame1);

        // Decode second frame
        let decoded2 = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded2, frame2);

        assert!(buf.is_empty());
    }

    #[test]
    fn test_custom_max_size() {
        let codec = FrameCodec::with_max_size(1024);
        assert_eq!(codec.max_frame_size(), 1024);
    }

    #[test]
    #[should_panic(expected = "exceeds protocol limit")]
    fn test_custom_max_size_exceeds_limit() {
        let _ = FrameCodec::with_max_size(MAX_FRAME_SIZE + 1);
    }

    #[test]
    fn test_encode_slice() {
        let mut codec = FrameCodec::new();
        let payload: &[u8] = b"slice data";

        let mut buf = BytesMut::new();
        codec.encode(payload, &mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_LEN + payload.len());
    }

    #[test]
    fn test_encode_vec() {
        let mut codec = FrameCodec::new();
        let payload = vec![1u8, 2, 3, 4, 5];

        let mut buf = BytesMut::new();
        codec.encode(payload.clone(), &mut buf).unwrap();

        assert_eq!(buf.len(), HEADER_LEN + payload.len());
    }

    #[test]
    fn test_max_valid_frame() {
        // Test encoding/decoding a frame at exactly MAX_FRAME_SIZE
        // Note: We use a smaller size for the actual test to avoid allocating 16MB
        let mut codec = FrameCodec::with_max_size(1024);
        let payload = Bytes::from(vec![0xABu8; 1024]);

        let mut buf = BytesMut::new();
        codec.encode(payload, &mut buf).unwrap();

        let decoded = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.len(), 1024);
    }
}
