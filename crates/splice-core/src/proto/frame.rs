//! Frame codec (§7.2).
//!
//! ```text
//! +----------+----------+------------------------+
//! | type: u8 | flags: u8|  len: u32 (big-endian) |
//! +----------+----------+------------------------+
//! |          body (len byte)                      |
//! +-----------------------------------------------+
//! ```
//!
//! I9: `len` is rejected **before** any body buffer is allocated. The decoder takes
//! the header alone and only then decides how much to read, so a peer cannot make
//! us reserve 4 GiB with a 6-byte message.

use crate::constants::{FRAME_HEADER_LEN, MAX_FRAME_LEN};
use crate::error::{FrameError, Result};

/// Frame type, i.e. the `type` byte. Values below `0x10` are control-plane frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// Control message; body is postcard-encoded `ControlMsg`.
    Control = 0x10,
    /// Phase 3 PTY output bytes.
    Output = 0x20,
    /// Phase 3 PTY input bytes.
    Input = 0x21,
    /// Phase 3 resize.
    Resize = 0x22,
    /// Phase 2 file chunk.
    ChunkData = 0x30,
    /// Connection is going away; body is the reason code.
    Close = 0x7f,
}

impl FrameKind {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x10 => Ok(Self::Control),
            0x20 => Ok(Self::Output),
            0x21 => Ok(Self::Input),
            0x22 => Ok(Self::Resize),
            0x30 => Ok(Self::ChunkData),
            0x7f => Ok(Self::Close),
            other => Err(FrameError::UnknownType { kind: other }.into()),
        }
    }

    /// Raw-byte frames carry no postcard envelope (§7.2).
    pub const fn carries_raw_bytes(self) -> bool {
        matches!(self, Self::Output | Self::Input | Self::ChunkData)
    }
}

/// Frame flag bits. Bit 0 marks a body that is compressed (Phase 2 chunk payloads).
/// Anything else is rejected: an unknown flag means the peer expects behaviour we
/// do not implement, so guessing is worse than closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const NONE: Self = Self(0);
    /// Body is a zstd-compressed chunk payload (Phase 2).
    pub const COMPRESSED: Self = Self(0b0000_0001);

    const SUPPORTED_MASK: u8 = 0b0000_0001;

    pub fn from_byte(byte: u8) -> Result<Self> {
        if byte & !Self::SUPPORTED_MASK != 0 {
            return Err(FrameError::UnsupportedFlags { flags: byte }.into());
        }
        Ok(Self(byte))
    }

    pub const fn as_byte(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

/// A decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: FrameFlags,
    pub body: Vec<u8>,
}

impl Frame {
    /// Build a frame with explicit flags.
    pub fn new(kind: FrameKind, flags: FrameFlags, body: Vec<u8>) -> Result<Self> {
        if body.len() > MAX_FRAME_LEN {
            return Err(FrameError::TooLarge {
                len: body.len() as u64,
                max: MAX_FRAME_LEN,
            }
            .into());
        }
        Ok(Self { kind, flags, body })
    }

    /// Build an uncompressed frame.
    pub fn plain(kind: FrameKind, body: Vec<u8>) -> Result<Self> {
        Self::new(kind, FrameFlags::NONE, body)
    }

    /// Build a CONTROL frame from a wire message.
    pub fn control<M: crate::proto::messages::WireMessage>(message: &M) -> Result<Self> {
        let body = message.encode_to_vec()?;
        Self::plain(FrameKind::Control, body)
    }

    /// Encode header + body.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.body.len());
        out.push(self.kind.as_byte());
        out.push(self.flags.as_byte());
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }
}

/// Decode the header that starts `buf`.
///
/// Returns the frame kind, flags and declared body length. `buf` must be at least
/// [`FRAME_HEADER_LEN`] bytes.
pub fn decode_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::ShortHeader {
            header: FRAME_HEADER_LEN,
        }
        .into());
    }
    let kind = FrameKind::from_byte(buf[0])?;
    let flags = FrameFlags::from_byte(buf[1])?;
    let len = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
    let len_usize = len as usize;
    if len_usize > MAX_FRAME_LEN {
        // Checked here, on the header, before the caller allocates anything.
        return Err(FrameError::TooLarge {
            len: u64::from(len),
            max: MAX_FRAME_LEN,
        }
        .into());
    }
    Ok(Header { kind, flags, len })
}

/// A decoded frame header with a validated length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: FrameKind,
    pub flags: FrameFlags,
    /// Body length in bytes; already known to be `<= MAX_FRAME_LEN`.
    pub len: u32,
}

impl Header {
    /// Attach a body that was read according to this header.
    pub fn into_frame(self, body: Vec<u8>) -> Result<Frame> {
        if body.len() != self.len as usize {
            return Err(FrameError::Truncated {
                declared: self.len,
                received: body.len(),
            }
            .into());
        }
        Ok(Frame {
            kind: self.kind,
            flags: self.flags,
            body,
        })
    }
}

/// Decode a complete buffer (header + body) in one step. Test and convenience path.
pub fn decode(buf: &[u8]) -> Result<(Frame, usize)> {
    let header = decode_header(buf)?;
    let body_start = FRAME_HEADER_LEN;
    let body_end = body_start + header.len as usize;
    if buf.len() < body_end {
        return Err(FrameError::Truncated {
            declared: header.len,
            received: buf.len().saturating_sub(body_start),
        }
        .into());
    }
    let frame = header.into_frame(buf[body_start..body_end].to_vec())?;
    Ok((frame, body_end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn roundtrips_a_frame() {
        let original = Frame::plain(FrameKind::Control, b"hello".to_vec()).unwrap();
        let encoded = original.encode();
        assert_eq!(&encoded[..2], &[0x10, 0x00]);
        assert_eq!(&encoded[2..6], &5u32.to_be_bytes());
        let (decoded, consumed) = decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn roundtrips_an_empty_body() {
        let original = Frame::plain(FrameKind::Close, Vec::new()).unwrap();
        let (decoded, consumed) = decode(&original.encode()).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(consumed, FRAME_HEADER_LEN);
    }

    #[test]
    fn oversized_length_is_rejected_from_the_header_alone() {
        // Header only: 6 bytes claiming 1 MiB + 1. No allocation may happen.
        let mut buf = vec![FrameKind::Control.as_byte(), 0, 0, 0, 0, 0];
        buf[2..6].copy_from_slice(&(MAX_FRAME_LEN as u32 + 1).to_be_bytes());
        match decode_header(&buf) {
            Err(Error::Frame(FrameError::TooLarge { len, max })) => {
                assert_eq!(len, MAX_FRAME_LEN as u64 + 1);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn absurd_length_does_not_allocate() {
        let mut buf = vec![FrameKind::Control.as_byte(), 0, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            decode_header(&buf),
            Err(Error::Frame(FrameError::TooLarge { .. }))
        ));
        // And the same via the one-shot decoder, which must fail on the header.
        assert!(matches!(
            decode(&buf),
            Err(Error::Frame(FrameError::TooLarge { .. }))
        ));
        buf.clear();
    }

    #[test]
    fn exact_limit_is_accepted() {
        let mut buf = vec![FrameKind::Control.as_byte(), 0, 0, 0, 0, 0];
        buf[2..6].copy_from_slice(&(MAX_FRAME_LEN as u32).to_be_bytes());
        assert_eq!(decode_header(&buf).unwrap().len as usize, MAX_FRAME_LEN);
    }

    #[test]
    fn short_header_is_rejected() {
        for len in 0..FRAME_HEADER_LEN {
            let buf = vec![0u8; len];
            assert!(matches!(
                decode_header(&buf),
                Err(Error::Frame(FrameError::ShortHeader { .. }))
            ));
        }
    }

    #[test]
    fn truncated_body_is_rejected() {
        let mut buf = vec![FrameKind::Control.as_byte(), 0, 0, 0, 0, 10];
        buf.extend_from_slice(b"short");
        match decode(&buf) {
            Err(Error::Frame(FrameError::Truncated { declared, received })) => {
                assert_eq!(declared, 10);
                assert_eq!(received, 5);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_and_flags_are_rejected() {
        let mut buf = vec![0x99u8, 0, 0, 0, 0, 0];
        assert!(matches!(
            decode_header(&buf),
            Err(Error::Frame(FrameError::UnknownType { kind: 0x99 }))
        ));
        buf[0] = FrameKind::Control.as_byte();
        buf[1] = 0b0000_0010;
        assert!(matches!(
            decode_header(&buf),
            Err(Error::Frame(FrameError::UnsupportedFlags { .. }))
        ));
    }

    #[test]
    fn flags_roundtrip() {
        assert_eq!(FrameFlags::from_byte(0).unwrap(), FrameFlags::NONE);
        assert_eq!(FrameFlags::from_byte(1).unwrap(), FrameFlags::COMPRESSED);
        assert!(FrameFlags::COMPRESSED.contains(FrameFlags::COMPRESSED));
        assert!(!FrameFlags::NONE.contains(FrameFlags::COMPRESSED));
        assert!(FrameFlags::from_byte(0x80).is_err());
    }

    #[test]
    fn building_an_oversized_frame_fails() {
        let body = vec![0u8; MAX_FRAME_LEN + 1];
        assert!(matches!(
            Frame::plain(FrameKind::Output, body),
            Err(Error::Frame(FrameError::TooLarge { .. }))
        ));
    }

    #[test]
    fn body_length_mismatch_on_attach_is_rejected() {
        let header = Header {
            kind: FrameKind::Control,
            flags: FrameFlags::NONE,
            len: 4,
        };
        assert!(header.into_frame(vec![1, 2, 3]).is_err());
        assert!(header.into_frame(vec![1, 2, 3, 4]).is_ok());
    }

    #[test]
    fn raw_byte_frames_are_marked() {
        assert!(FrameKind::Output.carries_raw_bytes());
        assert!(FrameKind::Input.carries_raw_bytes());
        assert!(FrameKind::ChunkData.carries_raw_bytes());
        assert!(!FrameKind::Control.carries_raw_bytes());
        assert!(!FrameKind::Close.carries_raw_bytes());
    }
}
