//! The first byte of every new stream (§7.1).

use crate::error::{ProtoError, Result};

/// Stream type byte. Unknown values are rejected rather than ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    /// Exactly one, opened by the caller. Hello, pairing, trust, ping, bye.
    Control = 0x01,
    /// Phase 3.
    Pty = 0x02,
    /// Phase 2.
    XferCtrl = 0x03,
    /// Phase 2.
    XferData = 0x04,
}

impl StreamType {
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parse the leading byte. Phase 1 only *serves* `Control`; the other three are
    /// known so that a peer using them gets "not in this phase" instead of
    /// "unknown type", which would be misleading.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(Self::Control),
            0x02 => Ok(Self::Pty),
            0x03 => Ok(Self::XferCtrl),
            0x04 => Ok(Self::XferData),
            other => Err(ProtoError::UnknownStreamType { kind: other }.into()),
        }
    }

    /// Whether this build can actually serve the stream type.
    pub const fn is_implemented_here(self) -> bool {
        matches!(self, Self::Control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn known_types_roundtrip() {
        for byte in [0x01u8, 0x02, 0x03, 0x04] {
            assert_eq!(StreamType::from_byte(byte).unwrap().as_byte(), byte);
        }
    }

    #[test]
    fn unknown_type_is_rejected() {
        for byte in [0x00u8, 0x05, 0x7f, 0xff] {
            let err = StreamType::from_byte(byte).unwrap_err();
            assert!(matches!(
                err,
                Error::Proto(ProtoError::UnknownStreamType { .. })
            ));
        }
    }

    #[test]
    fn only_control_is_implemented() {
        assert!(StreamType::Control.is_implemented_here());
        assert!(!StreamType::Pty.is_implemented_here());
        assert!(!StreamType::XferCtrl.is_implemented_here());
        assert!(!StreamType::XferData.is_implemented_here());
    }
}