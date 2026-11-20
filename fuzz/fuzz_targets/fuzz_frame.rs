//! Feed arbitrary bytes to the frame codec, twice: once as-is, once as the seed
//! of a *valid* frame.
//!
//! Three properties matter and none may panic:
//!   * `decode_header` must reject anything that would make a caller allocate
//!     more than `MAX_FRAME_LEN`, whatever the length field says.
//!   * `decode` must never index past the buffer, and any frame it does accept
//!     must re-encode to a prefix of the input (the codec is not lossy).
//!   * A frame that is well formed on the wire must decode and re-encode
//!     byte-for-byte, body included. Random input almost never produces a known
//!     `type` byte, so the body path is reached by *building* the header from the
//!     input rather than hoping for one.
#![no_main]

use libfuzzer_sys::fuzz_target;
use splice_core::constants::FRAME_HEADER_LEN;
use splice_core::proto::frame::{self, FrameKind};

/// Every wire value `FrameKind::from_byte` accepts, so modulo picks a real one.
const KINDS: [u8; 6] = [0x10, 0x20, 0x21, 0x22, 0x30, 0x7f];

fuzz_target!(|data: &[u8]| {
    let header = frame::decode_header(data);
    if let Ok(header) = header {
        assert!(
            (header.len as usize) <= 1024 * 1024,
            "header length stayed under the hard 1 MiB bound"
        );
    }

    if let Ok((decoded, consumed)) = frame::decode(data) {
        assert!(
            consumed <= data.len(),
            "decode reported consuming more than it was given"
        );
        let reencoded = decoded.encode();
        assert_eq!(
            &reencoded[..],
            &data[..consumed],
            "a decoded frame must re-encode to the bytes it came from"
        );
    }

    // Now the other half: force a header we already know is legal and check that
    // the body travels through unchanged.
    let (Some(&kind_byte), Some(&flag_bits)) = (data.first(), data.get(1)) else {
        return;
    };

    let kind = FrameKind::from_byte(KINDS[usize::from(kind_byte) % KINDS.len()])
        .expect("every entry in KINDS is a real frame type");
    let flags = flag_bits & 0b0000_0001;
    let body = &data[2..];

    let mut wire = Vec::with_capacity(FRAME_HEADER_LEN + body.len());
    wire.push(kind.as_byte());
    wire.push(flags);
    wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
    wire.extend_from_slice(body);

    let (decoded, consumed) = frame::decode(&wire).expect("a frame we built ourselves must decode");
    assert_eq!(consumed, wire.len(), "decode must consume the whole frame");
    assert_eq!(decoded.kind, kind);
    assert_eq!(decoded.flags.as_byte(), flags);
    assert_eq!(decoded.body, body, "the body must survive the round trip");
    assert_eq!(decoded.encode(), wire, "re-encoding must be byte-exact");
});
