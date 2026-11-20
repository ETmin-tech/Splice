//! Feed arbitrary strings to the pairing-code parser.
//!
//! The parser is what a human types off a screen, so it sees whitespace, mixed
//! case, look-alike characters and hostile lengths. It must never panic, and a
//! parse that succeeds must survive a round trip through the two text forms the
//! program itself produces.
#![no_main]

use libfuzzer_sys::fuzz_target;
use splice_core::code::parse_code;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(code) = parse_code(text) else {
        return;
    };

    // `reveal_for_user` is the exact string the terminal prints for the peer to
    // copy; it must parse back to the same value.
    let revealed = code.reveal_for_user();
    let reparsed = parse_code(&revealed).expect("the user-facing form must parse");
    assert_eq!(code.nameplate(), reparsed.nameplate());
    assert_eq!(
        code.password().expose_secret(),
        reparsed.password().expose_secret(),
        "a code must round-trip through its user-facing form"
    );

    // The masked form must never contain the secret, and neither must Debug.
    let secret = code.password().expose_secret().to_string();
    assert!(!code.masked().contains(&secret));
    assert!(
        !format!("{code:?}").contains(&secret),
        "Debug must not print the secret words"
    );
});
