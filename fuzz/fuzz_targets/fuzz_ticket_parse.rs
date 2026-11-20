//! Feed arbitrary strings to the ticket parser.
//!
//! A ticket is a string a peer handed us, so it is entirely attacker-controlled:
//! it can be any length, any alphabet, with any number of separators. The parser
//! must reject it without panicking, without allocating on the declared length
//! alone, and without accepting trailing bytes that `postcard` would ignore.
#![no_main]

use libfuzzer_sys::fuzz_target;
use splice_core::discovery::ticket::Ticket;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(ticket) = Ticket::parse(text) else {
        return;
    };

    // A ticket that parses must re-serialise to something that parses back to the
    // same node, addresses and secret: the text form is the only form that
    // crosses the wire, so a mismatch between parse and encode is a bug that
    // would show up as "the ticket you sent does not work".
    let encoded = ticket.encode();
    let reparsed = Ticket::parse(encoded.expose_secret()).expect("a ticket must round-trip");
    assert_eq!(ticket.node(), reparsed.node());
    assert_eq!(ticket.direct(), reparsed.direct());
    assert_eq!(ticket.relay(), reparsed.relay());
    assert_eq!(
        ticket.password_string().expose_secret(),
        reparsed.password_string().expose_secret(),
        "the ticket secret must survive the round trip"
    );
});
