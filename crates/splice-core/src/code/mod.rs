//! Pairing codes: `<nameplate>-<word1>-<word2>[ -<word3>]` (§5.2).
//!
//! The nameplate is public (it only selects a host on the LAN). The words are the
//! SPAKE2 password and are never sent, never hashed into an identifier, and never
//! logged (I1).

mod nameplate;
mod parse;
mod wordlist;

pub use nameplate::Nameplate;
pub use parse::{parse_code, Code, WordCount};
pub use wordlist::WORDS;

#[cfg(test)]
mod wordlist_tests {
    use super::WORDS;
    use crate::constants::WORDLIST_LEN;
    use std::collections::HashMap;

    #[test]
    fn has_exactly_the_declared_length() {
        assert_eq!(WORDS.len(), WORDLIST_LEN);
    }

    #[test]
    fn all_words_are_lowercase_ascii_letters() {
        for word in WORDS {
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase()),
                "word {word:?} is not lowercase ASCII"
            );
            assert!(
                (3..=8).contains(&word.len()),
                "word {word:?} has an unexpected length"
            );
        }
    }

    #[test]
    fn no_duplicates() {
        let mut seen = HashMap::new();
        for (index, word) in WORDS.iter().enumerate() {
            assert!(
                seen.insert(*word, index).is_none(),
                "duplicate word {word:?}"
            );
        }
    }

    #[test]
    fn four_letter_prefixes_are_unique() {
        // Three-letter words use the whole word as their prefix, so `act` and
        // `action` do not collide: the keys are `act` and `acti`.
        use std::collections::HashMap;
        let mut prefixes: HashMap<&str, &str> = HashMap::new();
        for word in WORDS {
            let prefix = &word[..word.len().min(4)];
            if let Some(other) = prefixes.insert(prefix, word) {
                panic!("prefix {prefix:?} is shared by {other:?} and {word:?}");
            }
        }
    }

    #[test]
    fn sorted_for_binary_search() {
        // `parse` uses `binary_search`; the list must stay sorted.
        assert!(WORDS.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
