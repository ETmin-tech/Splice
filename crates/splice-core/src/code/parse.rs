//! Parsing, formatting and generation of pairing codes (§5.2).
//!
//! Shape: `<nameplate>-<word1>-<word2>[ -<word3>]`, e.g. `7-torch-crystal`.
//!
//! The parser is strict on purpose. A lenient parser turns a typo into a wrong
//! password, which the host counts as a failed attempt (I3), so a user with a
//! sticky keyboard could burn a code for free. Everything that is not exactly a
//! valid code is rejected with a specific error.
//!
//! The words are secret. [`Code`] redacts them in `Debug`, and the only way to get
//! them out is [`Code::password`] (a zeroizing `SecretString`) or
//! [`Code::reveal_for_user`], which exists solely for the single terminal line that
//! tells the user what to type on the other machine (I1).

use std::fmt;

use rand::Rng;

use crate::code::nameplate::Nameplate;
use crate::code::wordlist::WORDS;
use crate::error::CodeError;
use crate::secret::SecretString;

/// How many secret words a code carries. 2 words = 22 bits, 3 words = 33 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WordCount {
    #[default]
    Two,
    Three,
}

impl WordCount {
    pub fn count(self) -> usize {
        match self {
            Self::Two => 2,
            Self::Three => 3,
        }
    }

    /// Entropy of the word part alone, in bits.
    pub fn entropy_bits(self) -> u32 {
        match self {
            Self::Two => 22,
            Self::Three => 33,
        }
    }

    pub fn from_count(count: usize) -> Result<Self, CodeError> {
        match count {
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            _ => Err(CodeError::WordCountOutOfRange),
        }
    }
}

/// A parsed or generated code.
#[derive(Clone, PartialEq, Eq)]
pub struct Code {
    nameplate: Nameplate,
    words: [&'static str; 3],
    count: WordCount,
}

impl Code {
    /// Build from already-validated parts.
    fn from_parts(nameplate: Nameplate, words: &[&'static str]) -> Result<Self, CodeError> {
        let count = WordCount::from_count(words.len())?;
        let mut buffer = ["", "", ""];
        buffer[..words.len()].copy_from_slice(words);
        Ok(Self {
            nameplate,
            words: buffer,
            count,
        })
    }

    /// Generate a fresh code from the given CSPRNG.
    ///
    /// The caller passes the RNG so tests can be deterministic; production code
    /// passes `rand::rng()` (the OS-seeded thread generator).
    pub fn generate<R: Rng + ?Sized>(
        rng: &mut R,
        count: WordCount,
        nameplate: Nameplate,
    ) -> Result<Self, CodeError> {
        let mut words = ["", "", ""];
        for slot in words.iter_mut().take(count.count()) {
            let index = rng.random_range(0..WORDS.len());
            *slot = WORDS[index];
        }
        Self::from_parts(nameplate, &words[..count.count()])
    }

    pub fn nameplate(&self) -> Nameplate {
        self.nameplate
    }

    pub fn word_count(&self) -> WordCount {
        self.count
    }

    /// The SPAKE2 password: lowercase words joined by `-` (§5.4 step 5).
    ///
    /// Zeroized when dropped. Never send this over the wire, never log it.
    pub fn password(&self) -> SecretString {
        SecretString::from_string(self.words[..self.count.count()].join("-"))
    }

    /// Full code for the one terminal line that is shown to the user.
    ///
    /// This is the only non-secret-typed way to obtain the words, and it exists so
    /// that the "give this to the other machine" output is a single greppable call
    /// site. Do not use it for logging.
    pub fn reveal_for_user(&self) -> String {
        format!("{}-{}", self.nameplate, self.password().expose_secret())
    }

    /// The code with the words masked, for logs and error messages.
    pub fn masked(&self) -> String {
        format!("{}-***", self.nameplate)
    }

    /// Parse user input. Case-insensitive, surrounding space ignored.
    pub fn parse(input: &str) -> Result<Self, CodeError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(CodeError::Empty);
        }
        // A code is at most about 40 characters; anything much longer is junk and
        // is rejected before any allocation-heavy work.
        if trimmed.len() > 64 {
            return Err(CodeError::TooLong);
        }

        let lowered = trimmed.to_ascii_lowercase();
        if !lowered
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(CodeError::InvalidCharacter);
        }

        let parts: Vec<&str> = lowered.split('-').collect();
        // An empty part means `--`, a leading `-`, or a trailing `-`.
        if parts.iter().any(|part| part.is_empty()) {
            return Err(CodeError::Shape);
        }
        if parts.len() < 3 || parts.len() > 4 {
            return Err(CodeError::Shape);
        }

        let nameplate: Nameplate = parts[0].parse()?;
        let mut words: [&'static str; 3] = ["", "", ""];
        for (index, part) in parts[1..].iter().enumerate() {
            words[index] = lookup_word(part)?;
        }
        Self::from_parts(nameplate, &words[..parts.len() - 1])
    }
}

/// Binary search the sorted word list. Returns the `'static` entry, not the input,
/// so a `Code` never owns user-supplied bytes.
fn lookup_word(word: &str) -> Result<&'static str, CodeError> {
    if word.len() < 3 {
        return Err(CodeError::UnknownWord);
    }
    WORDS
        .binary_search(&word)
        .map(|index| WORDS[index])
        .map_err(|_| CodeError::UnknownWord)
}

/// Convenience wrapper for the fuzz target and the CLI: never panics on any input.
pub fn parse_code(input: &str) -> Result<Code, CodeError> {
    Code::parse(input)
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the words; `masked` is the safe textual form.
        f.debug_struct("Code")
            .field("nameplate", &self.nameplate)
            .field("words", &"[redacted]")
            .field("count", &self.count)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn plate() -> Nameplate {
        Nameplate::new(7).unwrap()
    }

    #[test]
    fn parses_a_three_part_code() {
        let code = Code::parse("7-torch-crystal").unwrap();
        assert_eq!(code.nameplate().get(), 7);
        assert_eq!(code.word_count(), WordCount::Two);
        assert_eq!(code.password().expose_secret(), "torch-crystal");
    }

    #[test]
    fn parses_a_four_part_code() {
        let code = Code::parse("12-torch-crystal-zebra").unwrap();
        assert_eq!(code.word_count(), WordCount::Three);
        assert_eq!(code.password().expose_secret(), "torch-crystal-zebra");
    }

    #[test]
    fn parsing_is_case_insensitive_and_trims() {
        let code = Code::parse("  7-TORCH-Crystal  ").unwrap();
        assert_eq!(code.password().expose_secret(), "torch-crystal");
    }

    #[test]
    fn rejects_bad_input_with_specific_errors() {
        assert_eq!(Code::parse("").unwrap_err(), CodeError::Empty);
        assert_eq!(Code::parse("   ").unwrap_err(), CodeError::Empty);
        assert_eq!(Code::parse("7torchcrystal").unwrap_err(), CodeError::Shape);
        assert_eq!(Code::parse("7-torch").unwrap_err(), CodeError::Shape);
        assert_eq!(
            Code::parse("7-torch-crystal-extra-word").unwrap_err(),
            CodeError::Shape
        );
        assert_eq!(Code::parse("-torch-crystal").unwrap_err(), CodeError::Shape);
        assert_eq!(Code::parse("7-torch-").unwrap_err(), CodeError::Shape);
        assert_eq!(Code::parse("7--crystal").unwrap_err(), CodeError::Shape);
        assert_eq!(
            Code::parse("x-torch-crystal").unwrap_err(),
            CodeError::NameplateNotNumeric
        );
        assert_eq!(
            Code::parse("7-torch-nonsense").unwrap_err(),
            CodeError::UnknownWord
        );
        assert_eq!(
            Code::parse("7 cobal t crystal").unwrap_err(),
            CodeError::InvalidCharacter
        );
        assert_eq!(
            Code::parse("7-torch-crys_tal").unwrap_err(),
            CodeError::InvalidCharacter
        );
        assert_eq!(Code::parse(&"a".repeat(65)).unwrap_err(), CodeError::TooLong);
    }

    #[test]
    fn rejects_zero_nameplate() {
        assert_eq!(
            Code::parse("0-torch-crystal").unwrap_err(),
            CodeError::NameplateOutOfRange
        );
    }

    #[test]
    fn generate_masks_and_reveals_consistently() {
        let mut rng = StdRng::seed_from_u64(42);
        let code = Code::generate(&mut rng, WordCount::Two, plate()).unwrap();
        let revealed = code.reveal_for_user();
        assert!(revealed.starts_with("7-"));
        assert_eq!(revealed.split('-').count(), 3);
        assert_eq!(Code::parse(&revealed).unwrap(), code);
        assert_eq!(code.masked(), "7-***");
    }

    #[test]
    fn generate_three_words() {
        let mut rng = StdRng::seed_from_u64(1);
        let code = Code::generate(&mut rng, WordCount::Three, plate()).unwrap();
        assert_eq!(code.reveal_for_user().split('-').count(), 4);
        assert_eq!(code.word_count().entropy_bits(), 33);
    }

    #[test]
    fn debug_does_not_contain_the_words() {
        let code = Code::parse("7-torch-crystal").unwrap();
        let text = format!("{code:?}");
        assert!(!text.contains("torch"));
        assert!(!text.contains("crystal"));
        assert!(text.contains("[redacted]"));
    }

    #[test]
    fn entropy_bits_match_the_documented_values() {
        assert_eq!(WordCount::Two.entropy_bits(), 22);
        assert_eq!(WordCount::Three.entropy_bits(), 33);
        assert_eq!(WordCount::from_count(2).unwrap(), WordCount::Two);
        assert_eq!(WordCount::from_count(3).unwrap(), WordCount::Three);
        assert_eq!(WordCount::from_count(4), Err(CodeError::WordCountOutOfRange));
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        fn arb_code() -> impl Strategy<Value = Code> {
            (1u16..=999, 0usize..2048, 0usize..2048, 0usize..2048, any::<bool>()).prop_map(
                |(plate, a, b, c, three)| {
                    let nameplate = Nameplate::new(plate).unwrap();
                    let words: &[&'static str] = if three {
                        &[WORDS[a], WORDS[b], WORDS[c]]
                    } else {
                        &[WORDS[a], WORDS[b]]
                    };
                    Code::from_parts(nameplate, words).unwrap()
                },
            )
        }

        proptest! {
            /// `parse(format(x)) == x` for every well-formed code.
            #[test]
            fn roundtrip(code in arb_code()) {
                let text = code.reveal_for_user();
                let parsed = Code::parse(&text).unwrap();
                prop_assert_eq!(parsed, code);
            }

            /// Arbitrary strings must never panic and must never yield a password
            /// longer than the maximum code.
            #[test]
            fn no_panic_on_arbitrary_input(input in ".{0,200}") {
                let result = Code::parse(&input);
                if let Ok(code) = result {
                    prop_assert!(code.password().expose_secret().len() <= 25);
                }
            }
        }
    }
}