//! Nameplate: the public, non-secret part of a code (§5.2).
//!
//! A nameplate only selects which host on the LAN a guest should talk to. It is
//! advertised in mDNS in the clear and is worthless on its own. The range is small
//! on purpose: the user may have to say it out loud, and a conflict check over
//! mDNS is cheap only when the space is small.

use std::fmt;
use std::str::FromStr;

use rand::Rng;

use crate::error::CodeError;

/// Smallest valid nameplate. `0` is reserved so a missing value is obvious.
pub const NAMEPLATE_MIN: u16 = 1;
/// Largest valid nameplate. 999 keeps every code three characters wide at most.
pub const NAMEPLATE_MAX: u16 = 999;

/// A public host selector, `1..=999`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nameplate(u16);

impl Nameplate {
    /// Construct from a number, rejecting out-of-range values.
    pub fn new(value: u16) -> Result<Self, CodeError> {
        if (NAMEPLATE_MIN..=NAMEPLATE_MAX).contains(&value) {
            Ok(Self(value))
        } else {
            Err(CodeError::NameplateOutOfRange)
        }
    }

    pub fn get(self) -> u16 {
        self.0
    }

    /// Pick a random nameplate that is not in `taken`.
    ///
    /// Returns `None` when every nameplate in range is taken, which on a real LAN
    /// is impossible but keeps the caller honest instead of looping forever.
    pub fn random_avoiding<R: Rng + ?Sized>(taken: &[u16], rng: &mut R) -> Option<Self> {
        let span = (NAMEPLATE_MAX - NAMEPLATE_MIN + 1) as usize;
        if taken.len() >= span {
            return None;
        }
        // Rejection sampling over a small space risks long loops when almost every
        // value is taken, so pick from the complement directly.
        let taken_sorted: Vec<u16> = {
            let mut v: Vec<u16> = taken
                .iter()
                .copied()
                .filter(|n| (NAMEPLATE_MIN..=NAMEPLATE_MAX).contains(n))
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let free = span - taken_sorted.len();
        let mut pick = rng.random_range(0..free);
        let mut candidate = NAMEPLATE_MIN;
        for bound in taken_sorted {
            if candidate < bound {
                if pick == 0 {
                    break;
                }
                pick -= 1;
            }
            candidate = bound + 1;
        }
        Self::new(candidate).ok()
    }
}

impl fmt::Display for Nameplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Nameplate {
    type Err = CodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(CodeError::Shape);
        }
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CodeError::NameplateNotNumeric);
        }
        // Guard against a huge digit string before `parse` rejects it anyway.
        if s.len() > 4 {
            return Err(CodeError::NameplateOutOfRange);
        }
        let value: u16 = s.parse().map_err(|_| CodeError::NameplateOutOfRange)?;
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn range_is_enforced() {
        assert!(Nameplate::new(0).is_err());
        assert!(Nameplate::new(1).is_ok());
        assert!(Nameplate::new(999).is_ok());
        assert!(Nameplate::new(1000).is_err());
    }

    #[test]
    fn parses_only_digits() {
        assert_eq!("42".parse::<Nameplate>().unwrap().get(), 42);
        assert_eq!("7".parse::<Nameplate>().unwrap(), Nameplate::new(7).unwrap());
        assert_eq!("".parse::<Nameplate>(), Err(CodeError::Shape));
        assert_eq!("7a".parse::<Nameplate>(), Err(CodeError::NameplateNotNumeric));
        assert_eq!("-7".parse::<Nameplate>(), Err(CodeError::NameplateNotNumeric));
        assert_eq!("1000".parse::<Nameplate>(), Err(CodeError::NameplateOutOfRange));
        assert_eq!(
            "99999".parse::<Nameplate>(),
            Err(CodeError::NameplateOutOfRange)
        );
    }

    #[test]
    fn random_avoids_taken_values() {
        let mut rng = StdRng::seed_from_u64(7);
        for _ in 0..200 {
            let plate = Nameplate::random_avoiding(&[3, 4, 5], &mut rng).unwrap();
            assert!(![3u16, 4, 5].contains(&plate.get()));
            assert!((NAMEPLATE_MIN..=NAMEPLATE_MAX).contains(&plate.get()));
        }
    }

    #[test]
    fn random_can_exhaust_the_space() {
        let mut rng = StdRng::seed_from_u64(9);
        let everything: Vec<u16> = (NAMEPLATE_MIN..=NAMEPLATE_MAX).collect();
        assert_eq!(Nameplate::random_avoiding(&everything, &mut rng), None);
    }

    #[test]
    fn random_covers_the_complement() {
        // Excluding 1..=998 leaves exactly 999.
        let mut rng = StdRng::seed_from_u64(11);
        let taken: Vec<u16> = (NAMEPLATE_MIN..NAMEPLATE_MAX).collect();
        for _ in 0..20 {
            assert_eq!(
                Nameplate::random_avoiding(&taken, &mut rng).unwrap().get(),
                999
            );
        }
    }
}