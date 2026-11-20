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
        // Rejection sampling over a small space risks long loops when almost every
        // value is taken, so pick from the complement directly.
        //
        // Only in-range values matter: a caller passing `0` or `1000` should not
        // shrink the free set by a value that was never selectable anyway.
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
        let free = span.checked_sub(taken_sorted.len())?;
        if free == 0 {
            return None;
        }
        // `pick` is an index into the complement — the free values in ascending
        // order — not a raw nameplate. Starting that far above `NAMEPLATE_MIN`
        // and shifting up once per taken value at or below the position maps the
        // index onto the nameplate it names. Walking `taken` and decrementing a
        // counter instead would leave the tail of the range unreachable, and
        // with an empty `taken` it would return `NAMEPLATE_MIN` every time.
        let pick = rng.random_range(0..free) as u16;
        let mut candidate = NAMEPLATE_MIN + pick;
        for bound in taken_sorted {
            if bound > candidate {
                break;
            }
            candidate += 1;
        }
        // `candidate` is a free value by construction, so this only fails if the
        // loop above is ever changed to overshoot the range.
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
        assert_eq!(
            "7".parse::<Nameplate>().unwrap(),
            Nameplate::new(7).unwrap()
        );
        assert_eq!("".parse::<Nameplate>(), Err(CodeError::Shape));
        assert_eq!(
            "7a".parse::<Nameplate>(),
            Err(CodeError::NameplateNotNumeric)
        );
        assert_eq!(
            "-7".parse::<Nameplate>(),
            Err(CodeError::NameplateNotNumeric)
        );
        assert_eq!(
            "1000".parse::<Nameplate>(),
            Err(CodeError::NameplateOutOfRange)
        );
        assert_eq!(
            "99999".parse::<Nameplate>(),
            Err(CodeError::NameplateOutOfRange)
        );
    }

    /// The digit cap is a *count*, not a numeric bound: `parse::<u16>` would accept
    /// `00007` as `7`, so a five-character nameplate has to be rejected on its
    /// length before the numeric range check ever runs. Writing the guard as
    /// `s.len() == 4` passes every other case in this module and still lets
    /// `00007` through — which is exactly the mutant cargo-mutants found.
    #[test]
    fn rejects_over_long_digit_strings_even_when_the_value_fits() {
        assert_eq!(
            "00007".parse::<Nameplate>(),
            Err(CodeError::NameplateOutOfRange),
            "a five-digit string is over the cap even though it parses as 7"
        );
        assert_eq!(
            "0001".parse::<Nameplate>(),
            Ok(Nameplate::new(1).unwrap()),
            "four digits are still allowed, so the cap is 4 and not 3"
        );
        assert_eq!(
            "9999".parse::<Nameplate>(),
            Err(CodeError::NameplateOutOfRange),
            "four digits can still be out of range"
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

    /// `pair` calls this with an empty `taken`, so the empty case is the *normal*
    /// path, not an edge case. It must not collapse to the first nameplate: with
    /// every host on the LAN advertising the same nameplate a guest cannot tell
    /// which mDNS record is the live one, and a stale record sends it to a dead
    /// port.
    #[test]
    fn random_with_nothing_taken_spreads_over_the_whole_range() {
        let mut rng = StdRng::seed_from_u64(13);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let plate = Nameplate::random_avoiding(&[], &mut rng).unwrap().get();
            assert!((NAMEPLATE_MIN..=NAMEPLATE_MAX).contains(&plate));
            seen.insert(plate);
        }
        assert!(
            seen.len() > 100,
            "an empty `taken` must still pick widely, got {} distinct values",
            seen.len()
        );
        assert!(
            !(seen.len() == 1 && seen.contains(&NAMEPLATE_MIN)),
            "never vary: every draw was {NAMEPLATE_MIN}"
        );
    }

    /// The pick has to index the *complement* of `taken`, so values far above a
    /// small hole are reachable. Before the fix the walk stopped at the last hole
    /// and never added the remaining offset, which made every draw land in
    /// `1..=6` for `taken = [3, 4, 5]`.
    #[test]
    fn random_reaches_values_above_the_holes() {
        let mut rng = StdRng::seed_from_u64(17);
        let taken = [3u16, 4, 5];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            let plate = Nameplate::random_avoiding(&taken, &mut rng).unwrap().get();
            assert!(!taken.contains(&plate), "picked a taken value: {plate}");
            seen.insert(plate);
        }
        let top = *seen.iter().max().expect("draws");
        assert!(
            top > 500,
            "the draw must reach the upper half of the space, max was {top}"
        );
    }

    /// Every free value must be reachable and none of the taken ones: a mapping,
    /// not merely a valid-looking sample.
    #[test]
    fn random_mapping_hits_every_free_value_exactly_once() {
        let taken = [1u16, 2, 500, 999];
        let free: Vec<u16> = (NAMEPLATE_MIN..=NAMEPLATE_MAX)
            .filter(|n| !taken.contains(n))
            .collect();
        let mut rng = StdRng::seed_from_u64(19);
        let mut seen = std::collections::HashSet::new();
        // 20 000 draws over 995 free values: the chance of missing one is
        // vanishing, and it keeps the test fast.
        for _ in 0..20_000 {
            let plate = Nameplate::random_avoiding(&taken, &mut rng).unwrap().get();
            assert!(!taken.contains(&plate));
            seen.insert(plate);
        }
        assert_eq!(seen.len(), free.len(), "every free value must be reachable");
    }
}
