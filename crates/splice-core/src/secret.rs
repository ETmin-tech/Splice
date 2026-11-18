//! Secret wrapper (I1, I11).
//!
//! `Secret<T>` zeroizes its contents on drop and refuses to print them. There is
//! exactly one way to read the value: [`Secret::expose_secret`]. Call sites are
//! therefore greppable, which is how the I1 scan test asserts that words never
//! reach a formatter.

use std::fmt;

use zeroize::Zeroize;

/// Wraps secret material: redacted in `Debug`/`Display`, zeroized on drop.
///
/// `T: Zeroize` is required so the wrapper can actually clear memory. Use
/// [`SecretBytes`] for byte buffers, and [`SecretString`] for passphrases.
pub struct Secret<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Zeroize for Secret<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize> Secret<T> {
    /// Wrap an existing value. The caller's binding should be dropped right after.
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// The only accessor. Every call site is audited for I1.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Move the value out, leaving an empty value behind. The container is still
    /// dropped normally, so the emptied shell is zeroized too.
    pub fn into_inner(mut self) -> T
    where
        T: Default,
    {
        std::mem::take(&mut self.inner)
    }
}

impl<T: Zeroize + Clone> Secret<T> {
    /// A second owned copy of the same secret.
    ///
    /// `Secret` deliberately does not implement `Clone`: a silent copy of a secret
    /// is easy to leak. This named method makes each copy a visible decision, and
    /// the copy zeroizes on its own drop like any other.
    pub fn duplicate(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

/// `Secret<String>` is the passphrase type used by the code/PAKE path.
pub type SecretString = Secret<String>;

/// A byte buffer that clears itself on drop.
pub type SecretBytes = Secret<Vec<u8>>;

impl SecretBytes {
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl SecretString {
    /// Build from a `String` produced by the CSPRNG or the parser.
    pub fn from_string(value: String) -> Self {
        Self::new(value)
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<T: Zeroize> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn debug_and_display_are_redacted() {
        let secret = SecretString::from_string("cobalt-falcon".to_string());
        assert_eq!(format!("{secret:?}"), "[redacted]");
        assert_eq!(format!("{secret}"), "[redacted]");
        let nested = format!("{:?}", vec![secret]);
        assert_eq!(nested, "[[redacted]]");
    }

    /// I11: the buffered bytes are cleared when the secret is dropped.
    #[test]
    fn drop_zeroizes_the_backing_buffer() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);

        struct Recording(Arc<Mutex<Vec<u8>>>);
        impl Zeroize for Recording {
            fn zeroize(&mut self) {
                let mut buf = self.0.lock().unwrap();
                buf.iter_mut().for_each(|b| *b = 0);
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let buffer = Arc::new(Mutex::new(b"cobalt-falcon".to_vec()));
        {
            let secret = Secret::new(Recording(Arc::clone(&buffer)));
            assert_eq!(secret.expose_secret().0.lock().unwrap().len(), 13);
        }
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        assert!(
            buffer.lock().unwrap().iter().all(|b| *b == 0),
            "buffer must be zeroed after drop"
        );
    }

    #[test]
    fn into_inner_moves_the_value_out() {
        let secret = SecretString::from_string("7-cobalt-falcon".to_string());
        assert_eq!(secret.into_inner(), "7-cobalt-falcon");
    }
}
