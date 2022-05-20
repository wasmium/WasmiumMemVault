use secrecy::{DebugSecret, Secret};
use zeroize::Zeroize;

/// Stores the secret key from the prekey_vault module in memory
/// filling it with zeros whenever it is dropped.
pub struct HashedRandomMemKey(pub(crate) blake3::Hash);

impl HashedRandomMemKey {
    pub(crate) fn new(blake3_hash: blake3::Hash) -> Secret<HashedRandomMemKey> {
        Secret::new(HashedRandomMemKey(blake3_hash))
    }
}

impl core::default::Default for HashedRandomMemKey {
    fn default() -> HashedRandomMemKey {
        let array32_of_zeros: [u8; 32] = [0; 32];
        HashedRandomMemKey(blake3::hash(&array32_of_zeros))
    }
}

impl Zeroize for HashedRandomMemKey {
    fn zeroize(&mut self) {
        *self = HashedRandomMemKey::default();
    }
}

impl DebugSecret for HashedRandomMemKey {
    fn debug_secret(f: &mut core::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", "HashedRandomMemKey::<REDACTED_PROTECTED_SECRET>")
    }
}
