use secrecy::{DebugSecret, Secret};
use zeroize::Zeroize;

pub struct SecureMemVault(pub(crate) blake3::Hash);

impl SecureMemVault {
    pub(crate) fn new(blake3_hash: blake3::Hash) -> Secret<SecureMemVault> {
        Secret::new(SecureMemVault(blake3_hash))
    }
}

impl core::default::Default for SecureMemVault {
    fn default() -> SecureMemVault {
        let array32_of_zeros: [u8; 32] = [0; 32];
        SecureMemVault(blake3::hash(&array32_of_zeros))
    }
}

impl Zeroize for SecureMemVault {
    fn zeroize(&mut self) {
        *self = SecureMemVault::default();
    }
}

impl DebugSecret for SecureMemVault {
    fn debug_secret(f: &mut core::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", "SecureMemVault::<REDACTED_PROTECTED_SECRET>")
    }
}
