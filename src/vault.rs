use secrecy::Secret;

/// Encrypts and decrypts the `Ed25519::Keypair` .
pub struct EncryptedVault {
    pub(crate) secret: Secret<Vec<u8>>,
    pub(crate) nonce: Secret<[u8; 24]>,
}

#[cfg(feature = "dangerous_debug")]
use secrecy::ExposeSecret;
#[cfg(feature = "dangerous_debug")]
impl EncryptedVault {
    /// Useful only for testing, don't use in production.
    pub fn dangerous_debug_hashed(&self) {
        println!(
            "EncryptedVault {{
            secret: {:?},
            nonce: {:?},
        }}",
            blake3::hash(self.secret.expose_secret()).to_hex(),
            blake3::hash(self.nonce.expose_secret()).to_hex(),
        );
    }

    /// Useful only for testing, don't use in production.
    pub fn dangerous_debug(&self) {
        println!(
            "EncryptedVault {{
            secret: {:?},
            nonce: {:?},
        }}",
            self.secret.expose_secret(),
            self.nonce.expose_secret(),
        );
    }
}
