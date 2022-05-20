use crate::{MemVaultError, MemVaultResult};
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use secrecy::DebugSecret;
use zeroize::Zeroize;

/// Stores an `Ed255519` Keypair in memory ensuring it is filled with
/// zeros whenever it is dropped.
/// This crate ensures both the public key and secret key are wiped from a devices
/// memory.
pub struct Ed25519Vault(pub(crate) Keypair);

impl Ed25519Vault {
    /// Take ownership of a Ed25519 Keypair and move it to
    /// `Ed25519Vault` that ensures memory is wiped on drop.
    pub fn new(keypair: Keypair) -> Ed25519Vault {
        Ed25519Vault(keypair)
    }

    /// Generates a unique `ed25519_dalek::Keypair` and moves it
    /// to the `Ed25519Vault` to ensure it is securely wiped from memory
    pub fn new_unique() -> MemVaultResult<Ed25519Vault> {
        use rand::rngs::OsRng;

        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        Ok(Ed25519Vault(keypair))
    }

    /// Takes an existing `ed25519_dalek::Keypair` bytes and transforms them into an `Ed25519Vault` struct.
    pub fn from_bytes(input_bytes: &[u8]) -> MemVaultResult<Ed25519Vault> {
        match Keypair::from_bytes(input_bytes) {
            Ok(keypair) => Ok(Ed25519Vault(keypair)),
            Err(_) => return Err(MemVaultError::InvalidBytesForKeyPair),
        }
    }

    /// Attempts to sign a message using the decrypted `ed25519_dalek::Keypair`
    pub fn try_sign(&self, message: &[u8]) -> MemVaultResult<Signature> {
        match self.0.try_sign(message) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(MemVaultError::SigningError),
        }
    }

    /// Reveal the `ed25519::PublicKey` from the decrypted Keypair
    pub fn public_key(&self) -> ed25519_dalek::PublicKey {
        self.0.public
    }

    /// Reveal the `ed25519_dalek::Keypair` from the decrypted Keypair.
    /// This is dangerous and should only be used when exporting a
    /// `ed25519_dalek::Keypair` bytes from the wallet.
    pub fn dangerous_export(&self) -> [u8; 64] {
        self.0.to_bytes()
    }

    /// Enables generation of a `Base58` string of the public key
    #[cfg(feature = "satoshi_mode")]
    pub fn base58_public_key(&self) -> String {
        bs58::encode(&self.0.public.to_bytes()).into_string()
    }
}

impl Zeroize for Ed25519Vault {
    fn zeroize(&mut self) {
        *self = Ed25519Vault(Keypair {
            secret: SecretKey::from_bytes(&[0_u8; 32]).unwrap(), //Never fails, hence unwrap()
            public: PublicKey::from_bytes(&[0_u8; 32]).unwrap(), //Never fails, hence unwrap()
        });
    }
}

impl DebugSecret for Ed25519Vault {
    fn debug_secret(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Ed25519Vault(Keypair)").finish()
    }
}

impl core::fmt::Debug for Ed25519Vault {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ed25519Vault(Keypair)").finish()
    }
}
