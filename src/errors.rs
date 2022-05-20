pub type MemVaultResult<T> = Result<T, MemVaultError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemVaultError {
    /// The bytes provided could not be encrypted
    XChaCha8Poly1305EncryptionError,
    /// The encrypted bytes provided could not be decrypted
    XChaCha8Poly1305DecryptionError,
    /// The bytes provided for the `ed25519_dalek::Keypair` are invalid
    InvalidBytesForKeyPair,
    /// The bytes provided for the `ed25519_dalek::PublicKey` are invalid
    InvalidBytesForPublicKey,
    /// The bytes provided for the `ed25519_dalek::SecretKey` are invalid
    InvalidBytesForSecretKey,
    /// Could not sign the message. The actual error is opaque
    /// to prevent side-channel attacks
    SigningError,
    /// The memory occupied by `ed25519_dalek::Keypair` stored in `Ed25519Vault`
    /// could not be wiped
    MemoryCouldNotbeZeroized,
}
