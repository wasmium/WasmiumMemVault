//! ### `wasmium-securemem`
//! This crate is used to securely store in memory the `Ed25519 Keypair` of a Wasmium wallet.
//! The keys are encrypted when they are not being used and decrypted when they need to be used
//! to sign some bytes of any length.
//!
//! This is inspired by [sequoia-openpgp's Encrypted data structure](https://docs.rs/sequoia-openpgp/).
//! #### An excerpt from their documentation:
//!
//!
//! This type encrypts sensitive data, such as secret keys, in memory
//! while they are unused, and decrypts them on demand.  This protects
//! against cross-protection-boundary readout via microarchitectural
//! flaws like Spectre or Meltdown, via attacks on physical layout
//! like Rowbleed, and even via coldboot attacks.
//!
//! The key insight is that these kinds of attacks are imperfect,
//! i.e. the recovered data contains bitflips, or the attack only
//! provides a probability for any given bit.  Applied to
//! cryptographic keys, these kind of imperfect attacks are enough to
//! recover the actual key.
//!
//! This implementation on the other hand, derives a sealing key from
//! a large area of memory, the "pre-key", using a key derivation
//! function.  Now, any single bitflip in the readout of the pre-key
//! will avalanche through all the bits in the sealing key, rendering
//! it unusable with no indication of where the error occurred.
//!
//! This kind of protection was pioneered by OpenSSH.  The commit
//! adding it can be found
//! [here](https://marc.info/?l=openbsd-cvs&m=156109087822676).
//!
//!
mod prekey_vault;
pub use prekey_vault::*;
mod vault;
pub use vault::*;
mod memvault;
pub use memvault::*;
mod protected_keypair;
pub use protected_keypair::*;

#[cfg(test)]
mod correctness_tests {
    use crate::{EncryptedVault, ProtectedEd25519KeyPair};

    #[test]
    fn eq_between_original_and_encrypted() {
        use ed25519_dalek::Keypair;
        use ed25519_dalek::Signature;
        use rand::rngs::OsRng;

        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        use ed25519_dalek::Signer;
        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature: Signature = keypair.sign(message);

        let vault =
            EncryptedVault::encrypt_secret(&mut ProtectedEd25519KeyPair::new(keypair)).unwrap();

        let vault_signed = vault.decrypt_and_sign(message).unwrap();

        assert_eq!(signature, vault_signed);
    }
}
