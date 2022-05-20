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
mod random_key;
pub use random_key::*;
mod protected_keypair;
pub use protected_keypair::*;
mod errors;
pub use errors::*;

#[cfg(test)]
mod correctness_tests {
    use crate::{Ed25519Vault, EncryptedVault};
    use ed25519_dalek::{Keypair, Signer};

    #[test]
    fn eq_between_original_and_encrypted() {
        let data = b"1234567890";

        let mut ed25519vault = Ed25519Vault::new_unique().unwrap();

        let keypair_bytes = ed25519vault.dangerous_export();
        let ed_keypair = Keypair::from_bytes(&keypair_bytes).unwrap();
        let ed_sig = ed_keypair.sign(data);

        let vault = EncryptedVault::encrypt_secret(&mut ed25519vault).unwrap();

        let vault_sig = vault.decrypt_and_sign(data).unwrap();
        assert_eq!(ed_sig, vault_sig);
        assert_eq!(ed_keypair.public, vault.public_key().unwrap());
    }
}
