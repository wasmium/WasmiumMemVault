mod prekey_vault {
    use crate::{Ed25519Vault, EncryptedVault, HashedRandomMemKey, MemVaultError, MemVaultResult};
    use chacha20poly1305::{
        aead::{Aead, NewAead},
        Key, XChaCha8Poly1305, XNonce,
    };
    use ed25519_dalek::Signature;
    use nanorand::{BufferedRng, ChaCha8, Rng};
    use secrecy::{ExposeSecret, Secret};
    use zeroize::Zeroize;

    const VAULT_PAGES: usize = 4;
    const EACH_VAULT_PAGE_SIZE: usize = 4096_usize;

    lazy_static::lazy_static! {
        static ref PREKEY: [[u8; EACH_VAULT_PAGE_SIZE]; VAULT_PAGES] = {
            let mut pages = [[0_u8; EACH_VAULT_PAGE_SIZE]; VAULT_PAGES];

            (0..VAULT_PAGES).for_each(|vault_page_index| {
                let mut chacha_rng = ChaCha8::new();
                let mut random_bytes = [0; EACH_VAULT_PAGE_SIZE];
                (0..EACH_VAULT_PAGE_SIZE).for_each(|index| {
                    random_bytes[index] = chacha_rng.generate::<u8>();
                });

                pages[vault_page_index] = random_bytes;
            });

            pages
        };
    }

    impl EncryptedVault {
        fn sealing_key() -> Secret<HashedRandomMemKey> {
            let mut blake3_hasher = blake3::Hasher::new();
            PREKEY.into_iter().for_each(|page| {
                blake3_hasher.update(&page);
            });

            HashedRandomMemKey::new(blake3_hasher.finalize())
        }

        /// Encrypts the `Ed25519_dalek::Keypair` in memory
        pub fn encrypt_secret(user_secrets: &mut Ed25519Vault) -> MemVaultResult<EncryptedVault> {
            let sealing_key = EncryptedVault::sealing_key();
            let key = Key::from_slice(sealing_key.expose_secret().0.as_bytes()); // 32-bytes
            let aead = XChaCha8Poly1305::new(key);

            let mut rand24 = [0u8; 24];
            let mut rng = BufferedRng::new(ChaCha8::new());
            rng.fill(&mut rand24);

            let random_nonce = Secret::new(rand24); // Can be public
            let nonce = XNonce::from_slice(random_nonce.expose_secret()); // 24-bytes; unique
            let ciphertext = match aead.encrypt(nonce, &user_secrets.0.to_bytes()[..]) {
                Ok(ciphertext) => Secret::new(ciphertext),
                Err(_) => return Err(MemVaultError::XChaCha8Poly1305EncryptionError),
            };

            user_secrets.zeroize();

            if user_secrets.dangerous_export() != [0u8; 64] {
                Err(MemVaultError::MemoryCouldNotbeZeroized)
            } else {
                Ok(EncryptedVault {
                    secret: ciphertext,
                    nonce: random_nonce,
                })
            }
        }

        /// Decrypts the `ed25519_dalek::Keypair` and tries to sign a message
        pub fn decrypt_and_sign(&self, message: &[u8]) -> MemVaultResult<Signature> {
            let sealing_key = EncryptedVault::sealing_key();
            let key = Key::from_slice(sealing_key.expose_secret().0.as_bytes()); // 32-bytes
            let aead = XChaCha8Poly1305::new(key);

            let nonce = XNonce::from_slice(self.nonce.expose_secret()); // 24-bytes; unique
            let plaintext = match aead.decrypt(nonce, self.secret.expose_secret().as_ref()) {
                Ok(plaintext) => Secret::new(plaintext),
                Err(_) => return Err(MemVaultError::XChaCha8Poly1305DecryptionError),
            };

            let mut keypair = Ed25519Vault::from_bytes(&plaintext.expose_secret())?;

            let signature = keypair.try_sign(message);
            keypair.zeroize();

            signature
        }

        /// Decrypts the `ed25519_dalek::Keypair` and gets the `ed25519_dalek::PublicKey`
        pub fn public_key(&self) -> MemVaultResult<ed25519_dalek::PublicKey> {
            let sealing_key = EncryptedVault::sealing_key();
            let key = Key::from_slice(sealing_key.expose_secret().0.as_bytes()); // 32-bytes
            let aead = XChaCha8Poly1305::new(key);

            let nonce = XNonce::from_slice(self.nonce.expose_secret()); // 24-bytes; unique
            let plaintext = match aead.decrypt(nonce, self.secret.expose_secret().as_ref()) {
                Ok(plaintext) => Secret::new(plaintext),
                Err(_) => return Err(MemVaultError::XChaCha8Poly1305DecryptionError),
            };

            let mut keypair = Ed25519Vault::from_bytes(&plaintext.expose_secret())?;

            let public_key: ed25519_dalek::PublicKey = keypair.public_key();
            keypair.zeroize();

            Ok(public_key)
        }

        /// Reveal the `ed25519_dalek::Keypair` from the decrypted Keypair.
        /// This is dangerous and should only be used when exporting a
        /// `ed25519_dalek::Keypair` bytes from the wallet.
        pub fn dangerous_export(&self) -> MemVaultResult<Ed25519Vault> {
            let sealing_key = EncryptedVault::sealing_key();
            let key = Key::from_slice(sealing_key.expose_secret().0.as_bytes()); // 32-bytes
            let aead = XChaCha8Poly1305::new(key);

            let nonce = XNonce::from_slice(self.nonce.expose_secret()); // 24-bytes; unique
            let plaintext = match aead.decrypt(nonce, self.secret.expose_secret().as_ref()) {
                Ok(plaintext) => Secret::new(plaintext),
                Err(_) => return Err(MemVaultError::XChaCha8Poly1305DecryptionError),
            };

            Ed25519Vault::from_bytes(&plaintext.expose_secret())
        }
    }
}
