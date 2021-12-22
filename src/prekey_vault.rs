mod prekey_vault {
    use crate::{EncryptedVault, ProtectedEd25519KeyPair, SecureMemVault};
    use chacha20poly1305::{
        aead::{Aead, NewAead},
        Key, XChaCha8Poly1305, XNonce,
    };
    use ed25519_dalek::Signature;
    use nanorand::{ChaCha8, Rng};
    use secrecy::{ExposeSecret, Secret};
    use wasmium_errors::{WasmiumError, WasmiumResult};
    use wasmium_random::WasmiumRandom;
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
        fn sealing_key() -> Secret<SecureMemVault> {
            let mut blake3_hasher = blake3::Hasher::new();
            PREKEY.into_iter().for_each(|page| {
                blake3_hasher.update(&page);
            });

            SecureMemVault::new(blake3_hasher.finalize())
        }

        pub fn encrypt_secret(
            user_secrets: &mut ProtectedEd25519KeyPair,
        ) -> WasmiumResult<EncryptedVault> {
            let sealing_key = EncryptedVault::sealing_key();
            let key = Key::from_slice(sealing_key.expose_secret().0.as_bytes()); // 32-bytes
            let aead = XChaCha8Poly1305::new(key);

            let random_nonce = Secret::new(WasmiumRandom::secure_alphanumeric24()); // Can be public
            let nonce = XNonce::from_slice(random_nonce.expose_secret()); // 24-bytes; unique
            let ciphertext = match aead.encrypt(nonce, &user_secrets.0.to_bytes()[..]) {
                Ok(ciphertext) => Secret::new(ciphertext),
                Err(_) => return Err(WasmiumError::XChaCha8Poly1305EncryptionError),
            };

            user_secrets.zeroize();

            Ok(EncryptedVault {
                secret: ciphertext,
                nonce: random_nonce,
            })
        }

        pub fn decrypt_and_sign(&self, message: &[u8]) -> WasmiumResult<Signature> {
            let sealing_key = EncryptedVault::sealing_key();
            let key = Key::from_slice(sealing_key.expose_secret().0.as_bytes()); // 32-bytes
            let aead = XChaCha8Poly1305::new(key);

            let nonce = XNonce::from_slice(self.nonce.expose_secret()); // 24-bytes; unique
            let plaintext = match aead.decrypt(nonce, self.secret.expose_secret().as_ref()) {
                Ok(plaintext) => Secret::new(plaintext),
                Err(_) => return Err(WasmiumError::XChaCha8Poly1305EncryptionError),
            };

            let keypair = ProtectedEd25519KeyPair::from_bytes(&plaintext.expose_secret())?;

            keypair.try_sign(message)
        }
    }
}
