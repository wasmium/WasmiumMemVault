use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use secrecy::DebugSecret;
use wasmium_errors::{WasmiumError, WasmiumResult};
use zeroize::Zeroize;

pub struct ProtectedEd25519KeyPair(pub(crate) Keypair);

impl ProtectedEd25519KeyPair {
    pub fn new(keypair: Keypair) -> ProtectedEd25519KeyPair {
        ProtectedEd25519KeyPair(keypair)
    }

    pub fn from_bytes(input_bytes: &[u8]) -> WasmiumResult<ProtectedEd25519KeyPair> {
        match Keypair::from_bytes(input_bytes) {
            Ok(keypair) => Ok(ProtectedEd25519KeyPair::new(keypair)),
            Err(_) => return Err(WasmiumError::InvalidBytesForKeyPair),
        }
    }

    pub fn try_sign(&self, message: &[u8]) -> WasmiumResult<Signature> {
        match self.0.try_sign(message) {
            Ok(signature) => Ok(signature),
            Err(_) => Err(WasmiumError::SigningError),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.public.to_bytes()
    }
}

impl Zeroize for ProtectedEd25519KeyPair {
    fn zeroize(&mut self) {
        *self = ProtectedEd25519KeyPair(Keypair {
            secret: SecretKey::from_bytes(&[0_u8; 32]).unwrap(), //Never fails, hence unwrap()
            public: PublicKey::from_bytes(&[0_u8; 32]).unwrap(), //Never fails, hence unwrap()
        });
    }
}

impl DebugSecret for ProtectedEd25519KeyPair {
    fn debug_secret(f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("ProtectedEd25519KeyPair(Keypair)").finish()
    }
}

impl core::fmt::Debug for ProtectedEd25519KeyPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ProtectedEd25519KeyPair(Keypair)").finish()
    }
}
