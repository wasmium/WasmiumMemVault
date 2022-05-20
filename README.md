 ### `Wasmuium-MemVault`
 This crate is used to securely store in memory a `Ed25519 Keypair`.
 The keys are encrypted when they are not being used and decrypted when they need to be used to sign some bytes of any length.

 This is inspired by [sequoia-openpgp's Encrypted data structure](https://docs.rs/sequoia-openpgp/).
 #### An excerpt from their documentation:

 This type encrypts sensitive data, such as secret keys, in memory while they are unused, and decrypts them on demand.  This protects against cross-protection-boundary readout via microarchitectural flaws like Spectre or Meltdown, via attacks on physical layout like Rowbleed, and even via coldboot attacks.

 The key insight is that these kinds of attacks are imperfect,  i.e. the recovered data contains bitflips, or the attack only
 provides a probability for any given bit.  Applied to cryptographic keys, these kind of imperfect attacks are enough to
 recover the actual key.

 This implementation on the other hand, derives a sealing key from a large area of memory, the "pre-key", using a key derivation function.  Now, any single bitflip in the readout of the pre-key will avalanche through all the bits in the sealing key, rendering it unusable with no indication of where the error occurred.

 This kind of protection was pioneered by OpenSSH.  The commit adding it can be found [here](https://marc.info/?l=openbsd-cvs&m=156109087822676).

#### Usage

Create a new `Ed25519Vault`

```rust
use wasmium_memvault::Ed25519Vault;

// Create a unique `Ed25519` Keypair 
let mut ed25519vault = Ed25519Vault::new_unique().unwrap();

// Add an existing `Ed25519` Keypair from bytes
let mut ed25519vault = Ed25519Vault::from_bytes(&keypair_bytes).unwrap();
```

Encrypt the `Ed25519::Keypair`  in memory

```rust
use crate::{Ed25519Vault, EncryptedVault};

// Create a unique `Ed25519` Keypair 
let mut ed25519vault = Ed25519Vault::new_unique().unwrap();

// Call `encrypt_secret()` method on `EncryptedVault` to encrypt.
// This moves the `Ed25519Vault` containing the Keypair
// taking ownership of the `Keypair`
let vault = EncryptedVault::encrypt_secret(&mut ed25519vault).unwrap();

// Sign a message of bytes by calling method `decrypt_and_sign()` on `EncryptedVault`
let vault_sig = vault.decrypt_and_sign(data).unwrap();
println!("The signature of the message is: {:?}", vault_sig)
```

Expose the `ed25519_dalek::PublicKey` in order to share it with other parties who can use the public key to verify a message

```rust
use crate::{Ed25519Vault, EncryptedVault};

let mut ed25519vault = Ed25519Vault::new_unique().unwrap();
let vault = EncryptedVault::encrypt_secret(&mut ed25519vault).unwrap();

// Call method `public_key()?` on `EncryptedVault`
let public_key = vault.public_key()?;
```



#### License
`CCO-1.0` or `Apache-2.0`