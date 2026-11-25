use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CipherPassError, Result};

const BIO_SLOT_MAGIC_V1: &[u8; 8] = b"CPBIO001";
const BIO_SLOT_MAGIC_V2: &[u8; 8] = b"CPBIO002";
const BIO_KDF_DOMAIN_V1: &[u8] = b"CipherPass-Biometric-Vault-Keyslot-v1";
const BIO_KDF_DOMAIN_V2: &[u8] = b"CipherPass-Biometric-Vault-Keyslot-v2";

/// Decrypted credentials recovered from a biometric-bound keyslot (zeroized on drop).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BiometricVaultCredentials {
    pub master_password: Option<String>,
    pub keyfile_path: Option<String>,
}

impl std::fmt::Debug for BiometricVaultCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BiometricVaultCredentials")
            .field("master_password", &self.master_password.as_ref().map(|_| "[REDACTED]"))
            .field("keyfile_path", &self.keyfile_path)
            .finish()
    }
}

/// Compute a stable hex identifier for a vault path (used as filename & AAD binding).
pub fn vault_slot_id(canonical_vault_path: &str) -> String {
    let digest = Sha3_512::digest(canonical_vault_path.as_bytes());
    hex::encode(&digest[..16])
}

fn derive_slot_key_v1(
    device_secret: &[u8; 32],
    vault_id: &str,
    nonce: &[u8; 12],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_512::new();
    h.update(BIO_KDF_DOMAIN_V1);
    h.update(device_secret);
    h.update(vault_id.as_bytes());
    h.update(nonce);
    let mut digest = Zeroizing::new([0u8; 64]);
    digest.copy_from_slice(&h.finalize());
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    key
}

fn derive_slot_key_v2(
    device_secret: &[u8; 32],
    vault_id: &str,
    nonce: &[u8; 12],
) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_512::new();
    h.update(BIO_KDF_DOMAIN_V2);
    h.update(device_secret);
    h.update((vault_id.len() as u64).to_le_bytes());
    h.update(vault_id.as_bytes());
    h.update(nonce);
    let mut digest = Zeroizing::new([0u8; 64]);
    digest.copy_from_slice(&h.finalize());
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    key
}

/// Seal a vault's master credentials using ChaCha20-Poly1305 bound to the device/slot secret and vault ID.
pub fn seal_biometric_slot(
    creds: &BiometricVaultCredentials,
    device_secret: &[u8; 32],
    vault_id: &str,
) -> Result<Vec<u8>> {
    if vault_id.is_empty() || vault_id.len() > 256 {
        return Err(CipherPassError::CryptoError(
            "Invalid biometric slot vault_id".into(),
        ));
    }

    let plaintext = Zeroizing::new(
        serde_json::to_vec(creds)
            .map_err(|e| CipherPassError::CryptoError(format!("Biometric slot serialize: {e}")))?,
    );

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_slot_key_v2(device_secret, vault_id, &nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());

    let mut aad = Vec::with_capacity(8 + 12 + 8 + vault_id.len());
    aad.extend_from_slice(BIO_SLOT_MAGIC_V2);
    aad.extend_from_slice(&nonce_bytes);
    aad.extend_from_slice(&(vault_id.len() as u64).to_le_bytes());
    aad.extend_from_slice(vault_id.as_bytes());

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| CipherPassError::CryptoError("Biometric slot encryption failed".into()))?;

    let mut out = Vec::with_capacity(8 + 12 + ciphertext.len());
    out.extend_from_slice(BIO_SLOT_MAGIC_V2);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal a biometric-bound vault keyslot back into zeroizing master credentials.
pub fn unseal_biometric_slot(
    slot_bytes: &[u8],
    device_secret: &[u8; 32],
    vault_id: &str,
) -> Result<BiometricVaultCredentials> {
    if vault_id.is_empty() || vault_id.len() > 256 {
        return Err(CipherPassError::CryptoError(
            "Invalid biometric slot vault_id".into(),
        ));
    }
    if slot_bytes.len() < 8 + 12 + 16 {
        return Err(CipherPassError::MalformedFormat(
            "Truncated biometric vault keyslot".into(),
        ));
    }
    let magic = &slot_bytes[..8];
    let is_v2 = if magic == BIO_SLOT_MAGIC_V2 {
        true
    } else if magic == BIO_SLOT_MAGIC_V1 {
        false
    } else {
        return Err(CipherPassError::MalformedFormat(
            "Invalid biometric vault keyslot header".into(),
        ));
    };

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&slot_bytes[8..20]);
    let ciphertext = &slot_bytes[20..];

    let (key, aad) = if is_v2 {
        let key = derive_slot_key_v2(device_secret, vault_id, &nonce_bytes);
        let mut aad = Vec::with_capacity(8 + 12 + 8 + vault_id.len());
        aad.extend_from_slice(BIO_SLOT_MAGIC_V2);
        aad.extend_from_slice(&nonce_bytes);
        aad.extend_from_slice(&(vault_id.len() as u64).to_le_bytes());
        aad.extend_from_slice(vault_id.as_bytes());
        (key, aad)
    } else {
        let key = derive_slot_key_v1(device_secret, vault_id, &nonce_bytes);
        let mut aad = Vec::with_capacity(8 + 12 + vault_id.len());
        aad.extend_from_slice(BIO_SLOT_MAGIC_V1);
        aad.extend_from_slice(&nonce_bytes);
        aad.extend_from_slice(vault_id.as_bytes());
        (key, aad)
    };

    let cipher = ChaCha20Poly1305::new(key.as_slice().into());

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                CipherPassError::CryptoError(
                    "Biometric keyslot authentication failed (tampered or mismatched vault)".into(),
                )
            })?,
    );

    serde_json::from_slice(plaintext.as_slice())
        .map_err(|e| CipherPassError::CryptoError(format!("Biometric slot deserialize: {e}")))
}
