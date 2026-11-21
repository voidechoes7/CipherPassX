use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use fips203::ml_kem_1024;
use fips203::traits::{Decaps, Encaps, KeyGen, SerDes};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use zeroize::Zeroizing;

use crate::error::{CipherPassError, Result};

const PQ_MAGIC: &[u8; 8] = b"CPQX0001";
const PQ_KDF_DOMAIN: &[u8] = b"CipherPass-FIPS203-ML-KEM-1024-ChaCha20Poly1305-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlKem1024Keypair {
    /// Base64-encoded NIST FIPS 203 ML-KEM-1024 Encapsulation (Public) Key (1568 bytes raw).
    pub public_key_b64: String,
    /// Base64-encoded NIST FIPS 203 ML-KEM-1024 Decapsulation (Secret) Key (3168 bytes raw).
    pub secret_key_b64: String,
    /// Short SHA3-512 fingerprint of the public key for quick visual verification.
    pub fingerprint: String,
}

fn derive_aead_key(shared_secret: &[u8], kem_ct: &[u8], nonce: &[u8; 12]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha3_512::new();
    hasher.update(PQ_KDF_DOMAIN);
    hasher.update(shared_secret);
    hasher.update(kem_ct);
    hasher.update(nonce);
    let mut digest = Zeroizing::new([0u8; 64]);
    digest.copy_from_slice(&hasher.finalize());
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    key
}

/// Generate a fresh NIST FIPS 203 ML-KEM-1024 (NIST Category 5 / 256-bit Post-Quantum) keypair.
pub fn generate_mlkem1024_keypair() -> Result<MlKem1024Keypair> {
    let (ek, dk) = ml_kem_1024::KG::try_keygen_with_rng(&mut OsRng)
        .map_err(|e| CipherPassError::CryptoError(format!("ML-KEM-1024 keygen failed: {e}")))?;

    let ek_bytes = ek.into_bytes();
    let dk_bytes = Zeroizing::new(dk.into_bytes());

    let fp_hash = Sha3_512::digest(ek_bytes);
    let fingerprint = hex::encode_upper(&fp_hash[..8]);

    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(ek_bytes);
    let secret_key_b64 = base64::engine::general_purpose::STANDARD.encode(dk_bytes.as_slice());

    Ok(MlKem1024Keypair {
        public_key_b64,
        secret_key_b64,
        fingerprint,
    })
}

/// Seal raw `.kdbx` bytes inside a NIST FIPS 203 ML-KEM-1024 + ChaCha20-Poly1305 quantum-safe envelope (`.kdbx.pq`).
pub fn pq_seal_bytes(kdbx_bytes: &[u8], public_key_b64: &str) -> Result<Vec<u8>> {
    let ek_vec = base64::engine::general_purpose::STANDARD
        .decode(public_key_b64.trim())
        .map_err(|_| {
            CipherPassError::CryptoError("Invalid Base64 ML-KEM-1024 public key".into())
        })?;
    let ek_arr: [u8; ml_kem_1024::EK_LEN] = ek_vec.try_into().map_err(|_| {
        CipherPassError::CryptoError(format!(
            "ML-KEM-1024 public key must be {} bytes",
            ml_kem_1024::EK_LEN
        ))
    })?;

    let ek = ml_kem_1024::EncapsKey::try_from_bytes(ek_arr).map_err(|e| {
        CipherPassError::CryptoError(format!("Invalid ML-KEM-1024 public key: {e}"))
    })?;

    let (ss, ct) = ek
        .try_encaps_with_rng(&mut OsRng)
        .map_err(|e| CipherPassError::CryptoError(format!("ML-KEM-1024 encaps failed: {e}")))?;

    let ss_bytes = Zeroizing::new(ss.into_bytes());
    let ct_bytes = ct.into_bytes();

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);

    let aead_key = derive_aead_key(ss_bytes.as_slice(), &ct_bytes, &nonce_bytes);
    let cipher = ChaCha20Poly1305::new(aead_key.as_slice().into());

    // Build authenticated header (bound as AAD)
    let mut header = Vec::with_capacity(8 + 2 + ct_bytes.len() + 12);
    header.extend_from_slice(PQ_MAGIC);
    header.extend_from_slice(&(ct_bytes.len() as u16).to_le_bytes());
    header.extend_from_slice(&ct_bytes);
    header.extend_from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: kdbx_bytes,
                aad: &header,
            },
        )
        .map_err(|_| CipherPassError::CryptoError("PQ AEAD encryption failed".into()))?;

    let mut out = Vec::with_capacity(header.len() + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal a `.kdbx.pq` quantum-safe envelope back to standard `.kdbx` bytes using the ML-KEM-1024 secret key.
pub fn pq_unseal_bytes(pq_bytes: &[u8], secret_key_b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    if pq_bytes.len() < 8 + 2 + ml_kem_1024::CT_LEN + 12 + 16 {
        return Err(CipherPassError::MalformedFormat(
            "Truncated .kdbx.pq post-quantum envelope".into(),
        ));
    }
    if &pq_bytes[..8] != PQ_MAGIC {
        return Err(CipherPassError::MalformedFormat(
            "Invalid .kdbx.pq magic signature".into(),
        ));
    }

    let ct_len = u16::from_le_bytes([pq_bytes[8], pq_bytes[9]]) as usize;
    if ct_len != ml_kem_1024::CT_LEN {
        return Err(CipherPassError::MalformedFormat(format!(
            "Unexpected ML-KEM-1024 ciphertext length: {ct_len}"
        )));
    }

    let header_len = 8 + 2 + ct_len + 12;
    let header = &pq_bytes[..header_len];
    let ct_slice = &pq_bytes[10..10 + ct_len];
    let nonce_slice = &pq_bytes[10 + ct_len..header_len];
    let aead_ct = &pq_bytes[header_len..];

    let dk_vec = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(secret_key_b64.trim())
            .map_err(|_| {
                CipherPassError::CryptoError("Invalid Base64 ML-KEM-1024 secret key".into())
            })?,
    );
    let dk_arr: Zeroizing<[u8; ml_kem_1024::DK_LEN]> =
        Zeroizing::new(dk_vec.as_slice().try_into().map_err(|_| {
            CipherPassError::CryptoError(format!(
                "ML-KEM-1024 secret key must be {} bytes",
                ml_kem_1024::DK_LEN
            ))
        })?);

    let dk = ml_kem_1024::DecapsKey::try_from_bytes(*dk_arr).map_err(|e| {
        CipherPassError::CryptoError(format!("Invalid ML-KEM-1024 secret key: {e}"))
    })?;

    let ct_arr: [u8; ml_kem_1024::CT_LEN] = ct_slice.try_into().unwrap();
    let ct = ml_kem_1024::CipherText::try_from_bytes(ct_arr).map_err(|e| {
        CipherPassError::CryptoError(format!("Invalid ML-KEM-1024 ciphertext: {e}"))
    })?;

    let ss = dk
        .try_decaps(&ct)
        .map_err(|e| CipherPassError::CryptoError(format!("ML-KEM-1024 decaps failed: {e}")))?;
    let ss_bytes = Zeroizing::new(ss.into_bytes());

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(nonce_slice);

    let aead_key = derive_aead_key(ss_bytes.as_slice(), ct_slice, &nonce_bytes);
    let cipher = ChaCha20Poly1305::new(aead_key.as_slice().into());

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: aead_ct,
                aad: header,
            },
        )
        .map_err(|_| {
            CipherPassError::CryptoError(
                "Post-quantum envelope authentication failed (wrong ML-KEM-1024 key or tampered file)"
                    .into(),
            )
        })?;

    Ok(Zeroizing::new(plaintext))
}
