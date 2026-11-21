#![forbid(unsafe_code)]

//! CipherPass Core — Pure-Rust (`#![forbid(unsafe_code)]`) KeePass KDBX 4 / 4.1 engine.
//!
//! 100% offline, zero telemetry, post-quantum hardened 256-bit symmetric cryptography
//! (ChaCha20 / AES-256-CBC + HMAC-SHA256 + Argon2id/Argon2d + ChaCha20 inner stream + `zeroize`).

pub mod audit;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod kdbx;
pub mod kdbx_xml;
pub mod model;
pub mod pq_armor;
pub mod totp;
pub mod variant_dict;

pub use audit::{run_vault_audit, AuditIssueItem, SecurityAuditReport};
pub use crypto::{
    generate_keyfile_v2_xml, parse_keyfile_bytes, CipherAlgorithm, KdfAlgorithm, KdfConfig,
    MasterCredentials, MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_MIB, MAX_KDF_PARALLELISM,
    MIN_KDF_ITERATIONS, MIN_KDF_MEMORY_MIB, MIN_KDF_PARALLELISM,
};
pub use error::{CipherPassError, Result};
pub use generator::{
    evaluate_password, generate_passphrase, generate_password, EntropyReport, GeneratedSecret,
    PassphraseGenOptions, PasswordGenOptions,
};
pub use kdbx::{
    atomic_write_file, open_kdbx_bytes, open_kdbx_file, save_kdbx_bytes, save_kdbx_file_atomic,
};
pub use model::{
    CustomField, DeletedObject, EntryHistoryItem, EntryTimes, InnerBinary, ProtectedString, Vault,
    VaultEntry, VaultGroup, VaultMeta, FAVORITE_TAG,
};
pub use pq_armor::{generate_mlkem1024_keypair, pq_seal_bytes, pq_unseal_bytes, MlKem1024Keypair};
pub use totp::{generate_totp_at, generate_totp_now, parse_totp_uri, TotpAlgorithm, TotpCode};
