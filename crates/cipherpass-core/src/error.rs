use thiserror::Error;

#[derive(Debug, Error)]
pub enum CipherPassError {
    #[error("Invalid KDBX file signature")]
    InvalidSignature,

    #[error("Unsupported KDBX format version: {major}.{minor} (only KDBX 4.0 / 4.1 supported)")]
    UnsupportedVersion { major: u16, minor: u16 },

    #[error("Unsupported outer cipher UUID: {0}")]
    UnsupportedCipher(String),

    #[error("Unsupported KDF UUID: {0}")]
    UnsupportedKdf(String),

    #[error("Unsupported compression flag: {0}")]
    UnsupportedCompression(u32),

    #[error("Unsupported inner random stream ID: {0}")]
    UnsupportedInnerStream(u32),

    #[error("Header integrity check failed (SHA-256 mismatch — file may be corrupted)")]
    HeaderHashMismatch,

    #[error("Authentication failed: invalid master password, wrong keyfile, or tampered header")]
    HeaderHmacMismatch,

    #[error(
        "Block {block_index} HMAC verification failed — ciphertext was tampered with or corrupted"
    )]
    BlockHmacMismatch { block_index: u64 },

    #[error("Malformed KDBX structure: {0}")]
    MalformedFormat(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Invalid keyfile: {0}")]
    InvalidKeyfile(String),

    #[error("KDF parameters below safe minimum floor: {0}")]
    UnsafeKdfParams(String),

    #[error("XML serialization/deserialization error: {0}")]
    XmlError(String),

    #[error("Invalid TOTP configuration or URI: {0}")]
    InvalidTotp(String),

    #[error("Vault item not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, CipherPassError>;
