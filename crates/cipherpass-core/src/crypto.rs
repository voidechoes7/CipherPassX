use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20::cipher::StreamCipher;
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use salsa20::Salsa20;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{CipherPassError, Result};
use crate::variant_dict::{VariantDictionary, VariantValue};

/// KDBX 4 outer cipher UUIDs (standard KeePass 2 / KeePassXC / KeePassDX).
pub const CIPHER_CHACHA20_UUID: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];
pub const CIPHER_AES256_CBC_UUID: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];

/// KDBX 4 KDF UUIDs.
pub const KDF_ARGON2D_UUID: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
pub const KDF_ARGON2ID_UUID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

/// Safe minimum floor for newly created / updated vaults.
pub const MIN_KDF_MEMORY_MIB: u64 = 64;
pub const MIN_KDF_ITERATIONS: u64 = 3;
pub const MIN_KDF_PARALLELISM: u32 = 1;
pub const MAX_KDF_MEMORY_MIB: u64 = 2048;
pub const MAX_KDF_ITERATIONS: u64 = 100;
pub const MAX_KDF_PARALLELISM: u32 = 16;

/// Inner Random Stream IDs per KDBX 4 specification.
pub const INNER_STREAM_NONE: u32 = 0;
pub const INNER_STREAM_SALSA20: u32 = 2;
pub const INNER_STREAM_CHACHA20: u32 = 3;

/// Fixed Salsa20 IV from KeePass 2 specification (used only for legacy read compatibility).
const SALSA20_FIXED_IV: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    ChaCha20,
    Aes256Cbc,
}

impl CipherAlgorithm {
    pub fn uuid(self) -> [u8; 16] {
        match self {
            Self::ChaCha20 => CIPHER_CHACHA20_UUID,
            Self::Aes256Cbc => CIPHER_AES256_CBC_UUID,
        }
    }

    pub fn from_uuid(bytes: &[u8]) -> Result<Self> {
        if bytes == CIPHER_CHACHA20_UUID {
            Ok(Self::ChaCha20)
        } else if bytes == CIPHER_AES256_CBC_UUID {
            Ok(Self::Aes256Cbc)
        } else {
            Err(CipherPassError::UnsupportedCipher(hex::encode(bytes)))
        }
    }

    pub fn iv_len(self) -> usize {
        match self {
            Self::ChaCha20 => 12,
            Self::Aes256Cbc => 16,
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::ChaCha20 => "ChaCha20 (256-bit, PQ-safe)",
            Self::Aes256Cbc => "AES-256-CBC (256-bit, PQ-safe)",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfAlgorithm {
    Argon2id,
    Argon2d,
}

impl KdfAlgorithm {
    pub fn uuid(self) -> [u8; 16] {
        match self {
            Self::Argon2id => KDF_ARGON2ID_UUID,
            Self::Argon2d => KDF_ARGON2D_UUID,
        }
    }

    pub fn from_uuid(bytes: &[u8]) -> Result<Self> {
        if bytes == KDF_ARGON2ID_UUID {
            Ok(Self::Argon2id)
        } else if bytes == KDF_ARGON2D_UUID {
            Ok(Self::Argon2d)
        } else {
            Err(CipherPassError::UnsupportedKdf(hex::encode(bytes)))
        }
    }
}

/// Configurable Argon2 KDF parameters (KDBX 4 standard).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfConfig {
    pub algorithm: KdfAlgorithm,
    /// Memory cost in MiB (converted to bytes in KDBX header `M` field).
    pub memory_mib: u64,
    /// Number of iterations (`I` field).
    pub iterations: u64,
    /// Degree of parallelism / lanes (`P` field).
    pub parallelism: u32,
    /// Argon2 version (0x13 = 19).
    pub version: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        // Post-quantum hardened interactive default: Argon2id v0x13, 128 MiB, 4 rounds, 4 lanes.
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_mib: 128,
            iterations: 4,
            parallelism: 4,
            version: 0x13,
        }
    }
}

impl KdfConfig {
    /// Fast preset strictly for unit/integration tests; not accepted by `validate_safe_floor()`.
    pub fn test_fast() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_mib: 1,
            iterations: 1,
            parallelism: 1,
            version: 0x13,
        }
    }

    /// Enforce safe minimum cryptographic floor for newly created / updated vaults.
    pub fn validate_safe_floor(&self) -> Result<()> {
        if self.memory_mib < MIN_KDF_MEMORY_MIB || self.memory_mib > MAX_KDF_MEMORY_MIB {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Memory must be between {MIN_KDF_MEMORY_MIB} MiB and {MAX_KDF_MEMORY_MIB} MiB (got {} MiB)",
                self.memory_mib
            )));
        }
        if self.iterations < MIN_KDF_ITERATIONS || self.iterations > MAX_KDF_ITERATIONS {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Iterations must be between {MIN_KDF_ITERATIONS} and {MAX_KDF_ITERATIONS} (got {})",
                self.iterations
            )));
        }
        if self.parallelism < MIN_KDF_PARALLELISM || self.parallelism > MAX_KDF_PARALLELISM {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Parallelism must be between {MIN_KDF_PARALLELISM} and {MAX_KDF_PARALLELISM} (got {})",
                self.parallelism
            )));
        }
        if self.version != 0x13 && self.version != 0x10 {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Unsupported Argon2 version: 0x{:02x}",
                self.version
            )));
        }
        Ok(())
    }

    pub fn meets_safe_floor(&self) -> bool {
        self.validate_safe_floor().is_ok()
    }

    pub fn to_variant_dict(&self, salt: &[u8; 32]) -> VariantDictionary {
        let mut dict = VariantDictionary::new();
        dict.insert("$UUID", VariantValue::Bytes(self.algorithm.uuid().to_vec()));
        dict.insert("S", VariantValue::Bytes(salt.to_vec()));
        dict.insert("P", VariantValue::UInt32(self.parallelism));
        let mem_bytes = self.memory_mib.saturating_mul(1024).saturating_mul(1024);
        dict.insert("M", VariantValue::UInt64(mem_bytes));
        dict.insert("I", VariantValue::UInt64(self.iterations));
        dict.insert("V", VariantValue::UInt32(self.version));
        dict
    }

    pub fn from_variant_dict(dict: &VariantDictionary) -> Result<(Self, Vec<u8>)> {
        let uuid = dict
            .get_bytes("$UUID")
            .ok_or_else(|| CipherPassError::MalformedFormat("Missing KDF $UUID".into()))?;
        let algorithm = KdfAlgorithm::from_uuid(uuid)?;

        let salt = dict
            .get_bytes("S")
            .ok_or_else(|| CipherPassError::MalformedFormat("Missing KDF salt (S)".into()))?
            .to_vec();
        if salt.len() < 8 || salt.len() > 1024 {
            return Err(CipherPassError::MalformedFormat(format!(
                "KDF salt length out of safe bounds: {} bytes",
                salt.len()
            )));
        }
        let parallelism = dict.get_u32("P").ok_or_else(|| {
            CipherPassError::MalformedFormat("Missing KDF parallelism (P)".into())
        })?;
        let memory_bytes = dict
            .get_u64("M")
            .ok_or_else(|| CipherPassError::MalformedFormat("Missing KDF memory (M)".into()))?;
        let iterations = dict
            .get_u64("I")
            .ok_or_else(|| CipherPassError::MalformedFormat("Missing KDF iterations (I)".into()))?;
        let version = dict.get_u32("V").unwrap_or(0x13);

        // Enforce strict DoS upper bounds even before KDF execution on unauthenticated headers.
        let max_mem_bytes = MAX_KDF_MEMORY_MIB * 1024 * 1024;
        if memory_bytes < 8 * 1024 || memory_bytes > max_mem_bytes {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "KDF memory {} bytes outside safe open bounds (8 KiB ..= {MAX_KDF_MEMORY_MIB} MiB)",
                memory_bytes
            )));
        }
        if iterations == 0 || iterations > MAX_KDF_ITERATIONS {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "KDF iterations {iterations} outside safe open bounds (1 ..= {MAX_KDF_ITERATIONS})"
            )));
        }
        if parallelism == 0 || parallelism > MAX_KDF_PARALLELISM {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "KDF parallelism {parallelism} outside safe open bounds (1 ..= {MAX_KDF_PARALLELISM})"
            )));
        }

        // Convert bytes to MiB (round up to at least 1 MiB if small external test vault).
        let memory_mib = (memory_bytes / (1024 * 1024)).max(1);

        Ok((
            Self {
                algorithm,
                memory_mib,
                iterations,
                parallelism,
                version,
            },
            salt,
        ))
    }

    /// Derive 32-byte transformed key from the KDBX composite key using Argon2id/Argon2d.
    pub fn derive_transformed_key(
        &self,
        composite_key: &[u8; 32],
        salt: &[u8],
        exact_memory_bytes: Option<u64>,
    ) -> Result<Zeroizing<[u8; 32]>> {
        if salt.len() < 8 || salt.len() > 1024 {
            return Err(CipherPassError::CryptoError(format!(
                "Argon2 salt length out of range: {}",
                salt.len()
            )));
        }
        let max_mem_bytes = MAX_KDF_MEMORY_MIB * 1024 * 1024;
        let mem_bytes = match exact_memory_bytes {
            Some(b) => b,
            None => self
                .memory_mib
                .checked_mul(1024 * 1024)
                .ok_or_else(|| CipherPassError::CryptoError("Argon2 memory overflow".into()))?,
        };
        if mem_bytes < 8 * 1024 || mem_bytes > max_mem_bytes {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Argon2 memory {} bytes exceeds safe bounds (8 KiB ..= {MAX_KDF_MEMORY_MIB} MiB)",
                mem_bytes
            )));
        }
        if self.iterations == 0 || self.iterations > MAX_KDF_ITERATIONS {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Argon2 iterations {} exceeds safe bounds (1 ..= {MAX_KDF_ITERATIONS})",
                self.iterations
            )));
        }
        if self.parallelism == 0 || self.parallelism > MAX_KDF_PARALLELISM {
            return Err(CipherPassError::UnsafeKdfParams(format!(
                "Argon2 parallelism {} exceeds safe bounds (1 ..= {MAX_KDF_PARALLELISM})",
                self.parallelism
            )));
        }

        let mem_kib = u32::try_from(mem_bytes / 1024)
            .map_err(|_| CipherPassError::CryptoError("Argon2 memory out of range".into()))?;
        let t_cost = u32::try_from(self.iterations)
            .map_err(|_| CipherPassError::CryptoError("Argon2 iterations out of range".into()))?;

        let alg = match self.algorithm {
            KdfAlgorithm::Argon2id => Algorithm::Argon2id,
            KdfAlgorithm::Argon2d => Algorithm::Argon2d,
        };
        let ver = match self.version {
            0x10 => Version::V0x10,
            0x13 => Version::V0x13,
            other => {
                return Err(CipherPassError::CryptoError(format!(
                    "Unsupported Argon2 version 0x{other:02x}"
                )))
            }
        };

        let params = Params::new(mem_kib, t_cost, self.parallelism, Some(32))
            .map_err(|e| CipherPassError::CryptoError(format!("Invalid Argon2 params: {e}")))?;

        let argon2 = Argon2::new(alg, ver, params);
        let mut out = Zeroizing::new([0u8; 32]);
        argon2
            .hash_password_into(composite_key, salt, out.as_mut())
            .map_err(|e| CipherPassError::CryptoError(format!("Argon2 derivation failed: {e}")))?;

        Ok(out)
    }
}

/// Master credentials: master password and/or optional Keyfile (v2.0 XML or legacy).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterCredentials {
    pub password: Option<String>,
    pub keyfile_bytes: Option<Vec<u8>>,
}

impl MasterCredentials {
    pub fn from_password(password: impl Into<String>) -> Self {
        Self {
            password: Some(password.into()),
            keyfile_bytes: None,
        }
    }

    pub fn from_password_and_keyfile(
        password: Option<String>,
        keyfile_bytes: Option<Vec<u8>>,
    ) -> Result<Self> {
        let has_pw = password.as_ref().is_some_and(|p| !p.is_empty());
        let has_kf = keyfile_bytes.as_ref().is_some_and(|k| !k.is_empty());
        if !has_pw && !has_kf {
            return Err(CipherPassError::CryptoError(
                "At least a master password or a keyfile is required".into(),
            ));
        }
        Ok(Self {
            password: if has_pw { password } else { None },
            keyfile_bytes: if has_kf { keyfile_bytes } else { None },
        })
    }

    /// Compute KDBX 4 composite key: SHA-256( [SHA-256(password)] || [keyfile_key] ).
    pub fn composite_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let mut hasher = Sha256::new();
        let mut has_any = false;

        if let Some(ref pw) = self.password {
            if !pw.is_empty() {
                let mut pw_hash = Zeroizing::new([0u8; 32]);
                pw_hash.copy_from_slice(&Sha256::digest(pw.as_bytes()));
                hasher.update(pw_hash.as_slice());
                has_any = true;
            }
        }

        if let Some(ref kf) = self.keyfile_bytes {
            if !kf.is_empty() {
                let kf_key = parse_keyfile_bytes(kf)?;
                hasher.update(kf_key.as_slice());
                has_any = true;
            }
        }

        if !has_any {
            return Err(CipherPassError::CryptoError(
                "Empty master credentials".into(),
            ));
        }

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&hasher.finalize());
        Ok(out)
    }
}

/// Generate a KeePass Keyfile v2.0 XML document (256-bit CSPRNG key with SHA-256 4-byte hash prefix).
/// 100% compatible with KeePass 2.47+, KeePassXC 2.7+, and KeePassDX.
pub fn generate_keyfile_v2_xml() -> Zeroizing<String> {
    let mut raw_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(raw_key.as_mut());

    let hash = Sha256::digest(raw_key.as_slice());
    let hash_prefix = hex::encode_upper(&hash[..4]);

    let hex_key = Zeroizing::new(hex::encode_upper(raw_key.as_slice()));
    // Format as 8 groups of 8 hex chars across 2 lines (KeePass 2.0 standard formatting)
    let line1 = Zeroizing::new(format!(
        "{} {} {} {}",
        &hex_key[0..8],
        &hex_key[8..16],
        &hex_key[16..24],
        &hex_key[24..32]
    ));
    let line2 = Zeroizing::new(format!(
        "{} {} {} {}",
        &hex_key[32..40],
        &hex_key[40..48],
        &hex_key[48..56],
        &hex_key[56..64]
    ));

    Zeroizing::new(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <KeyFile>\n\
         \t<Meta>\n\
         \t\t<Version>2.0</Version>\n\
         \t</Meta>\n\
         \t<Key>\n\
         \t\t<Data Hash=\"{hash_prefix}\">\n\
         \t\t\t{}\n\
         \t\t\t{}\n\
         \t\t</Data>\n\
         \t</Key>\n\
         </KeyFile>\n",
        line1.as_str(),
        line2.as_str()
    ))
}

/// Hard cap on XML keyfile size (64 KiB) to prevent parser DoS.
const MAX_XML_KEYFILE_BYTES: usize = 64 * 1024;

/// Parse a KeePass keyfile: supports XML v2.0 (with Hash verification), XML v1.0 (base64),
/// 32-byte raw binary, 64-byte hex, or arbitrary file (SHA-256 fallback per KeePass spec).
pub fn parse_keyfile_bytes(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    // 1. Try XML keyfile (v2.0 or v1.0)
    if raw.len() <= MAX_XML_KEYFILE_BYTES {
        if let Ok(text) = std::str::from_utf8(raw) {
            let trimmed = text.trim_start_matches('\u{feff}').trim();
            if trimmed.contains("<KeyFile") && trimmed.contains("<Data") {
                return parse_xml_keyfile(trimmed);
            }
        }
    }

    // 2. 32-byte raw binary key
    if raw.len() == 32 {
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(raw);
        return Ok(out);
    }

    // 3. 64-byte hex-encoded key
    if raw.len() == 64 {
        if let Ok(decoded) = hex::decode(raw) {
            let decoded = Zeroizing::new(decoded);
            if decoded.len() == 32 {
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(decoded.as_slice());
                return Ok(out);
            }
        }
    }

    // 4. Arbitrary file fallback: SHA-256(file_contents)
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&Sha256::digest(raw));
    Ok(out)
}

fn parse_xml_keyfile(xml: &str) -> Result<Zeroizing<[u8; 32]>> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    if xml.len() > MAX_XML_KEYFILE_BYTES {
        return Err(CipherPassError::InvalidKeyfile(
            "XML keyfile exceeds 64 KiB safety limit".into(),
        ));
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut version = String::new();
    let mut in_version = false;
    let mut in_data = false;
    let mut data_seen = false;
    let mut data_hash_attr: Option<String> = None;
    let mut data_text = Zeroizing::new(String::new());

    loop {
        match reader.read_event() {
            Ok(Event::DocType(_)) => {
                return Err(CipherPassError::InvalidKeyfile(
                    "XML DOCTYPE declarations are forbidden in keyfiles".into(),
                ));
            }
            Ok(Event::Start(e)) => {
                let name = e.name();
                if name.as_ref() == b"Version" {
                    in_version = true;
                } else if name.as_ref() == b"Data" {
                    if data_seen {
                        return Err(CipherPassError::InvalidKeyfile(
                            "Duplicate <Data> element in XML keyfile".into(),
                        ));
                    }
                    data_seen = true;
                    in_data = true;
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Hash" {
                            data_hash_attr =
                                Some(String::from_utf8_lossy(attr.value.as_ref()).to_string());
                        }
                    }
                }
            }
            Ok(Event::Text(e)) => {
                let txt = e
                    .unescape()
                    .map_err(|err| CipherPassError::InvalidKeyfile(err.to_string()))?;
                if in_version {
                    version.push_str(&txt);
                } else if in_data {
                    data_text.push_str(&txt);
                }
            }
            Ok(Event::End(e)) => {
                let name = e.name();
                if name.as_ref() == b"Version" {
                    in_version = false;
                } else if name.as_ref() == b"Data" {
                    in_data = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(CipherPassError::InvalidKeyfile(format!(
                    "Malformed XML keyfile: {e}"
                )))
            }
            _ => {}
        }
    }

    let ver_trimmed = version.trim();
    if ver_trimmed.starts_with("2.") {
        // Keyfile v2.0: hex string (whitespace stripped) + mandatory 4-byte SHA-256 Hash verification
        let hex_clean: Zeroizing<String> =
            Zeroizing::new(data_text.chars().filter(|c| !c.is_whitespace()).collect());
        let decoded = Zeroizing::new(hex::decode(hex_clean.as_str()).map_err(|_| {
            CipherPassError::InvalidKeyfile("Invalid hex data in Keyfile v2.0".into())
        })?);
        if decoded.len() != 32 {
            return Err(CipherPassError::InvalidKeyfile(format!(
                "Keyfile v2.0 must contain 32 bytes, got {}",
                decoded.len()
            )));
        }

        let expected_hash = data_hash_attr.ok_or_else(|| {
            CipherPassError::InvalidKeyfile(
                "Missing mandatory Hash attribute in Keyfile v2.0".into(),
            )
        })?;
        let expected_bytes = hex::decode(expected_hash.trim()).map_err(|_| {
            CipherPassError::InvalidKeyfile("Invalid Hash attribute in Keyfile v2.0".into())
        })?;
        let actual_hash = Sha256::digest(decoded.as_slice());
        if expected_bytes.len() != 4 || actual_hash[..4].ct_eq(&expected_bytes).unwrap_u8() != 1 {
            return Err(CipherPassError::InvalidKeyfile(
                "Keyfile v2.0 integrity Hash mismatch".into(),
            ));
        }

        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(decoded.as_slice());
        Ok(out)
    } else if ver_trimmed.starts_with("1.") {
        // Keyfile v1.0: Base64-encoded 32 bytes
        use base64::Engine;
        let b64_clean: Zeroizing<String> =
            Zeroizing::new(data_text.chars().filter(|c| !c.is_whitespace()).collect());
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(b64_clean.as_str())
                .map_err(|_| {
                    CipherPassError::InvalidKeyfile("Invalid Base64 in Keyfile v1.0".into())
                })?,
        );
        if decoded.len() != 32 {
            return Err(CipherPassError::InvalidKeyfile(format!(
                "Keyfile v1.0 must decode to 32 bytes, got {}",
                decoded.len()
            )));
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(decoded.as_slice());
        Ok(out)
    } else {
        Err(CipherPassError::InvalidKeyfile(format!(
            "Unsupported XML keyfile version: '{ver_trimmed}'"
        )))
    }
}

/// Derived KDBX 4 session keys (all zeroized on drop).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedVaultKeys {
    pub master_key: [u8; 32],
    pub hmac_key_base: [u8; 64],
}

impl DerivedVaultKeys {
    pub fn derive(master_seed: &[u8; 32], transformed_key: &[u8; 32]) -> Self {
        // master_key = SHA-256(master_seed || transformed_key)
        let mut mk_hasher = Sha256::new();
        mk_hasher.update(master_seed);
        mk_hasher.update(transformed_key);
        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&mk_hasher.finalize());

        // hmac_key_base = SHA-512(master_seed || transformed_key || 0x01)
        let mut hk_hasher = Sha512::new();
        hk_hasher.update(master_seed);
        hk_hasher.update(transformed_key);
        hk_hasher.update([0x01u8]);
        let mut hmac_key_base = [0u8; 64];
        hmac_key_base.copy_from_slice(&hk_hasher.finalize());

        Self {
            master_key,
            hmac_key_base,
        }
    }

    pub fn header_hmac_key(&self) -> Zeroizing<[u8; 64]> {
        let mut h = Sha512::new();
        h.update(u64::MAX.to_le_bytes());
        h.update(self.hmac_key_base);
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(&h.finalize());
        out
    }

    pub fn block_hmac_key(&self, block_index: u64) -> Zeroizing<[u8; 64]> {
        let mut h = Sha512::new();
        h.update(block_index.to_le_bytes());
        h.update(self.hmac_key_base);
        let mut out = Zeroizing::new([0u8; 64]);
        out.copy_from_slice(&h.finalize());
        out
    }
}

pub fn compute_header_hmac(header_hmac_key: &[u8; 64], header_bytes: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(header_hmac_key).expect("HMAC accepts any key size");
    mac.update(header_bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn compute_block_hmac(
    block_hmac_key: &[u8; 64],
    block_index: u64,
    block_size: u32,
    block_data: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(block_hmac_key).expect("HMAC accepts any key size");
    mac.update(&block_index.to_le_bytes());
    mac.update(&block_size.to_le_bytes());
    mac.update(block_data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

pub fn constant_time_eq_32(a: &[u8], b: &[u8]) -> bool {
    a.len() == 32 && b.len() == 32 && a.ct_eq(b).unwrap_u8() == 1
}

/// Encrypt outer payload using KDBX 4 outer cipher (ChaCha20 or AES-256-CBC).
pub fn encrypt_outer(
    cipher: CipherAlgorithm,
    master_key: &[u8; 32],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match cipher {
        CipherAlgorithm::ChaCha20 => {
            if iv.len() != 12 {
                return Err(CipherPassError::CryptoError(format!(
                    "ChaCha20 requires 12-byte IV, got {}",
                    iv.len()
                )));
            }
            let mut buf = plaintext.to_vec();
            let mut stream = ChaCha20::new(master_key.into(), iv.into());
            stream.apply_keystream(&mut buf);
            Ok(buf)
        }
        CipherAlgorithm::Aes256Cbc => {
            if iv.len() != 16 {
                return Err(CipherPassError::CryptoError(format!(
                    "AES-256-CBC requires 16-byte IV, got {}",
                    iv.len()
                )));
            }
            let enc = Aes256CbcEnc::new(master_key.into(), iv.into());
            Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
        }
    }
}

/// Decrypt outer payload using KDBX 4 outer cipher (ChaCha20 or AES-256-CBC).
pub fn decrypt_outer(
    cipher: CipherAlgorithm,
    master_key: &[u8; 32],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    match cipher {
        CipherAlgorithm::ChaCha20 => {
            if iv.len() != 12 {
                return Err(CipherPassError::CryptoError(format!(
                    "ChaCha20 requires 12-byte IV, got {}",
                    iv.len()
                )));
            }
            let mut buf = Zeroizing::new(ciphertext.to_vec());
            let mut stream = ChaCha20::new(master_key.into(), iv.into());
            stream.apply_keystream(buf.as_mut_slice());
            Ok(buf)
        }
        CipherAlgorithm::Aes256Cbc => {
            if iv.len() != 16 {
                return Err(CipherPassError::CryptoError(format!(
                    "AES-256-CBC requires 16-byte IV, got {}",
                    iv.len()
                )));
            }
            let dec = Aes256CbcDec::new(master_key.into(), iv.into());
            let plain = dec
                .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
                .map_err(|_| {
                    CipherPassError::CryptoError("AES-256-CBC decryption/padding failed".into())
                })?;
            Ok(Zeroizing::new(plain))
        }
    }
}

/// Inner random stream cipher for encrypting/decrypting `<Value Protected="True">` XML fields.
pub enum InnerStreamCipher {
    None,
    ChaCha20(ChaCha20),
    Salsa20(Salsa20),
}

impl InnerStreamCipher {
    pub fn new(stream_id: u32, key: &[u8]) -> Result<Self> {
        match stream_id {
            INNER_STREAM_NONE => Ok(Self::None),
            INNER_STREAM_CHACHA20 => {
                if key.is_empty() {
                    return Err(CipherPassError::MalformedFormat(
                        "Missing or empty InnerRandomStreamKey for ChaCha20".into(),
                    ));
                }
                // KDBX 4 spec: SHA-512(key) -> first 32 bytes = ChaCha20 key, next 12 bytes = nonce.
                let mut hash = Zeroizing::new([0u8; 64]);
                hash.copy_from_slice(&Sha512::digest(key));
                let cipher = ChaCha20::new((&hash[0..32]).into(), (&hash[32..44]).into());
                Ok(Self::ChaCha20(cipher))
            }
            INNER_STREAM_SALSA20 => {
                if key.is_empty() {
                    return Err(CipherPassError::MalformedFormat(
                        "Missing or empty InnerRandomStreamKey for Salsa20".into(),
                    ));
                }
                // Legacy KDBX compatibility: SHA-256(key) + fixed 8-byte Salsa20 IV.
                let mut hash = Zeroizing::new([0u8; 32]);
                hash.copy_from_slice(&Sha256::digest(key));
                let cipher = Salsa20::new(hash.as_slice().into(), (&SALSA20_FIXED_IV).into());
                Ok(Self::Salsa20(cipher))
            }
            other => Err(CipherPassError::UnsupportedInnerStream(other)),
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::None => {}
            Self::ChaCha20(c) => c.apply_keystream(data),
            Self::Salsa20(c) => c.apply_keystream(data),
        }
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}
