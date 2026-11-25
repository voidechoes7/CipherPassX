use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::random_bytes;
use crate::error::{CipherPassError, Result};
use crate::model::{CustomField, ProtectedString, Vault, VaultEntry, VaultGroup};

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Hard cap on Bitwarden JSON / CSV import payload size (64 MiB) to prevent OOM DoS.
const MAX_INTERCHANGE_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Hard cap on nested folder depth during import/merge to prevent stack overflow DoS.
const MAX_IMPORT_FOLDER_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummary {
    pub source_format: String,
    pub imported_entries: usize,
    pub created_folders: usize,
    pub skipped_items: usize,
}

// =========================================================================
// Bitwarden JSON Schema (Unencrypted & Password-Protected Encrypted)
// =========================================================================

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwEnvelope {
    #[serde(default)]
    #[zeroize(skip)]
    encrypted: bool,
    #[serde(default)]
    #[zeroize(skip)]
    password_protected: bool,
    salt: Option<String>,
    #[zeroize(skip)]
    kdf_type: Option<u8>,
    #[zeroize(skip)]
    kdf_iterations: Option<u32>,
    #[zeroize(skip)]
    kdf_memory: Option<u32>,
    #[zeroize(skip)]
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: Option<String>,
    data: Option<String>,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwPlainExport {
    #[zeroize(skip)]
    encrypted: bool,
    folders: Vec<BwFolder>,
    items: Vec<BwItem>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwEncryptedExport {
    encrypted: bool,
    password_protected: bool,
    salt: String,
    kdf_type: u8,
    kdf_iterations: u32,
    kdf_memory: u32,
    kdf_parallelism: u32,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: String,
    data: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwFolder {
    id: String,
    name: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(rename = "type")]
    #[zeroize(skip)]
    item_type: u8,
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    #[zeroize(skip)]
    favorite: bool,
    #[serde(default)]
    fields: Vec<BwField>,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    card: Option<BwCard>,
    #[serde(default)]
    identity: Option<BwIdentity>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(rename = "type", default)]
    #[zeroize(skip)]
    field_type: u8,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwLogin {
    #[serde(default)]
    uris: Vec<BwUri>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwCard {
    #[serde(default)]
    cardholder_name: Option<String>,
    #[serde(default)]
    brand: Option<String>,
    #[serde(default)]
    number: Option<String>,
    #[serde(default)]
    exp_month: Option<String>,
    #[serde(default)]
    exp_year: Option<String>,
    #[serde(default)]
    code: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct BwIdentity {
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    middle_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    company: Option<String>,
    #[serde(default)]
    ssn: Option<String>,
    #[serde(default)]
    passport_number: Option<String>,
    #[serde(default)]
    license_number: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    address1: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

// =========================================================================
// Bitwarden-Compatible Crypto Helpers (PBKDF2 / Argon2id + HKDF + AES-CBC-HMAC)
// =========================================================================

fn pbkdf2_hmac_sha256_32(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    if iterations == 0 || iterations > 2_000_000 {
        return Err(CipherPassError::CryptoError(format!(
            "Unsupported PBKDF2 iteration count: {iterations} (allowed: 1..=2000000)"
        )));
    }
    let base_mac = <HmacSha256 as Mac>::new_from_slice(password)
        .map_err(|_| CipherPassError::CryptoError("HMAC init failed".into()))?;
    let mut mac = base_mac.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut out = Zeroizing::new(*u);

    for _ in 1..iterations {
        let mut m = base_mac.clone();
        m.update(u.as_slice());
        *u = m.finalize().into_bytes().into();
        for (dst, src) in out.iter_mut().zip(u.iter()) {
            *dst ^= *src;
        }
    }
    Ok(out)
}

/// Bitwarden's HKDF-Expand-SHA256 (RFC 5869 Expand step using master key directly as PRK).
fn hkdf_expand_sha256_32(prk: &[u8; 32], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
        .map_err(|_| CipherPassError::CryptoError("HKDF init failed".into()))?;
    mac.update(info);
    mac.update(&[1u8]);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}

type StretchedKeyPair = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn derive_bw_stretched_keys(
    password: &str,
    salt_str: &str,
    kdf_type: u8,
    iterations: u32,
    memory_mib: Option<u32>,
    parallelism: Option<u32>,
) -> Result<StretchedKeyPair> {
    if salt_str.is_empty() || salt_str.len() > 1024 {
        return Err(CipherPassError::MalformedFormat(
            "Invalid Bitwarden KDF salt length".into(),
        ));
    }

    let master_key = match kdf_type {
        0 => pbkdf2_hmac_sha256_32(password.as_bytes(), salt_str.as_bytes(), iterations)?,
        1 => {
            let mem_mib = memory_mib.unwrap_or(64);
            let lanes = parallelism.unwrap_or(4);
            if !(16..=512).contains(&mem_mib) {
                return Err(CipherPassError::UnsafeKdfParams(format!(
                    "Bitwarden Argon2id memory {mem_mib} MiB outside safe bounds (16..=512 MiB)"
                )));
            }
            if !(1..=16).contains(&lanes) {
                return Err(CipherPassError::UnsafeKdfParams(format!(
                    "Bitwarden Argon2id parallelism {lanes} outside safe bounds (1..=16)"
                )));
            }
            if !(1..=64).contains(&iterations) {
                return Err(CipherPassError::UnsafeKdfParams(format!(
                    "Bitwarden Argon2id iterations {iterations} outside safe bounds (1..=64)"
                )));
            }
            let salt_hash = Sha256::digest(salt_str.as_bytes());
            let params = Params::new(mem_mib * 1024, iterations, lanes, Some(32))
                .map_err(|e| CipherPassError::CryptoError(format!("Argon2id params error: {e}")))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = Zeroizing::new([0u8; 32]);
            argon2
                .hash_password_into(password.as_bytes(), &salt_hash, key.as_mut())
                .map_err(|e| CipherPassError::CryptoError(format!("Argon2id KDF failed: {e}")))?;
            key
        }
        other => {
            return Err(CipherPassError::CryptoError(format!(
                "Unsupported Bitwarden KDF type: {other}"
            )));
        }
    };

    let enc_key = hkdf_expand_sha256_32(&master_key, b"enc")?;
    let mac_key = hkdf_expand_sha256_32(&master_key, b"mac")?;
    Ok((enc_key, mac_key))
}

/// Encrypt bytes into Bitwarden EncString type 2 (`2.<iv_b64>|<ct_b64>|<mac_b64>`).
fn bw_encrypt_string(plaintext: &[u8], enc_key: &[u8; 32], mac_key: &[u8; 32]) -> Result<String> {
    let iv: [u8; 16] = random_bytes();
    let ct =
        Aes256CbcEnc::new(enc_key.into(), (&iv).into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mut mac = <HmacSha256 as Mac>::new_from_slice(mac_key)
        .map_err(|_| CipherPassError::CryptoError("MAC init failed".into()))?;
    mac.update(&iv);
    mac.update(&ct);
    let mac_bytes = mac.finalize().into_bytes();

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(format!(
        "2.{}|{}|{}",
        b64.encode(iv),
        b64.encode(ct),
        b64.encode(mac_bytes)
    ))
}

/// Decrypt Bitwarden EncString type 2 (`2.<iv_b64>|<ct_b64>|<mac_b64>`).
fn bw_decrypt_string(
    enc_string: &str,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>> {
    let body = enc_string.strip_prefix("2.").ok_or_else(|| {
        CipherPassError::MalformedFormat(
            "Unsupported Bitwarden cipher string format (expected type 2 AES-256-CBC+HMAC-SHA256)"
                .into(),
        )
    })?;
    let parts: Vec<&str> = body.split('|').collect();
    if parts.len() != 3 {
        return Err(CipherPassError::MalformedFormat(
            "Invalid Bitwarden encrypted string segments".into(),
        ));
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let iv = b64
        .decode(parts[0])
        .map_err(|_| CipherPassError::MalformedFormat("Invalid IV Base64".into()))?;
    let ct = b64
        .decode(parts[1])
        .map_err(|_| CipherPassError::MalformedFormat("Invalid ciphertext Base64".into()))?;
    let expected_mac = b64
        .decode(parts[2])
        .map_err(|_| CipherPassError::MalformedFormat("Invalid MAC Base64".into()))?;

    if iv.len() != 16 || expected_mac.len() != 32 {
        return Err(CipherPassError::MalformedFormat(
            "Invalid IV or MAC length in encrypted JSON".into(),
        ));
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(mac_key)
        .map_err(|_| CipherPassError::CryptoError("MAC init failed".into()))?;
    mac.update(&iv);
    mac.update(&ct);
    let computed_mac = mac.finalize().into_bytes();
    if !bool::from(computed_mac.as_slice().ct_eq(&expected_mac)) {
        return Err(CipherPassError::CryptoError(
            "Wrong export password or tampered encrypted JSON (HMAC verification failed)".into(),
        ));
    }

    let iv_arr: [u8; 16] = iv.try_into().unwrap();
    let pt = Aes256CbcDec::new(enc_key.into(), (&iv_arr).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ct)
        .map_err(|_| {
            CipherPassError::CryptoError("AES-256-CBC padding error (wrong password)".into())
        })?;

    Ok(Zeroizing::new(pt))
}

// =========================================================================
// Folder Path Helper (Supports Nested "Parent/Child" Folders, Depth-Capped)
// =========================================================================

fn ensure_folder_path<'a>(
    root: &'a mut VaultGroup,
    path_str: &str,
    created_folders: &mut usize,
) -> &'a mut VaultGroup {
    let mut current = root;
    for segment in path_str
        .split('/')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .take(MAX_IMPORT_FOLDER_DEPTH)
    {
        let existing_idx = current
            .subgroups
            .iter()
            .position(|g| g.name.eq_ignore_ascii_case(segment));
        let idx = if let Some(i) = existing_idx {
            i
        } else {
            current.subgroups.push(VaultGroup::new(segment, 48));
            *created_folders += 1;
            current.subgroups.len() - 1
        };
        current = &mut current.subgroups[idx];
    }
    current
}

fn push_cf(entry: &mut VaultEntry, key: &str, value: &str, protected: bool) {
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        entry.custom_fields.push(CustomField {
            key: key.to_string(),
            value: ProtectedString::new(trimmed.to_string()),
            protected,
        });
    }
}

// =========================================================================
// 1. Import Bitwarden JSON (Unencrypted OR Password-Protected Encrypted)
// =========================================================================

pub fn import_bitwarden_json(
    raw_bytes: &[u8],
    password: Option<&str>,
    target_vault: &mut Vault,
) -> Result<ImportSummary> {
    if raw_bytes.len() > MAX_INTERCHANGE_INPUT_BYTES {
        return Err(CipherPassError::MalformedFormat(
            "Bitwarden JSON file exceeds 64 MiB safety limit".into(),
        ));
    }

    let env: BwEnvelope = serde_json::from_slice(raw_bytes).map_err(|e| {
        CipherPassError::MalformedFormat(format!("Invalid Bitwarden JSON file: {e}"))
    })?;

    let (folders, items, source_format) = if env.encrypted {
        if !env.password_protected {
            return Err(CipherPassError::CryptoError(
                "This Bitwarden JSON is 'Account restricted' (tied to Bitwarden's server key). Re-export from Bitwarden choosing 'Password protected' (.json) or unencrypted .json so it can be imported offline."
                    .into(),
            ));
        }
        let pw = password.filter(|s| !s.is_empty()).ok_or_else(|| {
            CipherPassError::CryptoError(
                "This Bitwarden JSON is password-protected. Enter the export password to decrypt it."
                    .into(),
            )
        })?;
        let salt = env.salt.as_deref().ok_or_else(|| {
            CipherPassError::MalformedFormat("Missing salt in encrypted Bitwarden JSON".into())
        })?;
        let data_enc = env.data.as_deref().ok_or_else(|| {
            CipherPassError::MalformedFormat("Missing data payload in encrypted JSON".into())
        })?;
        let kdf_type = env.kdf_type.unwrap_or(0);
        let kdf_iterations = env.kdf_iterations.unwrap_or(600_000);

        let (enc_key, mac_key) = derive_bw_stretched_keys(
            pw,
            salt,
            kdf_type,
            kdf_iterations,
            env.kdf_memory,
            env.kdf_parallelism,
        )?;

        if let Some(ref validation) = env.enc_key_validation {
            let _ = bw_decrypt_string(validation, &enc_key, &mac_key)?;
        }

        let decrypted = bw_decrypt_string(data_enc, &enc_key, &mac_key)?;
        if decrypted.len() > MAX_INTERCHANGE_INPUT_BYTES {
            return Err(CipherPassError::MalformedFormat(
                "Decrypted Bitwarden JSON payload exceeds 64 MiB safety limit".into(),
            ));
        }
        let inner: BwEnvelope = serde_json::from_slice(decrypted.as_slice()).map_err(|e| {
            CipherPassError::MalformedFormat(format!("Decrypted JSON payload malformed: {e}"))
        })?;
        (
            inner.folders.clone(),
            inner.items.clone(),
            "Encrypted JSON (Bitwarden / CipherPass)".to_string(),
        )
    } else {
        (
            env.folders.clone(),
            env.items.clone(),
            "Bitwarden JSON".to_string(),
        )
    };

    let mut folder_map = std::collections::HashMap::new();
    let mut created_folders = 0usize;
    for f in &folders {
        let name = f.name.trim();
        if !name.is_empty() {
            folder_map.insert(f.id.clone(), name.to_string());
            let _ = ensure_folder_path(&mut target_vault.root_group, name, &mut created_folders);
        }
    }

    let mut imported_entries = 0usize;
    let mut skipped_items = 0usize;

    for item in &items {
        let title = if item.name.trim().is_empty() {
            "(Untitled)".to_string()
        } else {
            item.name.trim().to_string()
        };
        let mut entry = VaultEntry::new(title);
        entry.notes = item.notes.clone().unwrap_or_default();
        if item.favorite {
            entry.set_favorite(true);
        }

        match item.item_type {
            // 1 = Login
            1 => {
                push_cf(&mut entry, "EntryType", "login", false);
                if let Some(ref login) = item.login {
                    entry.username = login.username.clone().unwrap_or_default();
                    entry.password =
                        ProtectedString::new(login.password.as_deref().unwrap_or_default());
                    if let Some(first_uri) = login
                        .uris
                        .first()
                        .and_then(|u| u.uri.as_ref())
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                    {
                        entry.url = first_uri.to_string();
                    }
                    for (idx, extra_u) in login.uris.iter().skip(1).enumerate() {
                        if let Some(ref u) = extra_u.uri {
                            push_cf(&mut entry, &format!("URL {}", idx + 2), u, false);
                        }
                    }
                    if let Some(totp) = login
                        .totp
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        entry.set_totp_uri(Some(totp.to_string()));
                    }
                }
            }
            // 2 = Secure Note
            2 => {
                push_cf(&mut entry, "EntryType", "note", false);
            }
            // 3 = Card
            3 => {
                push_cf(&mut entry, "EntryType", "card", false);
                if let Some(ref card) = item.card {
                    if let Some(ref ch) = card.cardholder_name {
                        entry.username = ch.trim().to_string();
                        push_cf(&mut entry, "Cardholder", ch, false);
                    }
                    if let Some(ref num) = card.number {
                        push_cf(&mut entry, "Card Number", num, true);
                    }
                    let exp = match (
                        card.exp_month
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty()),
                        card.exp_year
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty()),
                    ) {
                        (Some(m), Some(y)) => format!("{m}/{y}"),
                        (Some(m), None) => m.to_string(),
                        (None, Some(y)) => y.to_string(),
                        _ => String::new(),
                    };
                    push_cf(&mut entry, "Expiration", &exp, false);
                    if let Some(ref code) = card.code {
                        push_cf(&mut entry, "CVV", code, true);
                    }
                    if let Some(ref brand) = card.brand {
                        push_cf(&mut entry, "Brand", brand, false);
                    }
                }
            }
            // 4 = Identity
            4 => {
                push_cf(&mut entry, "EntryType", "note", false);
                if let Some(ref id) = item.identity {
                    let full_name = [
                        id.first_name.as_deref(),
                        id.middle_name.as_deref(),
                        id.last_name.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                    push_cf(&mut entry, "Full Name", &full_name, false);
                    if let Some(ref u) = id.username {
                        push_cf(&mut entry, "Username", u, false);
                    }
                    if let Some(ref c) = id.company {
                        push_cf(&mut entry, "Company", c, false);
                    }
                    if let Some(ref e) = id.email {
                        push_cf(&mut entry, "Email", e, false);
                    }
                    if let Some(ref p) = id.phone {
                        push_cf(&mut entry, "Phone", p, false);
                    }
                    if let Some(ref ssn) = id.ssn {
                        push_cf(&mut entry, "SSN", ssn, true);
                    }
                    if let Some(ref pp) = id.passport_number {
                        push_cf(&mut entry, "Passport", pp, true);
                    }
                    if let Some(ref lic) = id.license_number {
                        push_cf(&mut entry, "License", lic, true);
                    }
                    let addr = [
                        id.address1.as_deref(),
                        id.city.as_deref(),
                        id.country.as_deref(),
                    ]
                    .into_iter()
                    .flatten()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(", ");
                    push_cf(&mut entry, "Address", &addr, false);
                }
            }
            _ => {
                skipped_items += 1;
                continue;
            }
        }

        for cf in &item.fields {
            let k = cf.name.as_deref().unwrap_or_default();
            let v = cf.value.as_deref().unwrap_or_default();
            if !k.trim().is_empty() {
                push_cf(&mut entry, k.trim(), v, cf.field_type == 1);
            }
        }

        let target_folder_name = item
            .folder_id
            .as_deref()
            .and_then(|fid| folder_map.get(fid))
            .map(String::as_str);

        if let Some(folder_path) = target_folder_name {
            let grp = ensure_folder_path(
                &mut target_vault.root_group,
                folder_path,
                &mut created_folders,
            );
            grp.entries.push(entry);
        } else {
            let grp = ensure_folder_path(
                &mut target_vault.root_group,
                "Imported",
                &mut created_folders,
            );
            grp.entries.push(entry);
        }
        imported_entries += 1;
    }

    Ok(ImportSummary {
        source_format,
        imported_entries,
        created_folders,
        skipped_items,
    })
}

// =========================================================================
// 2. Export Cross-Platform Password-Protected Encrypted JSON (Bitwarden v2 Spec)
// =========================================================================

fn collect_groups_for_bw(
    group: &VaultGroup,
    prefix: &str,
    is_root: bool,
    folders: &mut Vec<BwFolder>,
    items: &mut Vec<BwItem>,
) {
    let current_path = if is_root {
        String::new()
    } else if prefix.is_empty() {
        group.name.clone()
    } else {
        format!("{prefix}/{}", group.name)
    };

    let folder_id = if !is_root {
        let fid = group.uuid.to_string();
        folders.push(BwFolder {
            id: fid.clone(),
            name: current_path.clone(),
        });
        Some(fid)
    } else {
        None
    };

    for entry in &group.entries {
        let explicit_type = entry
            .custom_fields
            .iter()
            .find(|f| f.key.eq_ignore_ascii_case("EntryType"))
            .map(|f| f.value.expose().trim().to_lowercase())
            .unwrap_or_default();

        let get_cf = |name: &str| -> Option<String> {
            entry
                .custom_fields
                .iter()
                .find(|f| f.key.eq_ignore_ascii_case(name))
                .map(|f| f.value.expose().to_string())
                .filter(|s| !s.is_empty())
        };

        let is_card =
            explicit_type == "card" || get_cf("Card Number").is_some() || get_cf("CVV").is_some();
        let is_note = explicit_type == "note"
            || (!is_card
                && entry.password.expose().is_empty()
                && entry.username.trim().is_empty()
                && entry.totp_uri().is_none()
                && !entry.notes.trim().is_empty());

        let reserved: &[&str] = if is_card {
            &[
                "EntryType",
                "otp",
                "Cardholder",
                "Card Number",
                "Expiration",
                "CVV",
                "Brand",
            ]
        } else {
            &["EntryType", "otp"]
        };

        let fields: Vec<BwField> = entry
            .custom_fields
            .iter()
            .filter(|f| !reserved.iter().any(|r| r.eq_ignore_ascii_case(&f.key)))
            .map(|f| BwField {
                name: Some(f.key.clone()),
                value: Some(f.value.expose().to_string()),
                field_type: if f.protected { 1 } else { 0 },
            })
            .collect();

        let bw_item = if is_card {
            let exp_raw = get_cf("Expiration").unwrap_or_default();
            let mut exp_parts = exp_raw.split('/');
            let exp_month = exp_parts
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let exp_year = exp_parts
                .next()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            BwItem {
                id: Some(entry.uuid.to_string()),
                folder_id: folder_id.clone(),
                item_type: 3,
                name: entry.title.clone(),
                notes: if entry.notes.is_empty() {
                    None
                } else {
                    Some(entry.notes.clone())
                },
                favorite: entry.is_favorite(),
                fields,
                login: None,
                card: Some(BwCard {
                    cardholder_name: get_cf("Cardholder").or_else(|| {
                        if entry.username.is_empty() {
                            None
                        } else {
                            Some(entry.username.clone())
                        }
                    }),
                    brand: get_cf("Brand"),
                    number: get_cf("Card Number"),
                    exp_month,
                    exp_year,
                    code: get_cf("CVV"),
                }),
                identity: None,
            }
        } else if is_note {
            BwItem {
                id: Some(entry.uuid.to_string()),
                folder_id: folder_id.clone(),
                item_type: 2,
                name: entry.title.clone(),
                notes: Some(entry.notes.clone()),
                favorite: entry.is_favorite(),
                fields,
                login: None,
                card: None,
                identity: None,
            }
        } else {
            let uris = if entry.url.trim().is_empty() {
                Vec::new()
            } else {
                vec![BwUri {
                    uri: Some(entry.url.clone()),
                }]
            };
            BwItem {
                id: Some(entry.uuid.to_string()),
                folder_id: folder_id.clone(),
                item_type: 1,
                name: entry.title.clone(),
                notes: if entry.notes.is_empty() {
                    None
                } else {
                    Some(entry.notes.clone())
                },
                favorite: entry.is_favorite(),
                fields,
                login: Some(BwLogin {
                    uris,
                    username: if entry.username.is_empty() {
                        None
                    } else {
                        Some(entry.username.clone())
                    },
                    password: if entry.password.expose().is_empty() {
                        None
                    } else {
                        Some(entry.password.expose().to_string())
                    },
                    totp: entry.totp_uri(),
                }),
                card: None,
                identity: None,
            }
        };

        items.push(bw_item);
    }

    for sub in &group.subgroups {
        collect_groups_for_bw(sub, &current_path, false, folders, items);
    }
}

/// Export the vault to a cross-platform Bitwarden-compatible Password-Protected Encrypted JSON file.
/// Uses Argon2id (64 MiB, 3 iterations, 4 lanes) + HKDF-SHA256 + AES-256-CBC + HMAC-SHA256.
pub fn export_encrypted_bitwarden_json(vault: &Vault, password: &str) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(CipherPassError::CryptoError(
            "An export password is required for encrypted JSON export".into(),
        ));
    }

    let mut folders = Vec::new();
    let mut items = Vec::new();
    collect_groups_for_bw(&vault.root_group, "", true, &mut folders, &mut items);

    let plain = BwPlainExport {
        encrypted: false,
        folders,
        items,
    };
    let plain_bytes = Zeroizing::new(
        serde_json::to_vec(&plain)
            .map_err(|e| CipherPassError::CryptoError(format!("JSON serialize error: {e}")))?,
    );

    let salt_bytes: [u8; 32] = random_bytes();
    let salt_str = base64::engine::general_purpose::STANDARD.encode(salt_bytes);

    let kdf_type = 1u8; // Argon2id
    let kdf_iterations = 3u32;
    let kdf_memory = 64u32;
    let kdf_parallelism = 4u32;

    let (enc_key, mac_key) = derive_bw_stretched_keys(
        password,
        &salt_str,
        kdf_type,
        kdf_iterations,
        Some(kdf_memory),
        Some(kdf_parallelism),
    )?;

    let validation_uuid = uuid::Uuid::new_v4().to_string();
    let enc_key_validation = bw_encrypt_string(validation_uuid.as_bytes(), &enc_key, &mac_key)?;
    let data = bw_encrypt_string(plain_bytes.as_slice(), &enc_key, &mac_key)?;

    let envelope = BwEncryptedExport {
        encrypted: true,
        password_protected: true,
        salt: salt_str,
        kdf_type,
        kdf_iterations,
        kdf_memory,
        kdf_parallelism,
        enc_key_validation,
        data,
    };

    serde_json::to_vec_pretty(&envelope)
        .map_err(|e| CipherPassError::CryptoError(format!("Encrypted JSON serialize error: {e}")))
}

// =========================================================================
// 3. Merge External KeePass (.kdbx) Vault Into Current Vault
// =========================================================================

fn merge_group_recursive(
    source: &VaultGroup,
    target_root: &mut VaultGroup,
    prefix: &str,
    is_root: bool,
    imported_entries: &mut usize,
    created_folders: &mut usize,
) {
    let current_path = if is_root {
        String::new()
    } else if prefix.is_empty() {
        source.name.clone()
    } else {
        format!("{prefix}/{}", source.name)
    };

    if !source.entries.is_empty() {
        let dest = if current_path.is_empty() {
            ensure_folder_path(target_root, "Imported KeePass", created_folders)
        } else {
            ensure_folder_path(target_root, &current_path, created_folders)
        };
        for entry in &source.entries {
            let mut cloned = entry.clone();
            cloned.uuid = uuid::Uuid::new_v4();
            dest.entries.push(cloned);
            *imported_entries += 1;
        }
    } else if !is_root && !current_path.is_empty() {
        let _ = ensure_folder_path(target_root, &current_path, created_folders);
    }

    for sub in &source.subgroups {
        merge_group_recursive(
            sub,
            target_root,
            &current_path,
            false,
            imported_entries,
            created_folders,
        );
    }
}

pub fn merge_kdbx_vault(source: &Vault, target: &mut Vault) -> ImportSummary {
    let mut imported_entries = 0usize;
    let mut created_folders = 0usize;
    merge_group_recursive(
        &source.root_group,
        &mut target.root_group,
        "",
        true,
        &mut imported_entries,
        &mut created_folders,
    );
    ImportSummary {
        source_format: "KeePass KDBX 4".to_string(),
        imported_entries,
        created_folders,
        skipped_items: 0,
    }
}

// =========================================================================
// 4. Import CSV (Bitwarden CSV & KeePass / KeePassXC CSV)
// =========================================================================

fn parse_csv_rows(input: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut current_row = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    current_row.push(std::mem::take(&mut field));
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    current_row.push(std::mem::take(&mut field));
                    if current_row.iter().any(|s| !s.is_empty()) {
                        rows.push(std::mem::take(&mut current_row));
                    } else {
                        current_row.clear();
                    }
                }
                '\n' => {
                    current_row.push(std::mem::take(&mut field));
                    if current_row.iter().any(|s| !s.is_empty()) {
                        rows.push(std::mem::take(&mut current_row));
                    } else {
                        current_row.clear();
                    }
                }
                other => field.push(other),
            }
        }
    }

    if !field.is_empty() || !current_row.is_empty() {
        current_row.push(field);
        if current_row.iter().any(|s| !s.is_empty()) {
            rows.push(current_row);
        }
    }
    rows
}

pub fn import_csv(raw_csv: &str, target_vault: &mut Vault) -> Result<ImportSummary> {
    if raw_csv.len() > MAX_INTERCHANGE_INPUT_BYTES {
        return Err(CipherPassError::MalformedFormat(
            "CSV file exceeds 64 MiB safety limit".into(),
        ));
    }
    let clean = raw_csv.trim_start_matches('\u{feff}');
    let mut rows = parse_csv_rows(clean);
    if rows.len() < 2 {
        for row in &mut rows {
            for cell in row {
                cell.zeroize();
            }
        }
        return Err(CipherPassError::MalformedFormat(
            "CSV file has no data rows".into(),
        ));
    }

    let headers: Vec<String> = rows[0].iter().map(|h| h.trim().to_lowercase()).collect();
    let col = |names: &[&str]| -> Option<usize> {
        headers.iter().position(|h| names.iter().any(|n| h == n))
    };

    let idx_folder = col(&["folder", "group"]);
    let idx_title = col(&["name", "title", "account"]);
    let idx_user = col(&["login_username", "username", "user", "email"]);
    let idx_pass = col(&["login_password", "password"]);
    let idx_url = col(&["login_uri", "url", "website", "web site"]);
    let idx_notes = col(&["notes", "extra", "comments"]);
    let idx_totp = col(&["login_totp", "totp", "otp"]);
    let idx_fav = col(&["favorite"]);
    let idx_type = col(&["type"]);

    if idx_title.is_none() && idx_user.is_none() && idx_pass.is_none() {
        for row in &mut rows {
            for cell in row {
                cell.zeroize();
            }
        }
        return Err(CipherPassError::MalformedFormat(
            "Unrecognized CSV columns (expected Bitwarden or KeePass CSV header)".into(),
        ));
    }

    let mut imported_entries = 0usize;
    let mut created_folders = 0usize;
    let mut skipped_items = 0usize;

    for row in rows.iter().skip(1) {
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| row.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        let title = get(idx_title);
        let username = get(idx_user);
        let password = get(idx_pass);
        let url = get(idx_url);
        let notes = get(idx_notes);
        let totp = get(idx_totp);
        let folder = get(idx_folder);
        let fav = get(idx_fav);
        let item_type = get(idx_type).to_lowercase();

        if title.is_empty() && username.is_empty() && password.is_empty() && notes.is_empty() {
            skipped_items += 1;
            continue;
        }

        let mut entry = VaultEntry::new(if title.is_empty() {
            "(Untitled)".to_string()
        } else {
            title
        });
        entry.username = username;
        entry.password = ProtectedString::new(password);
        entry.url = url;
        entry.notes = notes;
        if !totp.is_empty() {
            entry.set_totp_uri(Some(totp));
        }
        if fav == "1" || fav.eq_ignore_ascii_case("true") {
            entry.set_favorite(true);
        }
        let cp_type = if item_type == "note" { "note" } else { "login" };
        push_cf(&mut entry, "EntryType", cp_type, false);

        let folder_path = if folder.is_empty() {
            "Imported CSV"
        } else {
            folder.as_str()
        };
        let grp = ensure_folder_path(
            &mut target_vault.root_group,
            folder_path,
            &mut created_folders,
        );
        grp.entries.push(entry);
        imported_entries += 1;
    }

    for row in &mut rows {
        for cell in row {
            cell.zeroize();
        }
    }

    Ok(ImportSummary {
        source_format: "CSV (Bitwarden / KeePass)".to_string(),
        imported_entries,
        created_folders,
        skipped_items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{CipherAlgorithm, KdfConfig};

    #[test]
    fn encrypted_json_export_and_reimport_roundtrip() {
        let mut src = Vault::new("Source", CipherAlgorithm::ChaCha20, KdfConfig::default());
        let mut work = VaultGroup::new("Work", 48);
        let mut login = VaultEntry::new("GitHub");
        login.username = "alice@example.com".into();
        login.password = ProtectedString::new("Sup3rS3cret!99");
        login.url = "https://github.com".into();
        login.set_totp_uri(Some("JBSWY3DPEHPK3PXP".into()));
        login.set_favorite(true);
        work.entries.push(login);

        let mut card = VaultEntry::new("Platinum Visa");
        push_cf(&mut card, "EntryType", "card", false);
        push_cf(&mut card, "Cardholder", "Alice Dev", false);
        push_cf(&mut card, "Card Number", "4111 2222 3333 4444", true);
        push_cf(&mut card, "Expiration", "09/29", false);
        push_cf(&mut card, "CVV", "842", true);
        work.entries.push(card);

        src.root_group.subgroups.push(work);

        let encrypted = export_encrypted_bitwarden_json(&src, "ExportPass#2026!").unwrap();

        // Wrong password must fail cleanly
        let mut bad_dst = Vault::new("Bad", CipherAlgorithm::ChaCha20, KdfConfig::default());
        assert!(import_bitwarden_json(&encrypted, Some("WrongPass"), &mut bad_dst).is_err());

        // Correct password decrypts & imports both entries and Work folder
        let mut dst = Vault::new("Target", CipherAlgorithm::ChaCha20, KdfConfig::default());
        let summary =
            import_bitwarden_json(&encrypted, Some("ExportPass#2026!"), &mut dst).unwrap();
        assert_eq!(summary.imported_entries, 2);

        let entries = dst.all_entries();
        assert_eq!(entries.len(), 2);
        let gh = entries.iter().find(|(_, e)| e.title == "GitHub").unwrap().1;
        assert_eq!(gh.password.expose(), "Sup3rS3cret!99");
        assert_eq!(gh.totp_uri().as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert!(gh.is_favorite());

        let visa = entries
            .iter()
            .find(|(_, e)| e.title == "Platinum Visa")
            .unwrap()
            .1;
        assert!(visa
            .custom_fields
            .iter()
            .any(|f| f.key == "Card Number" && f.value.expose() == "4111 2222 3333 4444"));
    }

    #[test]
    fn bitwarden_pbkdf2_encrypted_json_and_csv_import() {
        // Construct a real PBKDF2-HMAC-SHA256 Bitwarden encrypted JSON payload
        let plain_json = r#"{
            "encrypted": false,
            "folders": [{"id": "f1", "name": "Cloud/AWS"}],
            "items": [
                {
                    "id": "i1",
                    "folderId": "f1",
                    "type": 1,
                    "name": "AWS Prod",
                    "favorite": true,
                    "login": {
                        "username": "root@aws.example",
                        "password": "AwsRootPassword#123",
                        "uris": [{"uri": "https://console.aws.amazon.com"}],
                        "totp": "JBSWY3DPEHPK3PXP"
                    }
                }
            ]
        }"#;
        let salt = "test-salt-value";
        let (enc_key, mac_key) =
            derive_bw_stretched_keys("BwPass!42", salt, 0, 1000, None, None).unwrap();
        let val = bw_encrypt_string(b"valid", &enc_key, &mac_key).unwrap();
        let data = bw_encrypt_string(plain_json.as_bytes(), &enc_key, &mac_key).unwrap();
        let env = serde_json::json!({
            "encrypted": true,
            "passwordProtected": true,
            "salt": salt,
            "kdfType": 0,
            "kdfIterations": 1000,
            "encKeyValidation_DO_NOT_EDIT": val,
            "data": data
        });
        let raw = serde_json::to_vec(&env).unwrap();

        let mut vault = Vault::new("Test", CipherAlgorithm::ChaCha20, KdfConfig::default());
        let summary = import_bitwarden_json(&raw, Some("BwPass!42"), &mut vault).unwrap();
        assert_eq!(summary.imported_entries, 1);
        assert_eq!(summary.created_folders, 2); // Cloud + AWS nested

        // Also test CSV import
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nPersonal,1,login,Proton Mail,Backup note,,,https://mail.proton.me,me@proton.me,ProtonPass!77,JBSWY3DPEHPK3PXP\n";
        let csv_summary = import_csv(csv, &mut vault).unwrap();
        assert_eq!(csv_summary.imported_entries, 1);
        assert_eq!(vault.all_entries().len(), 2);
    }
}
