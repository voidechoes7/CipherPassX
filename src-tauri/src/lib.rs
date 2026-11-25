#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
#[cfg(any(target_os = "android", target_os = "ios"))]
use cipherpass_core::crypto::random_bytes;
use cipherpass_core::{
    atomic_write_file, evaluate_password, export_encrypted_bitwarden_json, generate_keyfile_v2_xml,
    generate_mlkem1024_keypair, generate_passphrase, generate_password, generate_totp_now,
    import_bitwarden_json, import_csv, merge_kdbx_vault, open_kdbx_bytes, pq_seal_bytes,
    pq_unseal_bytes, run_vault_audit, save_kdbx_bytes, validate_mlkem1024_key_b64, vault_slot_id,
    CipherAlgorithm, CustomField, EntropyReport, GeneratedSecret, ImportSummary, KdfAlgorithm,
    KdfConfig, MasterCredentials, MlKem1024Keypair, PassphraseGenOptions, PasswordGenOptions,
    ProtectedString, SecurityAuditReport, TotpCode, Vault, VaultEntry, VaultGroup,
};
#[cfg(any(target_os = "android", target_os = "ios"))]
use cipherpass_core::{seal_biometric_slot, unseal_biometric_slot, BiometricVaultCredentials};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_VAULT_FILE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
const MAX_KEYFILE_BYTES: u64 = 1024 * 1024; // 1 MiB
const MAX_PQ_KEY_FILE_BYTES: u64 = 16 * 1024; // 16 KiB

/// Unified cross-platform vault location supporting standard POSIX/Windows paths
/// as well as Android Storage Access Framework (`content://`) and iOS (`file://`) URIs.
#[derive(Clone, Debug)]
enum VaultLocation {
    FileSystem(PathBuf),
    ContentUri(tauri::Url),
}

impl VaultLocation {
    fn display_string(&self) -> String {
        match self {
            Self::FileSystem(p) => p.to_string_lossy().to_string(),
            Self::ContentUri(u) => u.to_string(),
        }
    }
}

fn set_private_dir_permissions(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

fn reject_symlink(path: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(
                "Symbolic links are not permitted for sensitive key/vault paths".to_string(),
            );
        }
    }
    Ok(())
}

/// Core path security validator: blocks NUL bytes, `..` traversal components, and any access
/// targeting the internal `.keystore` directory (checked both lexically and via canonical ancestor).
fn validate_fs_path_against_keystore(
    path: &Path,
    forbidden_keystore_dir: &Path,
) -> Result<(), String> {
    let raw_str = path.to_string_lossy();
    if raw_str.contains('\0') {
        return Err("File path contains invalid NUL byte".to_string());
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err("Path traversal ('..') components are forbidden".to_string());
        }
    }

    // Lexical check against `.keystore`
    if path == forbidden_keystore_dir || path.starts_with(forbidden_keystore_dir) {
        return Err("Access to internal keystore directory is forbidden".to_string());
    }

    // Canonicalized check against nearest existing ancestor (prevents symlink escape into .keystore)
    if let Ok(canonical_ks) = fs::canonicalize(forbidden_keystore_dir) {
        if let Ok(canonical_target) = fs::canonicalize(path) {
            if canonical_target == canonical_ks || canonical_target.starts_with(&canonical_ks) {
                return Err("Access to internal keystore directory is forbidden".to_string());
            }
        } else if let Some(parent) = path.parent() {
            if let Ok(canonical_parent) = fs::canonicalize(parent) {
                if canonical_parent == canonical_ks || canonical_parent.starts_with(&canonical_ks) {
                    return Err("Access to internal keystore directory is forbidden".to_string());
                }
            }
        }
    }

    Ok(())
}

fn validate_safe_fs_path(app: &AppHandle, path: &Path) -> Result<(), String> {
    if let Ok(base) = app.path().app_local_data_dir() {
        let ks = base.join(".keystore");
        validate_fs_path_against_keystore(path, &ks)?;
    } else {
        validate_fs_path_against_keystore(path, Path::new("/.keystore"))?;
    }
    Ok(())
}

fn has_allowed_pq_key_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            ext.eq_ignore_ascii_case("pqkey")
                || ext.eq_ignore_ascii_case("pqpub")
                || ext.eq_ignore_ascii_case("txt")
        })
}

fn default_vaults_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app_local_data_dir: {e}"))?;
    let dir = base.join("vaults");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create vaults directory: {e}"))?;
    set_private_dir_permissions(&dir);
    Ok(dir)
}

fn recent_vaults_file(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app_local_data_dir: {e}"))?;
    fs::create_dir_all(&base).map_err(|e| format!("Failed to create app data dir: {e}"))?;
    Ok(base.join("recent_vaults.json"))
}

fn record_recent_vault(app: &AppHandle, name: &str, path: &str) {
    let Ok(reg_path) = recent_vaults_file(app) else {
        return;
    };
    let mut items: Vec<LocalVaultInfo> = fs::read_to_string(&reg_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    let display_name = if name.trim().is_empty() {
        Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Vault.kdbx")
            .to_string()
    } else {
        name.trim().to_string()
    };

    items.retain(|i| i.path != path);
    let size_bytes = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    items.insert(
        0,
        LocalVaultInfo {
            name: display_name,
            path: path.to_string(),
            size_bytes,
        },
    );
    items.truncate(12);
    if let Ok(json) = serde_json::to_vec_pretty(&items) {
        let _ = atomic_write_file(&reg_path, &json);
    }
}

fn resolve_location(
    app: &AppHandle,
    raw: &str,
    default_ext: &str,
) -> Result<VaultLocation, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("File path cannot be empty".to_string());
    }
    if trimmed.contains('\0') {
        return Err("File path contains invalid NUL byte".to_string());
    }

    if trimmed.starts_with("content://") {
        let url =
            tauri::Url::parse(trimmed).map_err(|e| format!("Invalid Android content URI: {e}"))?;
        return Ok(VaultLocation::ContentUri(url));
    }

    if trimmed.starts_with("file://") {
        let url = tauri::Url::parse(trimmed).map_err(|e| format!("Invalid file URI: {e}"))?;
        if let Ok(path) = url.to_file_path() {
            validate_safe_fs_path(app, &path)?;
            return Ok(VaultLocation::FileSystem(path));
        }
        return Err("Unsupported or invalid file:// URI".to_string());
    }

    let path = PathBuf::from(trimmed);
    validate_safe_fs_path(app, &path)?;

    let needs_local_dir = !path.is_absolute()
        || path
            .parent()
            .is_none_or(|p| p.as_os_str().is_empty() || p == Path::new("/"));

    if needs_local_dir {
        let dir = default_vaults_dir(app)?;
        let mut fname = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("CipherPass")
            .to_string();
        if !fname.ends_with(default_ext) {
            fname.push_str(default_ext);
        }
        let resolved = dir.join(fname);
        validate_safe_fs_path(app, &resolved)?;
        return Ok(VaultLocation::FileSystem(resolved));
    }

    Ok(VaultLocation::FileSystem(path))
}

fn read_bytes_from_location(
    app: &AppHandle,
    loc: &VaultLocation,
    max_bytes: u64,
) -> Result<Vec<u8>, String> {
    match loc {
        VaultLocation::FileSystem(path) => {
            let file = fs::File::open(path).map_err(|e| format!("Failed to read file: {e}"))?;
            let mut bounded = file.take(max_bytes.saturating_add(1));
            let mut buf = Vec::new();
            bounded
                .read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read file: {e}"))?;
            if buf.len() as u64 > max_bytes {
                return Err(format!(
                    "File exceeds maximum allowed size ({} bytes)",
                    max_bytes
                ));
            }
            Ok(buf)
        }
        VaultLocation::ContentUri(url) => {
            let mut opts = OpenOptions::new();
            opts.read(true);
            let file = app
                .fs()
                .open(FilePath::Url(url.clone()), opts)
                .map_err(|e| format!("Failed to open content URI for reading: {e}"))?;
            let mut bounded = file.take(max_bytes.saturating_add(1));
            let mut buf = Vec::new();
            bounded
                .read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read content URI: {e}"))?;
            if buf.len() as u64 > max_bytes {
                return Err(format!(
                    "Content URI exceeds maximum allowed size ({} bytes)",
                    max_bytes
                ));
            }
            Ok(buf)
        }
    }
}

fn read_keyfile_bytes(app: &AppHandle, raw_path: &str) -> Result<Vec<u8>, String> {
    let kf_loc = resolve_location(app, raw_path, ".keyx")?;
    if let VaultLocation::FileSystem(ref p) = kf_loc {
        reject_symlink(p)?;
    }
    read_bytes_from_location(app, &kf_loc, MAX_KEYFILE_BYTES)
}

fn write_bytes_to_location(
    app: &AppHandle,
    loc: &VaultLocation,
    bytes: &[u8],
) -> Result<(), String> {
    match loc {
        VaultLocation::FileSystem(path) => {
            atomic_write_file(path, bytes).map_err(|e| e.to_string())
        }
        VaultLocation::ContentUri(url) => {
            let mut opts = OpenOptions::new();
            opts.write(true).truncate(true);
            let mut file = app
                .fs()
                .open(FilePath::Url(url.clone()), opts)
                .map_err(|e| format!("Failed to open content URI for writing: {e}"))?;
            file.write_all(bytes)
                .map_err(|e| format!("Failed to write content URI: {e}"))?;
            file.flush()
                .map_err(|e| format!("Failed to flush content URI: {e}"))?;
            Ok(())
        }
    }
}

fn persist_session(app: &AppHandle, sess: &mut UnlockedSession) -> Result<(), String> {
    let bytes =
        Zeroizing::new(save_kdbx_bytes(&sess.vault, &sess.credentials).map_err(|e| e.to_string())?);
    write_bytes_to_location(app, &sess.location, bytes.as_slice())?;
    sess.dirty = false;
    Ok(())
}

fn keystore_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app_local_data_dir: {e}"))?;
    let dir = base.join(".keystore");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create keystore directory: {e}"))?;
    set_private_dir_permissions(&dir);
    Ok(dir)
}

#[cfg(target_os = "ios")]
fn load_or_create_device_secret(app: &AppHandle) -> Result<Zeroizing<[u8; 32]>, String> {
    let key_path = keystore_dir(app)?.join("device.key");
    reject_symlink(&key_path)?;
    if key_path.exists() {
        let raw = Zeroizing::new(
            fs::read(&key_path).map_err(|e| format!("Failed to read device key: {e}"))?,
        );
        if raw.len() == 32 {
            let mut arr = Zeroizing::new([0u8; 32]);
            arr.copy_from_slice(raw.as_slice());
            return Ok(arr);
        }
    }
    let fresh = Zeroizing::new(random_bytes::<32>());
    atomic_write_file(&key_path, fresh.as_slice()).map_err(|e| e.to_string())?;
    Ok(fresh)
}

fn biometric_slot_path(app: &AppHandle, canonical_path: &str) -> Result<PathBuf, String> {
    let id = vault_slot_id(canonical_path);
    Ok(keystore_dir(app)?.join(format!("{id}.bio")))
}

fn biometric_hw_key_path(app: &AppHandle, canonical_path: &str) -> Result<PathBuf, String> {
    let id = vault_slot_id(canonical_path);
    Ok(keystore_dir(app)?.join(format!("{id}.biokey")))
}

fn secure_delete_file(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    if reject_symlink(path).is_ok() {
        if let Ok(meta) = fs::metadata(path) {
            let zeros = vec![0u8; (meta.len() as usize).min(1024 * 1024)];
            let _ = fs::write(path, zeros);
        }
    }
    fs::remove_file(path).is_ok()
}

fn wipe_biometric_slot(app: &AppHandle, canonical_path: &str) -> bool {
    let mut removed = false;
    if let Ok(slot_path) = biometric_slot_path(app, canonical_path) {
        removed |= secure_delete_file(&slot_path);
    }
    if let Ok(key_path) = biometric_hw_key_path(app, canonical_path) {
        removed |= secure_delete_file(&key_path);
    }
    removed
}

fn test_dir_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".cp_probe_{}", Uuid::new_v4().simple()));
    match fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

struct UnlockedSession {
    session_id: Uuid,
    vault: Vault,
    credentials: MasterCredentials,
    keyfile_path: Option<String>,
    location: VaultLocation,
    last_activity: Instant,
    dirty: bool,
}

impl UnlockedSession {
    fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AppConfig {
    auto_lock_seconds: u64,       // 0 = disabled, default 300 (5 min)
    clipboard_clear_seconds: u64, // 5..=300, default 30
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_lock_seconds: 300,
            clipboard_clear_seconds: 30,
        }
    }
}

fn app_config_file(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app_local_data_dir: {e}"))?;
    fs::create_dir_all(&base).map_err(|e| format!("Failed to create app data dir: {e}"))?;
    Ok(base.join("app_config.json"))
}

fn load_app_config(app: &AppHandle) -> AppConfig {
    let Ok(path) = app_config_file(app) else {
        return AppConfig::default();
    };
    let mut cfg: AppConfig = fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    cfg.clipboard_clear_seconds = cfg.clipboard_clear_seconds.clamp(5, 300);
    cfg
}

fn save_app_config(app: &AppHandle, cfg: &AppConfig) {
    let Ok(path) = app_config_file(app) else {
        return;
    };
    if let Ok(json) = serde_json::to_string_pretty(cfg) {
        if fs::write(&path, json).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

struct ClipboardTimerState {
    deadline: Option<(Instant, u64)>,
}

struct SharedState {
    session: Mutex<Option<UnlockedSession>>,
    config: Mutex<AppConfig>,
    clipboard_generation: AtomicU64,
    clipboard_timer: Mutex<ClipboardTimerState>,
    clipboard_cv: Condvar,
    failed_unlock_attempts: AtomicU32,
    unlock_in_progress: AtomicBool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            session: Mutex::new(None),
            config: Mutex::new(AppConfig::default()),
            clipboard_generation: AtomicU64::new(0),
            clipboard_timer: Mutex::new(ClipboardTimerState { deadline: None }),
            clipboard_cv: Condvar::new(),
            failed_unlock_attempts: AtomicU32::new(0),
            unlock_in_progress: AtomicBool::new(false),
        }
    }

    fn cancel_clipboard_timer(&self) {
        self.clipboard_generation.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut guard) = self.clipboard_timer.lock() {
            guard.deadline = None;
            self.clipboard_cv.notify_one();
        }
    }

    fn schedule_clipboard_clear(&self, timeout_secs: u64) {
        let gen_id = self.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        if let Ok(mut guard) = self.clipboard_timer.lock() {
            guard.deadline = Some((deadline, gen_id));
            self.clipboard_cv.notify_one();
        }
    }
}

struct UnlockAttemptGuard<'a>(&'a AtomicBool);

impl<'a> UnlockAttemptGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Result<Self, String> {
        if flag
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(
                "Another unlock operation is already in progress. Please wait.".to_string(),
            );
        }
        Ok(Self(flag))
    }
}

impl Drop for UnlockAttemptGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalVaultInfo {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRootDto {
    pub label: String,
    pub path: String,
    pub writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderListingDto {
    pub current_path: String,
    pub parent_path: Option<String>,
    pub writable: bool,
    pub folders: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatusDto {
    pub unlocked: bool,
    pub path: Option<String>,
    pub database_name: Option<String>,
    pub database_description: Option<String>,
    pub cipher: Option<CipherAlgorithm>,
    pub inner_cipher: Option<String>,
    pub kdbx_version: Option<String>,
    pub kdf: Option<KdfConfig>,
    pub has_master_password: bool,
    pub has_keyfile: bool,
    pub keyfile_path: Option<String>,
    pub compression: bool,
    pub pq_armor_available: bool,
    pub recycle_bin_id: Option<String>,
    pub entry_count: usize,
    pub dirty: bool,
    pub auto_lock_seconds: u64,
    pub clipboard_clear_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupDto {
    pub id: String,
    pub name: String,
    pub notes: String,
    pub icon_id: u32,
    pub entry_count: usize,
    pub subgroups: Vec<GroupDto>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomFieldDto {
    pub key: String,
    pub value: String,
    #[zeroize(skip)]
    pub protected: bool,
}

impl std::fmt::Debug for CustomFieldDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomFieldDto")
            .field("key", &self.key)
            .field(
                "value",
                &if self.protected {
                    "[REDACTED]"
                } else {
                    &self.value
                },
            )
            .field("protected", &self.protected)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HistoryItemDto {
    #[zeroize(skip)]
    pub index: usize,
    pub title: String,
    pub username: String,
    pub password: String,
    pub modified_at: String,
}

impl std::fmt::Debug for HistoryItemDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryItemDto")
            .field("index", &self.index)
            .field("title", &self.title)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummaryDto {
    pub id: String,
    pub group_id: String,
    pub entry_type: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub favorite: bool,
    pub has_totp: bool,
    pub tags: Vec<String>,
    pub modified_at: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryDetailDto {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[zeroize(skip)]
    pub favorite: bool,
    pub tags: Vec<String>,
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<CustomFieldDto>,
    pub history: Vec<HistoryItemDto>,
    pub created_at: String,
    pub modified_at: String,
    #[zeroize(skip)]
    pub expires: bool,
    pub expiry_time: String,
}

impl std::fmt::Debug for EntryDetailDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryDetailDto")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("password", &"[REDACTED]")
            .field("notes", &"[REDACTED]")
            .field("totp_uri", &self.totp_uri.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CreateVaultRequest {
    pub path: String,
    pub database_name: String,
    pub master_password: Option<String>,
    pub keyfile_path: Option<String>,
    #[zeroize(skip)]
    pub cipher: CipherAlgorithm,
    #[zeroize(skip)]
    pub kdf_algorithm: KdfAlgorithm,
    #[zeroize(skip)]
    pub memory_mib: u64,
    #[zeroize(skip)]
    pub iterations: u64,
    #[zeroize(skip)]
    pub parallelism: u32,
}

impl std::fmt::Debug for CreateVaultRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateVaultRequest")
            .field("path", &self.path)
            .field("database_name", &self.database_name)
            .field(
                "master_password",
                &self.master_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("keyfile_path", &self.keyfile_path)
            .finish()
    }
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct OpenVaultRequest {
    pub path: String,
    pub master_password: Option<String>,
    pub keyfile_path: Option<String>,
}

impl std::fmt::Debug for OpenVaultRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVaultRequest")
            .field("path", &self.path)
            .field(
                "master_password",
                &self.master_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("keyfile_path", &self.keyfile_path)
            .finish()
    }
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntryUpsertRequest {
    pub id: Option<String>,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    #[zeroize(skip)]
    pub favorite: bool,
    pub tags: Vec<String>,
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<CustomFieldDto>,
    #[zeroize(skip)]
    pub expires: bool,
    pub expiry_time: Option<String>,
}

impl std::fmt::Debug for EntryUpsertRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntryUpsertRequest")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("password", &"[REDACTED]")
            .field("notes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecuritySettingsRequest {
    pub database_name: Option<String>,
    pub database_description: Option<String>,
    pub cipher: Option<CipherAlgorithm>,
    pub kdf: Option<KdfConfig>,
    pub auto_lock_seconds: Option<u64>,
    pub clipboard_clear_seconds: Option<u64>,
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChangeMasterCredentialsRequest {
    pub current_password: Option<String>,
    pub new_password: Option<String>,
    /// "keep" | "set" | "remove"
    pub keyfile_action: String,
    pub new_keyfile_path: Option<String>,
}

impl std::fmt::Debug for ChangeMasterCredentialsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChangeMasterCredentialsRequest")
            .field(
                "current_password",
                &self.current_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "new_password",
                &self.new_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("keyfile_action", &self.keyfile_action)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeCredentialsResultDto {
    pub status: VaultStatusDto,
    pub biometric_reset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqSelfTestResultDto {
    pub passed: bool,
    pub algorithm: String,
    pub public_key_bytes: usize,
    pub secret_key_bytes: usize,
    pub ciphertext_bytes: usize,
    pub elapsed_ms: u64,
    pub fingerprint: String,
}

fn infer_entry_type(e: &VaultEntry) -> String {
    if let Some(explicit) = e
        .custom_fields
        .iter()
        .find(|f| f.key.eq_ignore_ascii_case("EntryType"))
        .map(|f| f.value.expose().trim().to_lowercase())
    {
        if matches!(
            explicit.as_str(),
            "login" | "card" | "totp" | "dev" | "note"
        ) {
            return explicit;
        }
    }

    let has_field = |needle: &str| {
        e.custom_fields
            .iter()
            .any(|f| f.key.eq_ignore_ascii_case(needle))
    };

    if has_field("Card Number") || has_field("CVV") || has_field("IBAN / Account") {
        return "card".to_string();
    }
    if has_field("API Token")
        || has_field("SSH Passphrase")
        || has_field("Private Key")
        || has_field("Public Key")
    {
        return "dev".to_string();
    }
    if e.totp_uri().is_some() && e.password.expose().is_empty() {
        return "totp".to_string();
    }
    if (has_field("Recovery Seed") || !e.notes.trim().is_empty())
        && e.password.expose().is_empty()
        && e.username.trim().is_empty()
        && e.url.trim().is_empty()
    {
        return "note".to_string();
    }
    "login".to_string()
}

fn group_to_dto(g: &VaultGroup) -> GroupDto {
    GroupDto {
        id: g.uuid.to_string(),
        name: g.name.clone(),
        notes: g.notes.clone(),
        icon_id: g.icon_id,
        entry_count: g.entries.len(),
        subgroups: g.subgroups.iter().map(group_to_dto).collect(),
    }
}

fn entry_to_summary(group_id: Uuid, e: &VaultEntry) -> EntrySummaryDto {
    let has_totp = e.totp_uri().map(Zeroizing::new).is_some();
    EntrySummaryDto {
        id: e.uuid.to_string(),
        group_id: group_id.to_string(),
        entry_type: infer_entry_type(e),
        title: e.title.clone(),
        username: e.username.clone(),
        url: e.url.clone(),
        favorite: e.is_favorite(),
        has_totp,
        tags: e.tags.clone(),
        modified_at: e.times.last_modification_time.to_rfc3339(),
    }
}

fn entry_to_detail(group_id: Uuid, e: &VaultEntry) -> EntryDetailDto {
    let totp_uri = e.totp_uri();
    let custom_fields = e
        .custom_fields
        .iter()
        .filter(|f| !f.key.eq_ignore_ascii_case("otp"))
        .map(|f| CustomFieldDto {
            key: f.key.clone(),
            value: f.value.expose().to_string(),
            protected: f.protected,
        })
        .collect();

    let history = e
        .history
        .iter()
        .enumerate()
        .map(|(index, h)| HistoryItemDto {
            index,
            title: h.title.clone(),
            username: h.username.clone(),
            password: h.password.expose().to_string(),
            modified_at: h.times.last_modification_time.to_rfc3339(),
        })
        .collect();

    EntryDetailDto {
        id: e.uuid.to_string(),
        group_id: group_id.to_string(),
        title: e.title.clone(),
        username: e.username.clone(),
        password: e.password.expose().to_string(),
        url: e.url.clone(),
        notes: e.notes.clone(),
        favorite: e.is_favorite(),
        tags: e.tags.clone(),
        totp_uri,
        custom_fields,
        history,
        created_at: e.times.creation_time.to_rfc3339(),
        modified_at: e.times.last_modification_time.to_rfc3339(),
        expires: e.times.expires,
        expiry_time: e.times.expiry_time.to_rfc3339(),
    }
}

#[derive(Clone, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CreateVaultFromImportRequest {
    pub path: String,
    pub database_name: String,
    pub master_password: Option<String>,
    pub keyfile_path: Option<String>,
    #[zeroize(skip)]
    pub cipher: CipherAlgorithm,
    #[zeroize(skip)]
    pub kdf_algorithm: KdfAlgorithm,
    #[zeroize(skip)]
    pub memory_mib: u64,
    #[zeroize(skip)]
    pub iterations: u64,
    #[zeroize(skip)]
    pub parallelism: u32,
    /// "bitwarden_json" | "csv"
    pub import_kind: String,
    pub import_source_path: String,
    pub import_password: Option<String>,
}

impl std::fmt::Debug for CreateVaultFromImportRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateVaultFromImportRequest")
            .field("path", &self.path)
            .field("database_name", &self.database_name)
            .field(
                "master_password",
                &self.master_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("import_kind", &self.import_kind)
            .field(
                "import_password",
                &self.import_password.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVaultFromImportResultDto {
    pub status: VaultStatusDto,
    pub summary: ImportSummary,
}

fn find_recycle_bin_uuid(vault: &Vault) -> Option<Uuid> {
    if !vault.meta.recycle_bin_uuid.is_nil()
        && vault
            .root_group
            .find_group(vault.meta.recycle_bin_uuid)
            .is_some()
    {
        return Some(vault.meta.recycle_bin_uuid);
    }
    vault
        .root_group
        .subgroups
        .iter()
        .find(|g| g.name.eq_ignore_ascii_case("Recycle Bin"))
        .map(|g| g.uuid)
}

fn ensure_recycle_bin(vault: &mut Vault) -> Uuid {
    if let Some(id) = find_recycle_bin_uuid(vault) {
        vault.meta.recycle_bin_uuid = id;
        return id;
    }
    let trash = VaultGroup::new("Recycle Bin", 43);
    let id = trash.uuid;
    vault.root_group.subgroups.push(trash);
    vault.meta.recycle_bin_uuid = id;
    vault.meta.recycle_bin_enabled = true;
    id
}

fn build_status(state: &SharedState) -> Result<VaultStatusDto, String> {
    let cfg = state.config.lock().map_err(|e| e.to_string())?;
    let sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    if let Some(ref sess) = *sess_guard {
        let rb_id = find_recycle_bin_uuid(&sess.vault);
        let active_count = sess
            .vault
            .all_entries()
            .into_iter()
            .filter(|(gid, _)| rb_id.is_none_or(|rb| *gid != rb))
            .count();
        Ok(VaultStatusDto {
            unlocked: true,
            path: Some(sess.location.display_string()),
            database_name: Some(sess.vault.meta.database_name.clone()),
            database_description: Some(sess.vault.meta.database_description.clone()),
            cipher: Some(sess.vault.cipher),
            inner_cipher: Some("ChaCha20 (256-bit)".to_string()),
            kdbx_version: Some(format!("KDBX 4.{}", sess.vault.version_minor)),
            kdf: Some(sess.vault.kdf.clone()),
            has_master_password: sess
                .credentials
                .password
                .as_ref()
                .is_some_and(|p| !p.is_empty()),
            has_keyfile: sess.credentials.keyfile_bytes.is_some(),
            keyfile_path: sess.keyfile_path.clone(),
            compression: sess.vault.compression,
            pq_armor_available: true,
            recycle_bin_id: rb_id.map(|u| u.to_string()),
            entry_count: active_count,
            dirty: sess.dirty,
            auto_lock_seconds: cfg.auto_lock_seconds,
            clipboard_clear_seconds: cfg.clipboard_clear_seconds,
        })
    } else {
        Ok(VaultStatusDto {
            unlocked: false,
            path: None,
            database_name: None,
            database_description: None,
            cipher: None,
            inner_cipher: None,
            kdbx_version: None,
            kdf: None,
            has_master_password: false,
            has_keyfile: false,
            keyfile_path: None,
            compression: true,
            pq_armor_available: true,
            recycle_bin_id: None,
            entry_count: 0,
            dirty: false,
            auto_lock_seconds: cfg.auto_lock_seconds,
            clipboard_clear_seconds: cfg.clipboard_clear_seconds,
        })
    }
}

#[tauri::command]
fn get_default_vault_dir(app: AppHandle) -> Result<String, String> {
    Ok(default_vaults_dir(&app)?.to_string_lossy().to_string())
}

#[tauri::command]
fn get_storage_roots(app: AppHandle) -> Result<Vec<StorageRootDto>, String> {
    let mut roots = Vec::new();

    if let Ok(app_dir) = default_vaults_dir(&app) {
        roots.push(StorageRootDto {
            label: "App Private Vaults (Recommended)".to_string(),
            path: app_dir.to_string_lossy().to_string(),
            writable: test_dir_writable(&app_dir),
        });
    }

    #[cfg(target_os = "android")]
    {
        for (label, p) in [
            (
                "Internal Storage (/storage/emulated/0)",
                "/storage/emulated/0",
            ),
            ("Documents", "/storage/emulated/0/Documents"),
            ("Download", "/storage/emulated/0/Download"),
        ] {
            let pb = PathBuf::from(p);
            if pb.exists() || p == "/storage/emulated/0" {
                roots.push(StorageRootDto {
                    label: label.to_string(),
                    path: p.to_string(),
                    writable: test_dir_writable(&pb),
                });
            }
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        if let Ok(doc) = app.path().document_dir() {
            if doc.exists() {
                roots.push(StorageRootDto {
                    label: "Documents".to_string(),
                    path: doc.to_string_lossy().to_string(),
                    writable: test_dir_writable(&doc),
                });
            }
        }
        if let Ok(dl) = app.path().download_dir() {
            if dl.exists() {
                roots.push(StorageRootDto {
                    label: "Downloads".to_string(),
                    path: dl.to_string_lossy().to_string(),
                    writable: test_dir_writable(&dl),
                });
            }
        }
        if let Ok(home) = app.path().home_dir() {
            if home.exists() {
                roots.push(StorageRootDto {
                    label: "Home Folder".to_string(),
                    path: home.to_string_lossy().to_string(),
                    writable: test_dir_writable(&home),
                });
            }
        }
    }

    Ok(roots)
}

#[tauri::command]
fn list_directory_folders(path: String, app: AppHandle) -> FolderListingDto {
    let trimmed = path.trim();
    let pb = PathBuf::from(trimmed);
    if let Err(err) = validate_safe_fs_path(&app, &pb) {
        return FolderListingDto {
            current_path: trimmed.to_string(),
            parent_path: None,
            writable: false,
            folders: Vec::new(),
            error: Some(err),
        };
    }

    #[cfg(target_os = "android")]
    let at_android_storage_root = trimmed.trim_end_matches('/') == "/storage/emulated/0";
    #[cfg(not(target_os = "android"))]
    let at_android_storage_root = false;

    let parent_path = if at_android_storage_root {
        None
    } else {
        pb.parent().and_then(|p| {
            let s = p.to_string_lossy().to_string();
            if s.is_empty() || s == trimmed {
                None
            } else {
                Some(s)
            }
        })
    };

    let writable = test_dir_writable(&pb);
    match fs::read_dir(&pb) {
        Ok(rd) => {
            let mut folders = Vec::new();
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        if !name.starts_with('.') {
                            folders.push(name.to_string());
                        }
                    }
                }
            }
            folders.sort_by_key(|a| a.to_lowercase());
            FolderListingDto {
                current_path: pb.to_string_lossy().to_string(),
                parent_path,
                writable,
                folders,
                error: None,
            }
        }
        Err(e) => FolderListingDto {
            current_path: pb.to_string_lossy().to_string(),
            parent_path,
            writable,
            folders: Vec::new(),
            error: Some(format!(
                "Cannot list this folder ({e}). On Android 11+, grant 'All files access' to CipherPass in Android Settings or use 'System Save As'."
            )),
        },
    }
}

#[tauri::command]
fn create_directory(
    parent_path: String,
    folder_name: String,
    app: AppHandle,
) -> Result<String, String> {
    let parent = PathBuf::from(parent_path.trim());
    validate_safe_fs_path(&app, &parent)?;

    let clean: String = folder_name
        .trim()
        .chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\' && *c != '\0')
        .collect::<String>()
        .trim_matches('.')
        .to_string();
    if clean.is_empty() || clean == "." || clean == ".." {
        return Err("Folder name cannot be empty".to_string());
    }
    let target = parent.join(&clean);
    validate_safe_fs_path(&app, &target)?;
    fs::create_dir_all(&target).map_err(|e| format!("Failed to create folder: {e}"))?;
    Ok(target.to_string_lossy().to_string())
}

#[tauri::command]
fn list_local_vaults(app: AppHandle) -> Result<Vec<LocalVaultInfo>, String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // 1. Recent vaults (any folder on phone/PC or content:// URI)
    if let Ok(reg_path) = recent_vaults_file(&app) {
        if let Ok(raw) = fs::read_to_string(&reg_path) {
            if let Ok(recent) = serde_json::from_str::<Vec<LocalVaultInfo>>(&raw) {
                for item in recent {
                    let exists =
                        item.path.starts_with("content://") || Path::new(&item.path).exists();
                    if exists && seen.insert(item.path.clone()) {
                        out.push(item);
                    }
                }
            }
        }
    }

    // 2. Vaults in app private vaults folder
    let dir = default_vaults_dir(&app)?;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("kdbx"))
            {
                let path_str = path.to_string_lossy().to_string();
                if seen.insert(path_str.clone()) {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("vault.kdbx")
                        .to_string();
                    let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    out.push(LocalVaultInfo {
                        name,
                        path: path_str,
                        size_bytes,
                    });
                }
            }
        }
    }
    Ok(out)
}

#[tauri::command]
fn get_vault_status(state: State<'_, Arc<SharedState>>) -> Result<VaultStatusDto, String> {
    build_status(&state)
}

#[tauri::command]
async fn create_vault(
    req: CreateVaultRequest,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    let kdf = KdfConfig {
        algorithm: req.kdf_algorithm,
        memory_mib: req.memory_mib,
        iterations: req.iterations,
        parallelism: req.parallelism,
        version: 0x13,
    };
    kdf.validate_safe_floor().map_err(|e| e.to_string())?;

    let saved_kf_path = req
        .keyfile_path
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let keyfile_bytes = match saved_kf_path {
        Some(ref p) => Some(read_keyfile_bytes(&app, p)?),
        None => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password.clone(), keyfile_bytes)
            .map_err(|e| e.to_string())?;

    let location = resolve_location(&app, &req.path, ".kdbx")?;
    let db_name = req.database_name.clone();
    let cipher = req.cipher;

    // Run Argon2id + KDBX 4 encryption off the UI thread to prevent Android ANRs
    let (vault, credentials, bytes) = tauri::async_runtime::spawn_blocking(move || {
        let vault = Vault::new(db_name, cipher, kdf);
        let bytes =
            Zeroizing::new(save_kdbx_bytes(&vault, &credentials).map_err(|e| e.to_string())?);
        Ok::<_, String>((vault, credentials, bytes))
    })
    .await
    .map_err(|e| format!("Background crypto task failed: {e}"))??;

    write_bytes_to_location(&app, &location, bytes.as_slice())?;
    record_recent_vault(&app, &vault.meta.database_name, &location.display_string());

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if let Some(mut old) = sess_guard.take() {
            old.vault.zeroize_secrets();
        }
        *sess_guard = Some(UnlockedSession {
            session_id: Uuid::new_v4(),
            vault,
            credentials,
            keyfile_path: saved_kf_path,
            location,
            last_activity: Instant::now(),
            dirty: false,
        });
    }

    build_status(&state)
}

#[tauri::command]
async fn open_vault(
    req: OpenVaultRequest,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    let _unlock_guard = UnlockAttemptGuard::acquire(&state.unlock_in_progress)?;

    let failures = state.failed_unlock_attempts.load(Ordering::SeqCst);
    if failures > 0 {
        let backoff_secs = (1u64 << (failures.saturating_sub(1).min(4))).min(15);
        tauri::async_runtime::spawn_blocking(move || {
            std::thread::sleep(Duration::from_secs(backoff_secs));
        })
        .await
        .map_err(|e| e.to_string())?;
    }

    let saved_kf_path = req
        .keyfile_path
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let keyfile_bytes = match saved_kf_path {
        Some(ref p) => Some(read_keyfile_bytes(&app, p)?),
        None => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password.clone(), keyfile_bytes)
            .map_err(|e| e.to_string())?;

    let location = resolve_location(&app, &req.path, ".kdbx")?;
    let raw_bytes = read_bytes_from_location(&app, &location, MAX_VAULT_FILE_BYTES)?;

    let res = tauri::async_runtime::spawn_blocking(move || {
        let vault = open_kdbx_bytes(&raw_bytes, &credentials).map_err(|e| e.to_string())?;
        Ok::<_, String>((vault, credentials))
    })
    .await
    .map_err(|e| format!("Background crypto task failed: {e}"))?;

    let (vault, credentials) = match res {
        Ok(pair) => {
            state.failed_unlock_attempts.store(0, Ordering::SeqCst);
            pair
        }
        Err(e) => {
            state.failed_unlock_attempts.fetch_add(1, Ordering::SeqCst);
            return Err(e);
        }
    };

    record_recent_vault(&app, &vault.meta.database_name, &location.display_string());

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if let Some(mut old) = sess_guard.take() {
            old.vault.zeroize_secrets();
        }
        *sess_guard = Some(UnlockedSession {
            session_id: Uuid::new_v4(),
            vault,
            credentials,
            keyfile_path: saved_kf_path,
            location,
            last_activity: Instant::now(),
            dirty: false,
        });
    }

    build_status(&state)
}

#[tauri::command]
fn lock_vault(
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if let Some(mut sess) = sess_guard.take() {
            sess.vault.zeroize_secrets();
        }
    }
    state.cancel_clipboard_timer();
    let _ = app.clipboard().clear();
    build_status(&state)
}

#[tauri::command]
fn save_vault(
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        persist_session(&app, sess)?;
    }
    build_status(&state)
}

#[tauri::command]
fn move_vault_to_path(
    dest_path: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    let new_loc = resolve_location(&app, &dest_path, ".kdbx")?;
    let new_canonical = new_loc.display_string();

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();

        let old_canonical = sess.location.display_string();
        let bytes = Zeroizing::new(
            save_kdbx_bytes(&sess.vault, &sess.credentials).map_err(|e| e.to_string())?,
        );
        write_bytes_to_location(&app, &new_loc, bytes.as_slice())?;

        // Always wipe the old biometric keyslot so moving the vault does not leave orphaned
        // encrypted credentials behind on disk.
        let had_old_slot = if old_canonical != new_canonical {
            wipe_biometric_slot(&app, &old_canonical)
        } else {
            false
        };

        // On iOS, re-bind the biometric slot under the new path; on Android, hardware
        // BiometricPrompt CryptoObject requires interactive user confirmation to re-enroll.
        #[cfg(target_os = "ios")]
        if had_old_slot {
            let bio_creds = BiometricVaultCredentials {
                master_password: sess.credentials.password.clone(),
                keyfile_path: sess.keyfile_path.clone(),
            };
            if let Ok(device_secret) = load_or_create_device_secret(&app) {
                let new_id = vault_slot_id(&new_canonical);
                if let Ok(sealed) = seal_biometric_slot(&bio_creds, &device_secret, &new_id) {
                    if let Ok(new_slot) = biometric_slot_path(&app, &new_canonical) {
                        let _ = atomic_write_file(&new_slot, &sealed);
                    }
                }
            }
        }
        #[cfg(not(target_os = "ios"))]
        let _ = had_old_slot;

        sess.location = new_loc;
        sess.dirty = false;
        record_recent_vault(&app, &sess.vault.meta.database_name, &new_canonical);
    }

    build_status(&state)
}

#[tauri::command]
fn generate_keyfile_to_path(path: String, app: AppHandle) -> Result<String, String> {
    let xml = generate_keyfile_v2_xml();
    let loc = resolve_location(&app, &path, ".keyx")?;
    write_bytes_to_location(&app, &loc, xml.as_bytes())?;
    Ok(loc.display_string())
}

#[tauri::command]
fn list_groups(state: State<'_, Arc<SharedState>>) -> Result<GroupDto, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();
    Ok(group_to_dto(&sess.vault.root_group))
}

#[tauri::command]
fn create_group(
    parent_id: String,
    name: String,
    icon_id: Option<u32>,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<GroupDto, String> {
    let parent_uuid = Uuid::parse_str(&parent_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let parent = sess
        .vault
        .root_group
        .find_group_mut(parent_uuid)
        .ok_or_else(|| "Parent group not found".to_string())?;
    let new_group = VaultGroup::new(name, icon_id.unwrap_or(48));
    let dto = group_to_dto(&new_group);
    parent.subgroups.push(new_group);
    sess.dirty = true;
    persist_session(&app, sess)?;
    Ok(dto)
}

#[tauri::command]
fn delete_group(
    group_id: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<(), String> {
    let uuid = Uuid::parse_str(&group_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();
    if sess.vault.root_group.uuid == uuid {
        return Err("Cannot delete root group".to_string());
    }
    let mut removed = sess
        .vault
        .root_group
        .remove_subgroup(uuid)
        .ok_or_else(|| "Group not found".to_string())?;
    removed.zeroize_secrets();
    persist_session(&app, sess)?;
    Ok(())
}

#[tauri::command]
fn rename_group(
    group_id: String,
    name: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<GroupDto, String> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err("Folder name cannot be empty".to_string());
    }
    let uuid = Uuid::parse_str(&group_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();
    if sess.vault.root_group.uuid == uuid {
        return Err("Rename the vault itself in Settings → Vault & Key".to_string());
    }
    let grp = sess
        .vault
        .root_group
        .find_group_mut(uuid)
        .ok_or_else(|| "Group not found".to_string())?;
    grp.name = clean.to_string();
    grp.times.last_modification_time = Utc::now();
    let dto = group_to_dto(grp);
    sess.dirty = true;
    persist_session(&app, sess)?;
    Ok(dto)
}

#[tauri::command]
fn clear_recent_vaults(app: AppHandle) -> Result<(), String> {
    if let Ok(reg_path) = recent_vaults_file(&app) {
        if reg_path.exists() {
            let _ = fs::remove_file(&reg_path);
        }
    }
    Ok(())
}

#[tauri::command]
async fn import_bitwarden_json_file(
    src_path: String,
    export_password: Option<String>,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<ImportSummary, String> {
    let export_password = export_password.map(Zeroizing::new);
    let src_loc = resolve_location(&app, &src_path, ".json")?;
    let raw = Zeroizing::new(read_bytes_from_location(
        &app,
        &src_loc,
        MAX_VAULT_FILE_BYTES,
    )?);

    let (expected_sid, mut vault_clone, creds_clone, loc_clone) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault must be unlocked to import".to_string())?;
        sess.touch();
        (
            sess.session_id,
            sess.vault.clone(),
            MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            },
            sess.location.clone(),
        )
    };

    let (mut updated_vault, summary, saved_bytes) =
        tauri::async_runtime::spawn_blocking(move || {
            let summary = import_bitwarden_json(
                raw.as_slice(),
                export_password.as_deref().map(|z| z.as_str()),
                &mut vault_clone,
            )
            .map_err(|e| e.to_string())?;
            let saved = Zeroizing::new(
                save_kdbx_bytes(&vault_clone, &creds_clone).map_err(|e| e.to_string())?,
            );
            Ok::<_, String>((vault_clone, summary, saved))
        })
        .await
        .map_err(|e| format!("Import task failed: {e}"))??;

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let Some(ref mut sess) = *sess_guard else {
            updated_vault.zeroize_secrets();
            return Err("Vault was locked during import operation".to_string());
        };
        if sess.session_id != expected_sid {
            updated_vault.zeroize_secrets();
            return Err("Active vault session changed during import operation".to_string());
        }
        write_bytes_to_location(&app, &loc_clone, saved_bytes.as_slice())?;
        sess.vault.zeroize_secrets();
        sess.vault = updated_vault;
        sess.dirty = false;
    }

    Ok(summary)
}

#[tauri::command]
async fn import_csv_file(
    src_path: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<ImportSummary, String> {
    let src_loc = resolve_location(&app, &src_path, ".csv")?;
    let raw = read_bytes_from_location(&app, &src_loc, MAX_VAULT_FILE_BYTES)?;
    let csv_text = Zeroizing::new(String::from_utf8(raw).map_err(|e| {
        let mut bad = e.into_bytes();
        bad.zeroize();
        "CSV file must be valid UTF-8 text".to_string()
    })?);

    let (expected_sid, mut vault_clone, creds_clone, loc_clone) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault must be unlocked to import".to_string())?;
        sess.touch();
        (
            sess.session_id,
            sess.vault.clone(),
            MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            },
            sess.location.clone(),
        )
    };

    let (mut updated_vault, summary, saved_bytes) =
        tauri::async_runtime::spawn_blocking(move || {
            let summary =
                import_csv(csv_text.as_str(), &mut vault_clone).map_err(|e| e.to_string())?;
            let saved = Zeroizing::new(
                save_kdbx_bytes(&vault_clone, &creds_clone).map_err(|e| e.to_string())?,
            );
            Ok::<_, String>((vault_clone, summary, saved))
        })
        .await
        .map_err(|e| format!("CSV import task failed: {e}"))??;

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let Some(ref mut sess) = *sess_guard else {
            updated_vault.zeroize_secrets();
            return Err("Vault was locked during CSV import operation".to_string());
        };
        if sess.session_id != expected_sid {
            updated_vault.zeroize_secrets();
            return Err("Active vault session changed during CSV import operation".to_string());
        }
        write_bytes_to_location(&app, &loc_clone, saved_bytes.as_slice())?;
        sess.vault.zeroize_secrets();
        sess.vault = updated_vault;
        sess.dirty = false;
    }

    Ok(summary)
}

#[tauri::command]
async fn import_kdbx_into_vault(
    src_path: String,
    master_password: Option<String>,
    keyfile_path: Option<String>,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<ImportSummary, String> {
    let master_password = master_password.map(Zeroizing::new);
    let src_loc = resolve_location(&app, &src_path, ".kdbx")?;
    let raw_kdbx = read_bytes_from_location(&app, &src_loc, MAX_VAULT_FILE_BYTES)?;

    let keyfile_bytes = match keyfile_path
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        Some(p) => Some(read_keyfile_bytes(&app, p)?),
        None => None,
    };
    let src_creds = MasterCredentials::from_password_and_keyfile(
        master_password.as_deref().map(|z| z.to_string()),
        keyfile_bytes,
    )
    .map_err(|e| e.to_string())?;

    let (expected_sid, mut vault_clone, creds_clone, loc_clone) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault must be unlocked to import".to_string())?;
        sess.touch();
        (
            sess.session_id,
            sess.vault.clone(),
            MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            },
            sess.location.clone(),
        )
    };

    let (mut updated_vault, summary, saved_bytes) =
        tauri::async_runtime::spawn_blocking(move || {
            let mut source_vault =
                open_kdbx_bytes(&raw_kdbx, &src_creds).map_err(|e| e.to_string())?;
            let summary = merge_kdbx_vault(&source_vault, &mut vault_clone);
            source_vault.zeroize_secrets();
            let saved = Zeroizing::new(
                save_kdbx_bytes(&vault_clone, &creds_clone).map_err(|e| e.to_string())?,
            );
            Ok::<_, String>((vault_clone, summary, saved))
        })
        .await
        .map_err(|e| format!("KDBX import task failed: {e}"))??;

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let Some(ref mut sess) = *sess_guard else {
            updated_vault.zeroize_secrets();
            return Err("Vault was locked during KDBX import operation".to_string());
        };
        if sess.session_id != expected_sid {
            updated_vault.zeroize_secrets();
            return Err("Active vault session changed during KDBX import operation".to_string());
        }
        write_bytes_to_location(&app, &loc_clone, saved_bytes.as_slice())?;
        sess.vault.zeroize_secrets();
        sess.vault = updated_vault;
        sess.dirty = false;
    }

    Ok(summary)
}

#[tauri::command]
async fn export_encrypted_json_file(
    dest_path: String,
    export_password: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<String, String> {
    let export_password = Zeroizing::new(export_password);
    let (expected_sid, vault_clone) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        (sess.session_id, sess.vault.clone())
    };

    let loc = resolve_location(&app, &dest_path, ".json")?;
    let json_bytes = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = vault_clone;
        let res = export_encrypted_bitwarden_json(&vault, export_password.as_str())
            .map_err(|e| e.to_string());
        vault.zeroize_secrets();
        res
    })
    .await
    .map_err(|e| format!("Encrypted JSON export task failed: {e}"))??;

    {
        let sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if sess_guard
            .as_ref()
            .is_none_or(|s| s.session_id != expected_sid)
        {
            return Err("Vault was locked or changed during export".to_string());
        }
    }

    write_bytes_to_location(&app, &loc, &json_bytes)?;
    Ok(loc.display_string())
}

#[tauri::command]
fn list_entries(
    group_id: Option<String>,
    query: Option<String>,
    favorites_only: Option<bool>,
    totp_only: Option<bool>,
    state: State<'_, Arc<SharedState>>,
) -> Result<Vec<EntrySummaryDto>, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let rb_id = find_recycle_bin_uuid(&sess.vault);
    let raw_entries: Vec<(Uuid, &VaultEntry)> = if let Some(ref gid_str) = group_id {
        let gid = Uuid::parse_str(gid_str).map_err(|e| e.to_string())?;
        let grp = sess
            .vault
            .root_group
            .find_group(gid)
            .ok_or_else(|| "Group not found".to_string())?;
        let mut out = Vec::new();
        grp.collect_all_entries(&mut out);
        out
    } else {
        sess.vault
            .all_entries()
            .into_iter()
            .filter(|(gid, _)| rb_id.is_none_or(|rb| *gid != rb))
            .collect()
    };

    let q_lower = query.unwrap_or_default().trim().to_lowercase();
    let fav_only = favorites_only.unwrap_or(false);
    let otp_only = totp_only.unwrap_or(false);

    let mut result: Vec<EntrySummaryDto> = raw_entries
        .into_iter()
        .filter(|(_, e)| e.matches_query(&q_lower))
        .filter(|(_, e)| !fav_only || e.is_favorite())
        .filter(|(_, e)| !otp_only || e.totp_uri().map(Zeroizing::new).is_some())
        .map(|(gid, e)| entry_to_summary(gid, e))
        .collect();

    result.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
    });

    Ok(result)
}

#[tauri::command]
fn get_entry(
    entry_id: String,
    state: State<'_, Arc<SharedState>>,
) -> Result<EntryDetailDto, String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let (gid, entry) = sess
        .vault
        .root_group
        .find_entry(uuid)
        .ok_or_else(|| "Entry not found".to_string())?;
    Ok(entry_to_detail(gid, entry))
}

#[tauri::command]
fn copy_entry_password(
    entry_id: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<u64, String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let secret = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        let (_, entry) = sess
            .vault
            .root_group
            .find_entry(uuid)
            .ok_or_else(|| "Entry not found".to_string())?;
        let pw = entry.password.expose();
        if pw.is_empty() {
            return Err("No password stored on this entry".to_string());
        }
        Zeroizing::new(pw.to_string())
    };
    copy_secret_with_auto_clear(secret.to_string(), None, app, state)
}

#[tauri::command]
fn upsert_entry(
    req: EntryUpsertRequest,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<EntryDetailDto, String> {
    let target_gid = Uuid::parse_str(&req.group_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    // Validate destination group upfront so moving an entry to an invalid group ID
    // can never silently remove/lose the entry.
    if sess.vault.root_group.find_group(target_gid).is_none() {
        return Err("Target group not found".to_string());
    }

    let history_max = sess.vault.meta.history_max_items;
    let now = Utc::now();

    let detail = if let Some(ref existing_id) = req.id {
        let entry_uuid = Uuid::parse_str(existing_id).map_err(|e| e.to_string())?;
        let (current_gid, entry) = sess
            .vault
            .root_group
            .find_entry_mut(entry_uuid)
            .ok_or_else(|| "Entry not found".to_string())?;

        entry.push_history_snapshot(history_max);

        entry.title = req.title.clone();
        entry.username = req.username.clone();
        entry.password = ProtectedString::new(req.password.clone());
        entry.url = req.url.clone();
        entry.notes = req.notes.clone();
        entry.tags = req.tags.clone();
        entry.set_favorite(req.favorite);
        entry.custom_fields = req
            .custom_fields
            .iter()
            .map(|cf| CustomField {
                key: cf.key.clone(),
                value: ProtectedString::new(cf.value.clone()),
                protected: cf.protected,
            })
            .collect();
        entry.set_totp_uri(req.totp_uri.clone());
        entry.times.last_modification_time = now;
        entry.times.expires = req.expires;
        if let Some(ref exp_str) = req.expiry_time {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                entry.times.expiry_time = dt.with_timezone(&Utc);
            }
        }

        let moved = current_gid != target_gid;
        let dto = entry_to_detail(target_gid, entry);

        if moved {
            if let Some(removed) = sess.vault.root_group.remove_entry(entry_uuid) {
                if let Some(dest) = sess.vault.root_group.find_group_mut(target_gid) {
                    dest.entries.push(removed);
                }
            }
        }
        dto
    } else {
        let mut entry = VaultEntry::new(req.title.clone());
        entry.username = req.username.clone();
        entry.password = ProtectedString::new(req.password.clone());
        entry.url = req.url.clone();
        entry.notes = req.notes.clone();
        entry.tags = req.tags.clone();
        entry.set_favorite(req.favorite);
        entry.custom_fields = req
            .custom_fields
            .iter()
            .map(|cf| CustomField {
                key: cf.key.clone(),
                value: ProtectedString::new(cf.value.clone()),
                protected: cf.protected,
            })
            .collect();
        entry.set_totp_uri(req.totp_uri.clone());
        entry.times.expires = req.expires;
        if let Some(ref exp_str) = req.expiry_time {
            if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(exp_str) {
                entry.times.expiry_time = dt.with_timezone(&Utc);
            }
        }

        let dto = entry_to_detail(target_gid, &entry);
        let grp = sess
            .vault
            .root_group
            .find_group_mut(target_gid)
            .ok_or_else(|| "Target group not found".to_string())?;
        grp.entries.push(entry);
        dto
    };

    persist_session(&app, sess)?;
    Ok(detail)
}

#[tauri::command]
fn delete_entry(
    entry_id: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<bool, String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let rb_existing = find_recycle_bin_uuid(&sess.vault);
    let in_recycle_bin = sess
        .vault
        .root_group
        .find_entry(uuid)
        .is_some_and(|(gid, _)| rb_existing == Some(gid));

    let mut removed = sess
        .vault
        .root_group
        .remove_entry(uuid)
        .ok_or_else(|| "Entry not found".to_string())?;

    let permanently_deleted = if in_recycle_bin || !sess.vault.meta.recycle_bin_enabled {
        removed.zeroize_secrets();
        sess.vault
            .deleted_objects
            .push(cipherpass_core::DeletedObject {
                uuid,
                deletion_time: Utc::now(),
            });
        true
    } else {
        let rb_id = ensure_recycle_bin(&mut sess.vault);
        removed.times.location_changed = Utc::now();
        if let Some(rb) = sess.vault.root_group.find_group_mut(rb_id) {
            rb.entries.push(removed);
        }
        false
    };

    persist_session(&app, sess)?;
    Ok(permanently_deleted)
}

#[tauri::command]
fn restore_entry(
    entry_id: String,
    target_group_id: Option<String>,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<EntryDetailDto, String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let rb_id = find_recycle_bin_uuid(&sess.vault);
    let mut entry = sess
        .vault
        .root_group
        .remove_entry(uuid)
        .ok_or_else(|| "Entry not found".to_string())?;

    let dest_gid = target_group_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .filter(|id| rb_id != Some(*id))
        .or_else(|| {
            sess.vault
                .root_group
                .subgroups
                .iter()
                .find(|g| g.name.eq_ignore_ascii_case("General") && rb_id != Some(g.uuid))
                .map(|g| g.uuid)
        })
        .or_else(|| {
            sess.vault
                .root_group
                .subgroups
                .iter()
                .find(|g| rb_id != Some(g.uuid))
                .map(|g| g.uuid)
        })
        .unwrap_or(sess.vault.root_group.uuid);

    entry.times.location_changed = Utc::now();
    let dto = entry_to_detail(dest_gid, &entry);
    if let Some(grp) = sess.vault.root_group.find_group_mut(dest_gid) {
        grp.entries.push(entry);
    }
    persist_session(&app, sess)?;
    Ok(dto)
}

#[tauri::command]
fn empty_recycle_bin(app: AppHandle, state: State<'_, Arc<SharedState>>) -> Result<usize, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let Some(rb_id) = find_recycle_bin_uuid(&sess.vault) else {
        return Ok(0);
    };

    let mut count = 0usize;
    let mut deleted_ids = Vec::new();
    if let Some(rb) = sess.vault.root_group.find_group_mut(rb_id) {
        for mut e in rb.entries.drain(..) {
            deleted_ids.push(e.uuid);
            e.zeroize_secrets();
            count += 1;
        }
        for mut sub in rb.subgroups.drain(..) {
            sub.zeroize_secrets();
        }
    }
    for id in deleted_ids {
        sess.vault
            .deleted_objects
            .push(cipherpass_core::DeletedObject {
                uuid: id,
                deletion_time: Utc::now(),
            });
    }

    if count > 0 {
        persist_session(&app, sess)?;
    }
    Ok(count)
}

/// Strictly restricted to writing validated NIST FIPS 203 ML-KEM-1024 key files
/// (`.pqpub`, `.pqkey`, `.txt`) up to 16 KiB — prevents arbitrary file overwrite from WebView IPC.
#[tauri::command]
fn write_text_file(path: String, content: String, app: AppHandle) -> Result<String, String> {
    let content = Zeroizing::new(content);
    if content.len() as u64 > MAX_PQ_KEY_FILE_BYTES {
        return Err("Key file content exceeds maximum allowed size (16 KiB)".to_string());
    }
    validate_mlkem1024_key_b64(content.as_str())
        .map_err(|e| format!("Refusing to write non-ML-KEM-1024 key payload: {e}"))?;

    let loc = resolve_location(&app, &path, ".pqkey")?;
    if let VaultLocation::FileSystem(ref p) = loc {
        if !has_allowed_pq_key_extension(p) {
            return Err(
                "Only .pqpub, .pqkey, or .txt key files are permitted for write_text_file"
                    .to_string(),
            );
        }
        reject_symlink(p)?;
    }
    write_bytes_to_location(&app, &loc, content.as_bytes())?;
    Ok(loc.display_string())
}

/// Strictly restricted to reading validated NIST FIPS 203 ML-KEM-1024 key files
/// (`.pqpub`, `.pqkey`, `.txt`) up to 16 KiB — prevents arbitrary file exfiltration from WebView IPC.
#[tauri::command]
fn read_text_file(path: String, app: AppHandle) -> Result<String, String> {
    let loc = resolve_location(&app, &path, ".pqkey")?;
    if let VaultLocation::FileSystem(ref p) = loc {
        if !has_allowed_pq_key_extension(p) {
            return Err(
                "Only .pqpub, .pqkey, or .txt key files are permitted for read_text_file"
                    .to_string(),
            );
        }
        reject_symlink(p)?;
    }
    let bytes = read_bytes_from_location(&app, &loc, MAX_PQ_KEY_FILE_BYTES)?;
    let text = Zeroizing::new(String::from_utf8(bytes).map_err(|e| {
        let mut bad = e.into_bytes();
        bad.zeroize();
        "Selected file is not valid UTF-8 text".to_string()
    })?);
    validate_mlkem1024_key_b64(text.as_str())
        .map_err(|e| format!("Selected file is not a valid ML-KEM-1024 key: {e}"))?;
    Ok(text.to_string())
}

#[tauri::command]
async fn create_vault_from_import(
    req: CreateVaultFromImportRequest,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<CreateVaultFromImportResultDto, String> {
    let kdf = KdfConfig {
        algorithm: req.kdf_algorithm,
        memory_mib: req.memory_mib,
        iterations: req.iterations,
        parallelism: req.parallelism,
        version: 0x13,
    };
    kdf.validate_safe_floor().map_err(|e| e.to_string())?;

    let saved_kf_path = req
        .keyfile_path
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let keyfile_bytes = match saved_kf_path {
        Some(ref p) => Some(read_keyfile_bytes(&app, p)?),
        None => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password.clone(), keyfile_bytes)
            .map_err(|e| e.to_string())?;

    let default_import_ext = if req.import_kind == "csv" {
        ".csv"
    } else {
        ".json"
    };
    let src_loc = resolve_location(&app, &req.import_source_path, default_import_ext)?;
    let raw_import = Zeroizing::new(read_bytes_from_location(
        &app,
        &src_loc,
        MAX_VAULT_FILE_BYTES,
    )?);

    let location = resolve_location(&app, &req.path, ".kdbx")?;
    let db_name = req.database_name.clone();
    let cipher = req.cipher;
    let import_kind = req.import_kind.clone();
    let import_password = req.import_password.clone().map(Zeroizing::new);

    let (vault, credentials, summary, bytes) = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = Vault::new(db_name, cipher, kdf);
        let summary = if import_kind == "csv" {
            let csv_text = Zeroizing::new(String::from_utf8(raw_import.to_vec()).map_err(|e| {
                let mut bad = e.into_bytes();
                bad.zeroize();
                "CSV file must be valid UTF-8 text".to_string()
            })?);
            import_csv(csv_text.as_str(), &mut vault).map_err(|e| e.to_string())?
        } else {
            import_bitwarden_json(
                raw_import.as_slice(),
                import_password.as_deref().map(|z| z.as_str()),
                &mut vault,
            )
            .map_err(|e| e.to_string())?
        };
        let bytes =
            Zeroizing::new(save_kdbx_bytes(&vault, &credentials).map_err(|e| e.to_string())?);
        Ok::<_, String>((vault, credentials, summary, bytes))
    })
    .await
    .map_err(|e| format!("Background vault import task failed: {e}"))??;

    write_bytes_to_location(&app, &location, bytes.as_slice())?;
    record_recent_vault(&app, &vault.meta.database_name, &location.display_string());

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if let Some(mut old) = sess_guard.take() {
            old.vault.zeroize_secrets();
        }
        *sess_guard = Some(UnlockedSession {
            session_id: Uuid::new_v4(),
            vault,
            credentials,
            keyfile_path: saved_kf_path,
            location,
            last_activity: Instant::now(),
            dirty: false,
        });
    }

    let status = build_status(&state)?;
    Ok(CreateVaultFromImportResultDto { status, summary })
}

#[tauri::command]
fn toggle_favorite(
    entry_id: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<EntryDetailDto, String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let (gid, entry) = sess
        .vault
        .root_group
        .find_entry_mut(uuid)
        .ok_or_else(|| "Entry not found".to_string())?;
    let next_fav = !entry.is_favorite();
    entry.set_favorite(next_fav);
    entry.times.last_modification_time = Utc::now();
    let dto = entry_to_detail(gid, entry);

    persist_session(&app, sess)?;
    Ok(dto)
}

#[tauri::command]
fn get_totp_code(uri_or_secret: String) -> Result<TotpCode, String> {
    let uri_or_secret = Zeroizing::new(uri_or_secret);
    generate_totp_now(uri_or_secret.as_str()).map_err(|e| e.to_string())
}

/// Generates the current TOTP code for an entry by UUID inside Rust so raw TOTP seeds
/// never need to be exposed in bulk `list_entries` payloads or React state.
#[tauri::command]
fn get_entry_totp_code(
    entry_id: String,
    state: State<'_, Arc<SharedState>>,
) -> Result<TotpCode, String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let totp_uri = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        let (_, entry) = sess
            .vault
            .root_group
            .find_entry(uuid)
            .ok_or_else(|| "Entry not found".to_string())?;
        entry
            .totp_uri()
            .map(Zeroizing::new)
            .ok_or_else(|| "Entry has no TOTP configured".to_string())?
    };
    generate_totp_now(totp_uri.as_str()).map_err(|e| e.to_string())
}

#[tauri::command]
fn generate_password_cmd(options: PasswordGenOptions) -> GeneratedSecret {
    generate_password(&options)
}

#[tauri::command]
fn generate_passphrase_cmd(options: PassphraseGenOptions) -> GeneratedSecret {
    generate_passphrase(&options)
}

#[tauri::command]
fn evaluate_password_cmd(password: String) -> EntropyReport {
    let password = Zeroizing::new(password);
    evaluate_password(password.as_str())
}

#[tauri::command]
fn copy_secret_with_auto_clear(
    secret: String,
    clear_seconds: Option<u64>,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<u64, String> {
    let secret = Zeroizing::new(secret);
    let timeout = {
        let cfg = state.config.lock().map_err(|e| e.to_string())?;
        clear_seconds
            .unwrap_or(cfg.clipboard_clear_seconds)
            .clamp(5, 300)
    };

    app.clipboard()
        .write_text(secret.as_str())
        .map_err(|e| format!("Clipboard write failed: {e}"))?;

    state.schedule_clipboard_clear(timeout);

    Ok(timeout)
}

#[tauri::command]
fn clear_clipboard_now(app: AppHandle, state: State<'_, Arc<SharedState>>) -> Result<(), String> {
    state.cancel_clipboard_timer();
    app.clipboard()
        .clear()
        .map_err(|e| format!("Failed to clear clipboard: {e}"))
}

#[tauri::command]
async fn update_security_settings(
    req: SecuritySettingsRequest,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    {
        let mut cfg = state.config.lock().map_err(|e| e.to_string())?;
        let mut cfg_changed = false;
        if let Some(secs) = req.auto_lock_seconds {
            cfg.auto_lock_seconds = secs;
            cfg_changed = true;
        }
        if let Some(secs) = req.clipboard_clear_seconds {
            cfg.clipboard_clear_seconds = secs.clamp(5, 300);
            cfg_changed = true;
        }
        if cfg_changed {
            save_app_config(&app, &cfg);
        }
    }

    let needs_persist = req.cipher.is_some()
        || req.kdf.is_some()
        || req.database_name.is_some()
        || req.database_description.is_some();

    if needs_persist {
        let (expected_sid, mut vault_clone, creds_clone, loc_clone, updated_name) = {
            let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            let sess = sess_guard
                .as_mut()
                .ok_or_else(|| "Vault must be unlocked to change vault settings".to_string())?;
            sess.touch();

            let mut next_vault = sess.vault.clone();
            if let Some(name) = req.database_name {
                let clean = name.trim();
                if !clean.is_empty() {
                    if next_vault.root_group.name == next_vault.meta.database_name {
                        next_vault.root_group.name = clean.to_string();
                    }
                    next_vault.meta.database_name = clean.to_string();
                }
            }
            if let Some(desc) = req.database_description {
                next_vault.meta.database_description = desc.trim().to_string();
            }
            if let Some(kdf) = req.kdf {
                kdf.validate_safe_floor().map_err(|e| e.to_string())?;
                next_vault.kdf = kdf;
            }
            if let Some(cipher) = req.cipher {
                next_vault.cipher = cipher;
            }
            let creds_copy = MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            };
            let updated_name = next_vault.meta.database_name.clone();
            (
                sess.session_id,
                next_vault,
                creds_copy,
                sess.location.clone(),
                updated_name,
            )
        };

        let (mut next_vault, bytes) = tauri::async_runtime::spawn_blocking(move || {
            let raw = save_kdbx_bytes(&vault_clone, &creds_clone).map_err(|e| {
                vault_clone.zeroize_secrets();
                e.to_string()
            })?;
            Ok::<_, String>((vault_clone, Zeroizing::new(raw)))
        })
        .await
        .map_err(|e| format!("Background re-encryption failed: {e}"))??;

        {
            let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            let Some(ref mut sess) = *sess_guard else {
                next_vault.zeroize_secrets();
                return Err("Vault was locked while updating security settings".to_string());
            };
            if sess.session_id != expected_sid {
                next_vault.zeroize_secrets();
                return Err(
                    "Active vault session changed while updating security settings".to_string(),
                );
            }
            write_bytes_to_location(&app, &loc_clone, bytes.as_slice())?;
            sess.vault.zeroize_secrets();
            sess.vault = next_vault;
            sess.dirty = false;
        }
        record_recent_vault(&app, &updated_name, &loc_clone.display_string());
    }

    build_status(&state)
}

#[tauri::command]
async fn change_master_credentials(
    req: ChangeMasterCredentialsRequest,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<ChangeCredentialsResultDto, String> {
    let _unlock_guard = UnlockAttemptGuard::acquire(&state.unlock_in_progress)?;

    let failures = state.failed_unlock_attempts.load(Ordering::SeqCst);
    if failures > 0 {
        let backoff_secs = (1u64 << (failures.saturating_sub(1).min(4))).min(15);
        tauri::async_runtime::spawn_blocking(move || {
            std::thread::sleep(Duration::from_secs(backoff_secs));
        })
        .await
        .map_err(|e| e.to_string())?;
    }

    let (expected_sid, vault_clone, loc_clone, current_kf_bytes, current_kf_path) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault must be unlocked to change Master Password".to_string())?;
        sess.touch();

        // Constant-time, length-hiding verification of current master password via SHA-256
        if let Some(ref existing_pw) = sess.credentials.password {
            if !existing_pw.is_empty() {
                let supplied = req.current_password.as_deref().unwrap_or("");
                let existing_hash: Zeroizing<[u8; 32]> =
                    Zeroizing::new(Sha256::digest(existing_pw.as_bytes()).into());
                let supplied_hash: Zeroizing<[u8; 32]> =
                    Zeroizing::new(Sha256::digest(supplied.as_bytes()).into());
                let eq = bool::from(existing_hash.as_slice().ct_eq(supplied_hash.as_slice()));
                if !eq {
                    state.failed_unlock_attempts.fetch_add(1, Ordering::SeqCst);
                    return Err("Current Master Password is incorrect.".to_string());
                }
                state.failed_unlock_attempts.store(0, Ordering::SeqCst);
            }
        }

        (
            sess.session_id,
            sess.vault.clone(),
            sess.location.clone(),
            sess.credentials.keyfile_bytes.clone(),
            sess.keyfile_path.clone(),
        )
    };

    let (next_kf_bytes, next_kf_path) = match req.keyfile_action.as_str() {
        "remove" => (None, None),
        "set" => {
            let path = req
                .new_keyfile_path
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "Select a Keyfile path to attach.".to_string())?;
            let kf_bytes = read_keyfile_bytes(&app, &path)?;
            (Some(kf_bytes), Some(path))
        }
        _ => (current_kf_bytes.map(|z| z.to_vec()), current_kf_path),
    };

    let next_pw = req.new_password.clone().filter(|s| !s.is_empty());

    let new_creds = MasterCredentials::from_password_and_keyfile(next_pw, next_kf_bytes)
        .map_err(|e| e.to_string())?;

    let creds_for_task = MasterCredentials {
        password: new_creds.password.clone(),
        keyfile_bytes: new_creds.keyfile_bytes.clone(),
    };

    let bytes = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = vault_clone;
        let raw = save_kdbx_bytes(&vault, &creds_for_task).map_err(|e| e.to_string());
        vault.zeroize_secrets();
        Ok::<_, String>(Zeroizing::new(raw?))
    })
    .await
    .map_err(|e| format!("Background re-encryption failed: {e}"))??;

    let canonical = loc_clone.display_string();
    let biometric_reset = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let Some(ref mut sess) = *sess_guard else {
            return Err("Vault was locked while changing Master Credentials".to_string());
        };
        if sess.session_id != expected_sid {
            return Err(
                "Active vault session changed while changing Master Credentials".to_string(),
            );
        }
        write_bytes_to_location(&app, &loc_clone, bytes.as_slice())?;
        let reset = wipe_biometric_slot(&app, &canonical);
        sess.credentials = new_creds;
        sess.keyfile_path = next_kf_path;
        sess.dirty = false;
        reset
    };

    let status = build_status(&state)?;
    Ok(ChangeCredentialsResultDto {
        status,
        biometric_reset,
    })
}

#[tauri::command]
fn run_security_audit_cmd(
    state: State<'_, Arc<SharedState>>,
) -> Result<SecurityAuditReport, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();
    Ok(run_vault_audit(&sess.vault))
}

#[tauri::command]
async fn export_vault_backup(
    dest_path: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<String, String> {
    let (expected_sid, vault_clone, creds_clone) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        (
            sess.session_id,
            sess.vault.clone(),
            MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            },
        )
    };

    let loc = resolve_location(&app, &dest_path, ".kdbx")?;
    let bytes = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = vault_clone;
        let raw = save_kdbx_bytes(&vault, &creds_clone).map_err(|e| e.to_string());
        vault.zeroize_secrets();
        Ok::<_, String>(Zeroizing::new(raw?))
    })
    .await
    .map_err(|e| format!("Backup export task failed: {e}"))??;

    {
        let sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if sess_guard
            .as_ref()
            .is_none_or(|s| s.session_id != expected_sid)
        {
            return Err("Vault was locked or changed during backup export".to_string());
        }
    }

    write_bytes_to_location(&app, &loc, bytes.as_slice())?;
    Ok(loc.display_string())
}

#[tauri::command]
fn generate_pq_keypair_cmd() -> Result<MlKem1024Keypair, String> {
    generate_mlkem1024_keypair().map_err(|e| e.to_string())
}

#[tauri::command]
async fn run_pq_self_test() -> Result<PqSelfTestResultDto, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let started = Instant::now();
        let kp = generate_mlkem1024_keypair().map_err(|e| e.to_string())?;
        let sample = b"CipherPass NIST FIPS 203 ML-KEM-1024 live device verification payload";
        let sealed = pq_seal_bytes(sample, &kp.public_key_b64).map_err(|e| e.to_string())?;
        let unsealed = pq_unseal_bytes(&sealed, &kp.secret_key_b64).map_err(|e| e.to_string())?;
        let passed = unsealed.as_slice() == sample;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        Ok::<_, String>(PqSelfTestResultDto {
            passed,
            algorithm: "NIST FIPS 203 ML-KEM-1024 (Category 5) + SHA3-512 + ChaCha20-Poly1305"
                .to_string(),
            public_key_bytes: 1568,
            secret_key_bytes: 3168,
            ciphertext_bytes: 1568,
            elapsed_ms,
            fingerprint: kp.fingerprint.clone(),
        })
    })
    .await
    .map_err(|e| format!("PQ self-test failed: {e}"))?
}

#[tauri::command]
async fn export_pq_armored_vault(
    dest_path: String,
    public_key_b64: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<String, String> {
    let (expected_sid, vault_clone, creds_clone) = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        (
            sess.session_id,
            sess.vault.clone(),
            MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            },
        )
    };

    let loc = resolve_location(&app, &dest_path, ".kdbx.pq")?;
    let sealed = tauri::async_runtime::spawn_blocking(move || {
        let mut vault = vault_clone;
        let kdbx_res = save_kdbx_bytes(&vault, &creds_clone).map_err(|e| e.to_string());
        vault.zeroize_secrets();
        let kdbx_bytes = Zeroizing::new(kdbx_res?);
        pq_seal_bytes(kdbx_bytes.as_slice(), &public_key_b64).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("PQ seal task failed: {e}"))??;

    {
        let sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if sess_guard
            .as_ref()
            .is_none_or(|s| s.session_id != expected_sid)
        {
            return Err("Vault was locked or changed during PQ armor export".to_string());
        }
    }

    write_bytes_to_location(&app, &loc, &sealed)?;
    Ok(loc.display_string())
}

#[tauri::command]
fn unseal_pq_armored_vault(
    src_pq_path: String,
    dest_kdbx_path: String,
    secret_key_b64: String,
    app: AppHandle,
) -> Result<String, String> {
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
    let src_loc = resolve_location(&app, &src_pq_path, ".pq")?;
    let sealed = read_bytes_from_location(&app, &src_loc, MAX_VAULT_FILE_BYTES)?;
    let kdbx_bytes =
        pq_unseal_bytes(&sealed, secret_key_b64.as_str()).map_err(|e| e.to_string())?;
    let dest_loc = resolve_location(&app, &dest_kdbx_path, ".kdbx")?;
    write_bytes_to_location(&app, &dest_loc, kdbx_bytes.as_slice())?;
    Ok(dest_loc.display_string())
}

#[tauri::command]
fn has_biometric_slot(path: String, app: AppHandle) -> Result<bool, String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = (path, app);
        Ok(false)
    }

    #[cfg(target_os = "android")]
    {
        let loc = resolve_location(&app, &path, ".kdbx")?;
        let canonical = loc.display_string();
        let slot_path = biometric_slot_path(&app, &canonical)?;
        let hw_key_path = biometric_hw_key_path(&app, &canonical)?;
        Ok(slot_path.exists() && hw_key_path.exists())
    }

    #[cfg(target_os = "ios")]
    {
        let loc = resolve_location(&app, &path, ".kdbx")?;
        let slot_path = biometric_slot_path(&app, &loc.display_string())?;
        Ok(slot_path.exists())
    }
}

#[tauri::command]
fn enable_biometric_unlock(
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<bool, String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = (app, state);
        Err(
            "Biometric Vault Unlock is enforced via native OS BiometricPrompt / Face ID on Android & iOS."
                .to_string(),
        )
    }

    #[cfg(target_os = "android")]
    {
        use tauri_plugin_biometric::{AuthOptions, BiometricExt};

        let (expected_sid, canonical, bio_creds) = {
            let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            let sess = sess_guard
                .as_mut()
                .ok_or_else(|| "Vault must be unlocked first".to_string())?;
            sess.touch();
            let canonical = sess.location.display_string();
            let bio_creds = BiometricVaultCredentials {
                master_password: sess.credentials.password.clone(),
                keyfile_path: sess.keyfile_path.clone(),
            };
            (sess.session_id, canonical, bio_creds)
        };

        // Generate a fresh per-vault 256-bit wrapping key and seal it inside Android KeyStore
        // hardware using BiometricPrompt.CryptoObject (BIOMETRIC_STRONG / Class 3).
        let slot_key = Zeroizing::new(random_bytes::<32>());
        let slot_key_hex = Zeroizing::new(hex::encode(slot_key.as_slice()));

        let cipher_res = app
            .biometric()
            .biometric_cipher(
                "Confirm biometrics to bind your vault Master Key in hardware".to_string(),
                AuthOptions {
                    allow_device_credential: false,
                    cancel_title: Some("Cancel".to_string()),
                    fallback_title: Some("Use Master Password".to_string()),
                    title: Some("Enable Biometric Vault Unlock".to_string()),
                    subtitle: Some(
                        "Hardware-backed Android KeyStore + ChaCha20-Poly1305".to_string(),
                    ),
                    confirmation_required: Some(true),
                    data_to_encrypt: Some(slot_key_hex.to_string()),
                    data_to_decrypt: None,
                },
            )
            .map_err(|e| format!("Hardware biometric binding failed: {e}"))?;

        {
            let sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            if sess_guard
                .as_ref()
                .is_none_or(|s| s.session_id != expected_sid)
            {
                return Err("Vault was locked during biometric enrollment".to_string());
            }
        }

        let vault_id = vault_slot_id(&canonical);
        let sealed =
            seal_biometric_slot(&bio_creds, &slot_key, &vault_id).map_err(|e| e.to_string())?;
        let slot_path = biometric_slot_path(&app, &canonical)?;
        let hw_key_path = biometric_hw_key_path(&app, &canonical)?;
        reject_symlink(&slot_path)?;
        reject_symlink(&hw_key_path)?;
        atomic_write_file(&slot_path, &sealed).map_err(|e| e.to_string())?;
        atomic_write_file(&hw_key_path, cipher_res.data.as_bytes()).map_err(|e| e.to_string())?;

        // Securely remove any legacy plaintext device.key from prior versions
        if let Ok(ks) = keystore_dir(&app) {
            let legacy = ks.join("device.key");
            secure_delete_file(&legacy);
        }

        Ok(true)
    }

    #[cfg(target_os = "ios")]
    {
        use tauri_plugin_biometric::{AuthOptions, BiometricExt};
        app.biometric()
            .authenticate(
                "Confirm biometrics to bind your vault Master Key".to_string(),
                AuthOptions {
                    allow_device_credential: false,
                    cancel_title: Some("Cancel".to_string()),
                    fallback_title: Some("Use Master Password".to_string()),
                    title: Some("Enable Biometric Vault Unlock".to_string()),
                    subtitle: Some("Seal KDBX 4 credentials with ChaCha20-Poly1305".to_string()),
                    confirmation_required: Some(true),
                    data_to_encrypt: None,
                    data_to_decrypt: None,
                },
            )
            .map_err(|e| format!("Biometric verification failed: {e}"))?;

        let (canonical, bio_creds) = {
            let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            let sess = sess_guard
                .as_mut()
                .ok_or_else(|| "Vault must be unlocked first".to_string())?;
            sess.touch();
            let canonical = sess.location.display_string();
            let bio_creds = BiometricVaultCredentials {
                master_password: sess.credentials.password.clone(),
                keyfile_path: sess.keyfile_path.clone(),
            };
            (canonical, bio_creds)
        };

        let device_secret = load_or_create_device_secret(&app)?;
        let vault_id = vault_slot_id(&canonical);
        let sealed = seal_biometric_slot(&bio_creds, &device_secret, &vault_id)
            .map_err(|e| e.to_string())?;
        let slot_path = biometric_slot_path(&app, &canonical)?;
        reject_symlink(&slot_path)?;
        atomic_write_file(&slot_path, &sealed).map_err(|e| e.to_string())?;
        Ok(true)
    }
}

#[tauri::command]
fn disable_biometric_unlock(
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<bool, String> {
    let canonical = {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        sess.location.display_string()
    };

    wipe_biometric_slot(&app, &canonical);
    Ok(false)
}

#[tauri::command]
async fn unlock_vault_biometric(
    path: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let _ = (path, app, state);
        Err("Biometric Vault Unlock is only available on Android & iOS devices.".to_string())
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        use tauri_plugin_biometric::{AuthOptions, BiometricExt};

        let _unlock_guard = UnlockAttemptGuard::acquire(&state.unlock_in_progress)?;

        let location = resolve_location(&app, &path, ".kdbx")?;
        let canonical = location.display_string();
        let slot_path = biometric_slot_path(&app, &canonical)?;
        reject_symlink(&slot_path)?;
        if !slot_path.exists() {
            return Err("Biometric unlock is not enabled for this vault".to_string());
        }

        let vault_id = vault_slot_id(&canonical);

        #[cfg(target_os = "android")]
        let slot_key: Zeroizing<[u8; 32]> = {
            let hw_key_path = biometric_hw_key_path(&app, &canonical)?;
            reject_symlink(&hw_key_path)?;
            if !hw_key_path.exists() {
                return Err(
                    "Legacy biometric keyslot detected. Unlock with Master Password and re-enable biometrics for hardware KeyStore protection."
                        .to_string(),
                );
            }
            let wrapped_bytes = read_bytes_from_location(
                &app,
                &VaultLocation::FileSystem(hw_key_path),
                MAX_PQ_KEY_FILE_BYTES,
            )?;
            let wrapped_str = String::from_utf8(wrapped_bytes)
                .map_err(|_| "Corrupted biometric hardware key file".to_string())?;

            let cipher_res = app
                .biometric()
                .biometric_cipher(
                    "Authenticate to decrypt your CipherPass KDBX 4 vault".to_string(),
                    AuthOptions {
                        allow_device_credential: false,
                        cancel_title: Some("Cancel".to_string()),
                        fallback_title: Some("Use Master Password".to_string()),
                        title: Some("CipherPass Biometric Unlock".to_string()),
                        subtitle: Some("Unlock hardware-backed Android KeyStore key".to_string()),
                        confirmation_required: Some(true),
                        data_to_encrypt: None,
                        data_to_decrypt: Some(wrapped_str),
                    },
                )
                .map_err(|e| format!("Hardware biometric decryption failed: {e}"))?;

            let plain_hex = Zeroizing::new(cipher_res.data);
            let decoded = Zeroizing::new(
                hex::decode(plain_hex.trim())
                    .map_err(|_| "Corrupted unwrapped biometric key".to_string())?,
            );
            if decoded.len() != 32 {
                return Err("Invalid unwrapped biometric key length".to_string());
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(decoded.as_slice());
            key
        };

        #[cfg(target_os = "ios")]
        let slot_key: Zeroizing<[u8; 32]> = {
            app.biometric()
                .authenticate(
                    "Authenticate to decrypt your CipherPass KDBX 4 vault".to_string(),
                    AuthOptions {
                        allow_device_credential: false,
                        cancel_title: Some("Cancel".to_string()),
                        fallback_title: Some("Use Master Password".to_string()),
                        title: Some("CipherPass Biometric Unlock".to_string()),
                        subtitle: Some("Decrypt bound KDBX 4 Master Key".to_string()),
                        confirmation_required: Some(true),
                        data_to_encrypt: None,
                        data_to_decrypt: None,
                    },
                )
                .map_err(|e| format!("Biometric authentication failed: {e}"))?;
            load_or_create_device_secret(&app)?
        };

        let slot_bytes =
            read_bytes_from_location(&app, &VaultLocation::FileSystem(slot_path), 64 * 1024)?;
        let bio_creds =
            unseal_biometric_slot(&slot_bytes, &slot_key, &vault_id).map_err(|e| e.to_string())?;

        let saved_kf_path = bio_creds.keyfile_path.clone();
        let keyfile_bytes = match saved_kf_path {
            Some(ref p) => Some(read_keyfile_bytes(&app, p)?),
            None => None,
        };

        let credentials = MasterCredentials::from_password_and_keyfile(
            bio_creds.master_password.clone(),
            keyfile_bytes,
        )
        .map_err(|e| e.to_string())?;

        let raw_bytes = read_bytes_from_location(&app, &location, MAX_VAULT_FILE_BYTES)?;

        let (vault, credentials) = tauri::async_runtime::spawn_blocking(move || {
            let vault = open_kdbx_bytes(&raw_bytes, &credentials).map_err(|e| e.to_string())?;
            Ok::<_, String>((vault, credentials))
        })
        .await
        .map_err(|e| format!("Background crypto task failed: {e}"))??;

        state.failed_unlock_attempts.store(0, Ordering::SeqCst);
        record_recent_vault(&app, &vault.meta.database_name, &canonical);

        {
            let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            if let Some(mut old) = sess_guard.take() {
                old.vault.zeroize_secrets();
            }
            *sess_guard = Some(UnlockedSession {
                session_id: Uuid::new_v4(),
                vault,
                credentials,
                keyfile_path: saved_kf_path,
                location,
                last_activity: Instant::now(),
                dirty: false,
            });
        }

        build_status(&state)
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let shared_state = Arc::new(SharedState::new());
    let monitor_state = Arc::clone(&shared_state);
    let clipboard_state = Arc::clone(&shared_state);

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_clipboard_manager::init());

    #[cfg(any(target_os = "android", target_os = "ios"))]
    let builder = builder.plugin(tauri_plugin_biometric::init());

    builder
        .manage(shared_state)
        .setup(move |app| {
            let app_handle = app.handle().clone();
            let loaded_cfg = load_app_config(&app_handle);
            if let Ok(mut cfg) = monitor_state.config.lock() {
                *cfg = loaded_cfg;
            }
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let auto_lock_secs = monitor_state
                    .config
                    .lock()
                    .map(|c| c.auto_lock_seconds)
                    .unwrap_or(300);

                if auto_lock_secs == 0 {
                    continue;
                }

                let mut locked_now = false;
                if let Ok(mut guard) = monitor_state.session.lock() {
                    if let Some(ref sess) = *guard {
                        if sess.last_activity.elapsed().as_secs() >= auto_lock_secs {
                            if let Some(mut old) = guard.take() {
                                old.vault.zeroize_secrets();
                            }
                            locked_now = true;
                        }
                    }
                }
                if locked_now {
                    monitor_state.cancel_clipboard_timer();
                    let _ = app_handle.clipboard().clear();
                    let _ = app_handle.emit("vault-auto-locked", ());
                }
            });

            // Single persistent worker thread for clipboard auto-clear (prevents unbounded thread creation)
            let clip_app = app.handle().clone();
            std::thread::spawn(move || loop {
                let mut guard = match clipboard_state.clipboard_timer.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                let (deadline, expected_gen) = match guard.deadline {
                    Some(pair) => pair,
                    None => {
                        guard = match clipboard_state.clipboard_cv.wait(guard) {
                            Ok(g) => g,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        drop(guard);
                        continue;
                    }
                };
                let now = Instant::now();
                if now >= deadline {
                    guard.deadline = None;
                    drop(guard);
                    if clipboard_state.clipboard_generation.load(Ordering::SeqCst) == expected_gen {
                        let _ = clip_app.clipboard().clear();
                        let _ = clip_app.emit("clipboard-cleared", ());
                    }
                } else {
                    let wait_for = deadline.saturating_duration_since(now);
                    let _ = clipboard_state.clipboard_cv.wait_timeout(guard, wait_for);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_default_vault_dir,
            get_storage_roots,
            list_directory_folders,
            create_directory,
            list_local_vaults,
            clear_recent_vaults,
            get_vault_status,
            create_vault,
            create_vault_from_import,
            open_vault,
            lock_vault,
            save_vault,
            move_vault_to_path,
            generate_keyfile_to_path,
            write_text_file,
            read_text_file,
            list_groups,
            create_group,
            rename_group,
            delete_group,
            import_bitwarden_json_file,
            import_csv_file,
            import_kdbx_into_vault,
            export_encrypted_json_file,
            list_entries,
            get_entry,
            copy_entry_password,
            upsert_entry,
            delete_entry,
            restore_entry,
            empty_recycle_bin,
            toggle_favorite,
            get_totp_code,
            get_entry_totp_code,
            generate_password_cmd,
            generate_passphrase_cmd,
            evaluate_password_cmd,
            copy_secret_with_auto_clear,
            clear_clipboard_now,
            update_security_settings,
            change_master_credentials,
            run_security_audit_cmd,
            export_vault_backup,
            generate_pq_keypair_cmd,
            run_pq_self_test,
            export_pq_armored_vault,
            unseal_pq_armored_vault,
            has_biometric_slot,
            enable_biometric_unlock,
            disable_biometric_unlock,
            unlock_vault_biometric,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherPass Tauri application");
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn path_validator_blocks_traversal_nul_and_keystore() {
        let ks = Path::new("/tmp/app_data/.keystore");

        // NUL byte injection
        assert!(validate_fs_path_against_keystore(Path::new("/tmp/foo\0bar.kdbx"), ks).is_err());

        // Parent directory traversal
        assert!(validate_fs_path_against_keystore(
            Path::new("/tmp/vaults/../.keystore/device.key"),
            ks
        )
        .is_err());
        assert!(validate_fs_path_against_keystore(Path::new("../etc/passwd"), ks).is_err());

        // Direct .keystore targeting
        assert!(validate_fs_path_against_keystore(ks, ks).is_err());
        assert!(validate_fs_path_against_keystore(&ks.join("device.key"), ks).is_err());
        assert!(validate_fs_path_against_keystore(&ks.join("abc.bio"), ks).is_err());

        // Legitimate vault path outside .keystore
        assert!(
            validate_fs_path_against_keystore(Path::new("/tmp/app_data/vaults/main.kdbx"), ks)
                .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_validator_blocks_symlink_escape_into_keystore() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!("cpx_sec_test_{}", Uuid::new_v4()));
        let ks = base.join(".keystore");
        let vaults = base.join("vaults");
        fs::create_dir_all(&ks).unwrap();
        fs::create_dir_all(&vaults).unwrap();
        let secret_file = ks.join("device.key");
        fs::write(&secret_file, [0x42u8; 32]).unwrap();

        // Symlink inside vaults/ pointing directly to .keystore/device.key
        let link_file = vaults.join("evil.pqkey");
        symlink(&secret_file, &link_file).unwrap();

        assert!(reject_symlink(&link_file).is_err());
        assert!(validate_fs_path_against_keystore(&link_file, &ks).is_err());

        // Symlink directory pointing to .keystore
        let link_dir = vaults.join("ks_alias");
        symlink(&ks, &link_dir).unwrap();
        assert!(validate_fs_path_against_keystore(&link_dir.join("new.bio"), &ks).is_err());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn pq_key_extension_and_payload_validation_rejects_arbitrary_files() {
        assert!(has_allowed_pq_key_extension(Path::new("/tmp/a.pqkey")));
        assert!(has_allowed_pq_key_extension(Path::new("/tmp/a.pqpub")));
        assert!(has_allowed_pq_key_extension(Path::new("/tmp/a.txt")));
        assert!(!has_allowed_pq_key_extension(Path::new("/etc/passwd")));
        assert!(!has_allowed_pq_key_extension(Path::new("/home/u/.bashrc")));
        assert!(!has_allowed_pq_key_extension(Path::new(
            "/home/u/.ssh/id_rsa"
        )));
        assert!(!has_allowed_pq_key_extension(Path::new("/tmp/evil.sh")));

        // Arbitrary shell script / config / JSON must fail ML-KEM-1024 validation
        assert!(validate_mlkem1024_key_b64("#!/bin/sh\ncurl evil.example\n").is_err());
        assert!(validate_mlkem1024_key_b64("root:x:0:0:root:/root:/bin/bash").is_err());
        assert!(validate_mlkem1024_key_b64("{\"secret\": \"value\"}").is_err());

        // Genuine ML-KEM-1024 keys must pass
        let kp = generate_mlkem1024_keypair().unwrap();
        assert!(validate_mlkem1024_key_b64(&kp.public_key_b64).is_ok());
        assert!(validate_mlkem1024_key_b64(&kp.secret_key_b64).is_ok());
    }

    #[test]
    fn unlock_attempt_guard_serializes_concurrent_unlocks() {
        let flag = AtomicBool::new(false);
        let g1 = UnlockAttemptGuard::acquire(&flag).expect("first unlock acquires lock");
        assert!(UnlockAttemptGuard::acquire(&flag).is_err());
        drop(g1);
        assert!(UnlockAttemptGuard::acquire(&flag).is_ok());
    }

    #[test]
    fn entry_summary_dto_omits_totp_uri_and_detail_redacts_debug() {
        let mut entry = VaultEntry::new("Bank");
        entry.password = ProtectedString::new("SuperSecret!123");
        entry.notes = "Pin 9876".to_string();
        entry.set_totp_uri(Some(
            "otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP".to_string(),
        ));

        let summary = entry_to_summary(Uuid::new_v4(), &entry);
        let summary_json = serde_json::to_string(&summary).unwrap();
        assert!(summary.has_totp);
        assert!(!summary_json.contains("JBSWY3DPEHPK3PXP"));
        assert!(!summary_json.contains("SuperSecret!123"));

        let detail = entry_to_detail(Uuid::new_v4(), &entry);
        let debug_str = format!("{detail:?}");
        assert!(!debug_str.contains("SuperSecret!123"));
        assert!(!debug_str.contains("JBSWY3DPEHPK3PXP"));
        assert!(!debug_str.contains("Pin 9876"));
    }
}
