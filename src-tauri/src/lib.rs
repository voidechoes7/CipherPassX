#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use cipherpass_core::crypto::random_bytes;
#[cfg(any(target_os = "android", target_os = "ios"))]
use cipherpass_core::unseal_biometric_slot;
use cipherpass_core::{
    atomic_write_file, evaluate_password, generate_keyfile_v2_xml, generate_mlkem1024_keypair,
    generate_passphrase, generate_password, generate_totp_now, open_kdbx_bytes, pq_seal_bytes,
    pq_unseal_bytes, run_vault_audit, save_kdbx_bytes, seal_biometric_slot, vault_slot_id,
    BiometricVaultCredentials, CipherAlgorithm, CustomField, EntropyReport, GeneratedSecret,
    KdfAlgorithm, KdfConfig, MasterCredentials, MlKem1024Keypair, PassphraseGenOptions,
    PasswordGenOptions, ProtectedString, SecurityAuditReport, TotpCode, Vault, VaultEntry,
    VaultGroup,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_fs::{FilePath, FsExt, OpenOptions};
use uuid::Uuid;
use zeroize::Zeroizing;

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

fn default_vaults_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let base = app
        .path()
        .app_local_data_dir()
        .map_err(|e| format!("Failed to resolve app_local_data_dir: {e}"))?;
    let dir = base.join("vaults");
    fs::create_dir_all(&dir).map_err(|e| format!("Failed to create vaults directory: {e}"))?;
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

    if trimmed.starts_with("content://") {
        let url =
            tauri::Url::parse(trimmed).map_err(|e| format!("Invalid Android content URI: {e}"))?;
        return Ok(VaultLocation::ContentUri(url));
    }

    if trimmed.starts_with("file://") {
        let url = tauri::Url::parse(trimmed).map_err(|e| format!("Invalid file URI: {e}"))?;
        if let Ok(path) = url.to_file_path() {
            return Ok(VaultLocation::FileSystem(path));
        }
        return Ok(VaultLocation::ContentUri(url));
    }

    let path = PathBuf::from(trimmed);
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
        return Ok(VaultLocation::FileSystem(dir.join(fname)));
    }

    Ok(VaultLocation::FileSystem(path))
}

fn read_bytes_from_location(app: &AppHandle, loc: &VaultLocation) -> Result<Vec<u8>, String> {
    match loc {
        VaultLocation::FileSystem(path) => {
            fs::read(path).map_err(|e| format!("Failed to read file: {e}"))
        }
        VaultLocation::ContentUri(url) => {
            let mut opts = OpenOptions::new();
            opts.read(true);
            let mut file = app
                .fs()
                .open(FilePath::Url(url.clone()), opts)
                .map_err(|e| format!("Failed to open content URI for reading: {e}"))?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .map_err(|e| format!("Failed to read content URI: {e}"))?;
            Ok(buf)
        }
    }
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
    Ok(dir)
}

fn load_or_create_device_secret(app: &AppHandle) -> Result<Zeroizing<[u8; 32]>, String> {
    let key_path = keystore_dir(app)?.join("device.key");
    if key_path.exists() {
        let raw = fs::read(&key_path).map_err(|e| format!("Failed to read device key: {e}"))?;
        if raw.len() == 32 {
            let mut arr = Zeroizing::new([0u8; 32]);
            arr.copy_from_slice(&raw);
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

struct AppConfig {
    auto_lock_seconds: u64,       // 0 = disabled, default 300 (5 min)
    clipboard_clear_seconds: u64, // 15, 30, or 60
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_lock_seconds: 300,
            clipboard_clear_seconds: 30,
        }
    }
}

struct SharedState {
    session: Mutex<Option<UnlockedSession>>,
    config: Mutex<AppConfig>,
    clipboard_generation: AtomicU64,
    failed_unlock_attempts: AtomicU32,
}

impl SharedState {
    fn new() -> Self {
        Self {
            session: Mutex::new(None),
            config: Mutex::new(AppConfig::default()),
            clipboard_generation: AtomicU64::new(0),
            failed_unlock_attempts: AtomicU32::new(0),
        }
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
    pub cipher: Option<CipherAlgorithm>,
    pub kdf: Option<KdfConfig>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomFieldDto {
    pub key: String,
    pub value: String,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryItemDto {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub password: String,
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrySummaryDto {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub favorite: bool,
    pub has_totp: bool,
    pub totp_uri: Option<String>,
    pub tags: Vec<String>,
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryDetailDto {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<CustomFieldDto>,
    pub history: Vec<HistoryItemDto>,
    pub created_at: String,
    pub modified_at: String,
    pub expires: bool,
    pub expiry_time: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateVaultRequest {
    pub path: String,
    pub database_name: String,
    pub master_password: Option<String>,
    pub keyfile_path: Option<String>,
    pub cipher: CipherAlgorithm,
    pub kdf_algorithm: KdfAlgorithm,
    pub memory_mib: u64,
    pub iterations: u64,
    pub parallelism: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OpenVaultRequest {
    pub path: String,
    pub master_password: Option<String>,
    pub keyfile_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EntryUpsertRequest {
    pub id: Option<String>,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub favorite: bool,
    pub tags: Vec<String>,
    pub totp_uri: Option<String>,
    pub custom_fields: Vec<CustomFieldDto>,
    pub expires: bool,
    pub expiry_time: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecuritySettingsRequest {
    pub cipher: Option<CipherAlgorithm>,
    pub kdf: Option<KdfConfig>,
    pub auto_lock_seconds: Option<u64>,
    pub clipboard_clear_seconds: Option<u64>,
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
    let totp_uri = e.totp_uri();
    EntrySummaryDto {
        id: e.uuid.to_string(),
        group_id: group_id.to_string(),
        title: e.title.clone(),
        username: e.username.clone(),
        url: e.url.clone(),
        favorite: e.is_favorite(),
        has_totp: totp_uri.is_some(),
        totp_uri,
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

fn build_status(state: &SharedState) -> Result<VaultStatusDto, String> {
    let cfg = state.config.lock().map_err(|e| e.to_string())?;
    let sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    if let Some(ref sess) = *sess_guard {
        Ok(VaultStatusDto {
            unlocked: true,
            path: Some(sess.location.display_string()),
            database_name: Some(sess.vault.meta.database_name.clone()),
            cipher: Some(sess.vault.cipher),
            kdf: Some(sess.vault.kdf.clone()),
            entry_count: sess.vault.all_entries().len(),
            dirty: sess.dirty,
            auto_lock_seconds: cfg.auto_lock_seconds,
            clipboard_clear_seconds: cfg.clipboard_clear_seconds,
        })
    } else {
        Ok(VaultStatusDto {
            unlocked: false,
            path: None,
            database_name: None,
            cipher: None,
            kdf: None,
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
            if pb.exists() {
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
fn list_directory_folders(path: String) -> FolderListingDto {
    let pb = PathBuf::from(path.trim());
    let parent_path = pb.parent().and_then(|p| {
        let s = p.to_string_lossy().to_string();
        if s.is_empty() || s == path.trim() {
            None
        } else {
            Some(s)
        }
    });

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
fn create_directory(parent_path: String, folder_name: String) -> Result<String, String> {
    let clean = folder_name
        .trim()
        .replace(['/', '\\'], "")
        .trim_matches('.')
        .to_string();
    if clean.is_empty() {
        return Err("Folder name cannot be empty".to_string());
    }
    let target = PathBuf::from(parent_path.trim()).join(&clean);
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
        Some(ref p) => {
            let kf_loc = resolve_location(&app, p, ".keyx")?;
            Some(read_bytes_from_location(&app, &kf_loc)?)
        }
        None => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password, keyfile_bytes)
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
        *sess_guard = Some(UnlockedSession {
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
        Some(ref p) => {
            let kf_loc = resolve_location(&app, p, ".keyx")?;
            Some(read_bytes_from_location(&app, &kf_loc)?)
        }
        None => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password, keyfile_bytes)
            .map_err(|e| e.to_string())?;

    let location = resolve_location(&app, &req.path, ".kdbx")?;
    let raw_bytes = read_bytes_from_location(&app, &location)?;

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
        *sess_guard = Some(UnlockedSession {
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
    state.clipboard_generation.fetch_add(1, Ordering::SeqCst);
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

        // Re-bind biometric slot if one existed for the old path
        if let Ok(old_slot) = biometric_slot_path(&app, &old_canonical) {
            if old_slot.exists() {
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
        }

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
    sess.vault
        .root_group
        .remove_subgroup(uuid)
        .ok_or_else(|| "Group not found".to_string())?;
    persist_session(&app, sess)?;
    Ok(())
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
        sess.vault.all_entries()
    };

    let q_lower = query.unwrap_or_default().trim().to_lowercase();
    let fav_only = favorites_only.unwrap_or(false);
    let otp_only = totp_only.unwrap_or(false);

    let mut result: Vec<EntrySummaryDto> = raw_entries
        .into_iter()
        .filter(|(_, e)| e.matches_query(&q_lower))
        .filter(|(_, e)| !fav_only || e.is_favorite())
        .filter(|(_, e)| !otp_only || e.totp_uri().is_some())
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
        Zeroizing::new(entry.password.expose().to_string())
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

        entry.title = req.title;
        entry.username = req.username;
        entry.password = ProtectedString::new(req.password);
        entry.url = req.url;
        entry.notes = req.notes;
        entry.tags = req.tags;
        entry.set_favorite(req.favorite);
        entry.custom_fields = req
            .custom_fields
            .into_iter()
            .map(|cf| CustomField {
                key: cf.key,
                value: ProtectedString::new(cf.value),
                protected: cf.protected,
            })
            .collect();
        entry.set_totp_uri(req.totp_uri);
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
        let mut entry = VaultEntry::new(req.title);
        entry.username = req.username;
        entry.password = ProtectedString::new(req.password);
        entry.url = req.url;
        entry.notes = req.notes;
        entry.tags = req.tags;
        entry.set_favorite(req.favorite);
        entry.custom_fields = req
            .custom_fields
            .into_iter()
            .map(|cf| CustomField {
                key: cf.key,
                value: ProtectedString::new(cf.value),
                protected: cf.protected,
            })
            .collect();
        entry.set_totp_uri(req.totp_uri);
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
) -> Result<(), String> {
    let uuid = Uuid::parse_str(&entry_id).map_err(|e| e.to_string())?;
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let mut removed = sess
        .vault
        .root_group
        .remove_entry(uuid)
        .ok_or_else(|| "Entry not found".to_string())?;
    removed.zeroize_secrets();

    sess.vault
        .deleted_objects
        .push(cipherpass_core::DeletedObject {
            uuid,
            deletion_time: Utc::now(),
        });

    persist_session(&app, sess)?;
    Ok(())
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
    generate_totp_now(&uri_or_secret).map_err(|e| e.to_string())
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
    evaluate_password(&password)
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

    let gen_id = state.clipboard_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let shared = Arc::clone(&state);
    let app_clone = app.clone();

    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout));
        if shared.clipboard_generation.load(Ordering::SeqCst) == gen_id {
            let _ = app_clone.clipboard().clear();
            let _ = app_clone.emit("clipboard-cleared", ());
        }
    });

    Ok(timeout)
}

#[tauri::command]
fn clear_clipboard_now(app: AppHandle, state: State<'_, Arc<SharedState>>) -> Result<(), String> {
    state.clipboard_generation.fetch_add(1, Ordering::SeqCst);
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
        if let Some(secs) = req.auto_lock_seconds {
            cfg.auto_lock_seconds = secs;
        }
        if let Some(secs) = req.clipboard_clear_seconds {
            cfg.clipboard_clear_seconds = secs.clamp(5, 300);
        }
    }

    if req.cipher.is_some() || req.kdf.is_some() {
        let (vault_clone, creds_clone, loc_clone) = {
            let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
            let sess = sess_guard
                .as_mut()
                .ok_or_else(|| "Vault must be unlocked to change cipher or KDF".to_string())?;
            sess.touch();

            if let Some(kdf) = req.kdf {
                kdf.validate_safe_floor().map_err(|e| e.to_string())?;
                sess.vault.kdf = kdf;
            }
            if let Some(cipher) = req.cipher {
                sess.vault.cipher = cipher;
            }
            let creds_copy = MasterCredentials {
                password: sess.credentials.password.clone(),
                keyfile_bytes: sess.credentials.keyfile_bytes.clone(),
            };
            (sess.vault.clone(), creds_copy, sess.location.clone())
        };

        let bytes = tauri::async_runtime::spawn_blocking(move || {
            let raw = save_kdbx_bytes(&vault_clone, &creds_clone).map_err(|e| e.to_string())?;
            Ok::<_, String>(Zeroizing::new(raw))
        })
        .await
        .map_err(|e| format!("Background re-encryption failed: {e}"))??;

        write_bytes_to_location(&app, &loc_clone, bytes.as_slice())?;

        if let Ok(mut sess_guard) = state.session.lock() {
            if let Some(ref mut sess) = *sess_guard {
                sess.dirty = false;
            }
        }
    }

    build_status(&state)
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
fn export_vault_backup(
    dest_path: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<String, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let loc = resolve_location(&app, &dest_path, ".kdbx")?;
    let bytes =
        Zeroizing::new(save_kdbx_bytes(&sess.vault, &sess.credentials).map_err(|e| e.to_string())?);
    write_bytes_to_location(&app, &loc, bytes.as_slice())?;
    Ok(loc.display_string())
}

#[tauri::command]
fn generate_pq_keypair_cmd() -> Result<MlKem1024Keypair, String> {
    generate_mlkem1024_keypair().map_err(|e| e.to_string())
}

#[tauri::command]
fn export_pq_armored_vault(
    dest_path: String,
    public_key_b64: String,
    app: AppHandle,
    state: State<'_, Arc<SharedState>>,
) -> Result<String, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();

    let kdbx_bytes =
        Zeroizing::new(save_kdbx_bytes(&sess.vault, &sess.credentials).map_err(|e| e.to_string())?);
    let sealed =
        pq_seal_bytes(kdbx_bytes.as_slice(), &public_key_b64).map_err(|e| e.to_string())?;
    let loc = resolve_location(&app, &dest_path, ".kdbx.pq")?;
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
    let sealed = read_bytes_from_location(&app, &src_loc)?;
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
        return Ok(false);
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
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
        return Err(
            "Biometric Vault Unlock is enforced via native OS BiometricPrompt / Face ID on Android & iOS."
                .to_string(),
        );
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
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

    let slot_path = biometric_slot_path(&app, &canonical)?;
    if slot_path.exists() {
        if let Ok(meta) = fs::metadata(&slot_path) {
            let zeros = vec![0u8; meta.len() as usize];
            let _ = fs::write(&slot_path, zeros);
        }
        let _ = fs::remove_file(&slot_path);
    }
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
        return Err(
            "Biometric Vault Unlock is only available on Android & iOS devices.".to_string(),
        );
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        use tauri_plugin_biometric::{AuthOptions, BiometricExt};

        let location = resolve_location(&app, &path, ".kdbx")?;
        let canonical = location.display_string();
        let slot_path = biometric_slot_path(&app, &canonical)?;
        if !slot_path.exists() {
            return Err("Biometric unlock is not enabled for this vault".to_string());
        }

        // Enforce native OS BiometricPrompt / Face ID in Rust BEFORE unsealing keyslot
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

        let device_secret = load_or_create_device_secret(&app)?;
        let vault_id = vault_slot_id(&canonical);
        let slot_bytes =
            fs::read(&slot_path).map_err(|e| format!("Failed to read biometric keyslot: {e}"))?;
        let bio_creds = unseal_biometric_slot(&slot_bytes, &device_secret, &vault_id)
            .map_err(|e| e.to_string())?;

        let saved_kf_path = bio_creds.keyfile_path.clone();
        let keyfile_bytes = match saved_kf_path {
            Some(ref p) => {
                let kf_loc = resolve_location(&app, p, ".keyx")?;
                Some(read_bytes_from_location(&app, &kf_loc)?)
            }
            None => None,
        };

        let credentials = MasterCredentials::from_password_and_keyfile(
            bio_creds.master_password.clone(),
            keyfile_bytes,
        )
        .map_err(|e| e.to_string())?;

        let raw_bytes = read_bytes_from_location(&app, &location)?;

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
            *sess_guard = Some(UnlockedSession {
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
                    monitor_state
                        .clipboard_generation
                        .fetch_add(1, Ordering::SeqCst);
                    let _ = app_handle.clipboard().clear();
                    let _ = app_handle.emit("vault-auto-locked", ());
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
            get_vault_status,
            create_vault,
            open_vault,
            lock_vault,
            save_vault,
            move_vault_to_path,
            generate_keyfile_to_path,
            list_groups,
            create_group,
            delete_group,
            list_entries,
            get_entry,
            copy_entry_password,
            upsert_entry,
            delete_entry,
            toggle_favorite,
            get_totp_code,
            generate_password_cmd,
            generate_passphrase_cmd,
            evaluate_password_cmd,
            copy_secret_with_auto_clear,
            clear_clipboard_now,
            update_security_settings,
            run_security_audit_cmd,
            export_vault_backup,
            generate_pq_keypair_cmd,
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
