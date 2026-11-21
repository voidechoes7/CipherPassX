#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use cipherpass_core::{
    atomic_write_file, evaluate_password, generate_keyfile_v2_xml, generate_mlkem1024_keypair,
    generate_passphrase, generate_password, generate_totp_now, open_kdbx_file, pq_seal_bytes,
    pq_unseal_bytes, run_vault_audit, save_kdbx_bytes, save_kdbx_file_atomic, CipherAlgorithm,
    CustomField, EntropyReport, GeneratedSecret, KdfAlgorithm, KdfConfig, MasterCredentials,
    MlKem1024Keypair, PassphraseGenOptions, PasswordGenOptions, ProtectedString,
    SecurityAuditReport, TotpCode, Vault, VaultEntry, VaultGroup,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;
use zeroize::Zeroizing;

struct UnlockedSession {
    vault: Vault,
    credentials: MasterCredentials,
    path: PathBuf,
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
    EntrySummaryDto {
        id: e.uuid.to_string(),
        group_id: group_id.to_string(),
        title: e.title.clone(),
        username: e.username.clone(),
        url: e.url.clone(),
        favorite: e.is_favorite(),
        has_totp: e.totp_uri().is_some(),
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
            path: Some(sess.path.to_string_lossy().to_string()),
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
fn get_vault_status(state: State<'_, Arc<SharedState>>) -> Result<VaultStatusDto, String> {
    build_status(&state)
}

#[tauri::command]
fn create_vault(
    req: CreateVaultRequest,
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

    let keyfile_bytes = match req.keyfile_path {
        Some(ref p) if !p.trim().is_empty() => {
            Some(fs::read(p).map_err(|e| format!("Failed to read keyfile: {e}"))?)
        }
        _ => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password, keyfile_bytes)
            .map_err(|e| e.to_string())?;

    let vault = Vault::new(req.database_name, req.cipher, kdf);
    let path = PathBuf::from(&req.path);
    save_kdbx_file_atomic(&path, &vault, &credentials).map_err(|e| e.to_string())?;

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        *sess_guard = Some(UnlockedSession {
            vault,
            credentials,
            path,
            last_activity: Instant::now(),
            dirty: false,
        });
    }

    build_status(&state)
}

#[tauri::command]
fn open_vault(
    req: OpenVaultRequest,
    state: State<'_, Arc<SharedState>>,
) -> Result<VaultStatusDto, String> {
    let keyfile_bytes = match req.keyfile_path {
        Some(ref p) if !p.trim().is_empty() => {
            Some(fs::read(p).map_err(|e| format!("Failed to read keyfile: {e}"))?)
        }
        _ => None,
    };

    let credentials =
        MasterCredentials::from_password_and_keyfile(req.master_password, keyfile_bytes)
            .map_err(|e| e.to_string())?;

    let path = PathBuf::from(&req.path);
    let vault = open_kdbx_file(&path, &credentials).map_err(|e| e.to_string())?;

    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        *sess_guard = Some(UnlockedSession {
            vault,
            credentials,
            path,
            last_activity: Instant::now(),
            dirty: false,
        });
    }

    build_status(&state)
}

#[tauri::command]
fn lock_vault(state: State<'_, Arc<SharedState>>) -> Result<VaultStatusDto, String> {
    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        if let Some(mut sess) = sess_guard.take() {
            sess.vault.zeroize_secrets();
            // `sess` drops here -> MasterCredentials and Vault both zeroize on drop.
        }
    }
    build_status(&state)
}

#[tauri::command]
fn save_vault(state: State<'_, Arc<SharedState>>) -> Result<VaultStatusDto, String> {
    {
        let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
        let sess = sess_guard
            .as_mut()
            .ok_or_else(|| "Vault is locked".to_string())?;
        sess.touch();
        save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials)
            .map_err(|e| e.to_string())?;
        sess.dirty = false;
    }
    build_status(&state)
}

#[tauri::command]
fn generate_keyfile_to_path(path: String) -> Result<String, String> {
    let xml = generate_keyfile_v2_xml();
    atomic_write_file(PathBuf::from(&path).as_path(), xml.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path)
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
    save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials).map_err(|e| e.to_string())?;
    sess.dirty = false;
    Ok(dto)
}

#[tauri::command]
fn delete_group(group_id: String, state: State<'_, Arc<SharedState>>) -> Result<(), String> {
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
    save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials).map_err(|e| e.to_string())?;
    sess.dirty = false;
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
fn upsert_entry(
    req: EntryUpsertRequest,
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

        // Snapshot previous state before modifying
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

    save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials).map_err(|e| e.to_string())?;
    sess.dirty = false;

    Ok(detail)
}

#[tauri::command]
fn delete_entry(entry_id: String, state: State<'_, Arc<SharedState>>) -> Result<(), String> {
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

    save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials).map_err(|e| e.to_string())?;
    sess.dirty = false;
    Ok(())
}

#[tauri::command]
fn toggle_favorite(
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
        .find_entry_mut(uuid)
        .ok_or_else(|| "Entry not found".to_string())?;
    let next_fav = !entry.is_favorite();
    entry.set_favorite(next_fav);
    entry.times.last_modification_time = Utc::now();
    let dto = entry_to_detail(gid, entry);

    save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials).map_err(|e| e.to_string())?;
    sess.dirty = false;
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
fn update_security_settings(
    req: SecuritySettingsRequest,
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

        save_kdbx_file_atomic(&sess.path, &sess.vault, &sess.credentials)
            .map_err(|e| e.to_string())?;
        sess.dirty = false;
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
    state: State<'_, Arc<SharedState>>,
) -> Result<String, String> {
    let mut sess_guard = state.session.lock().map_err(|e| e.to_string())?;
    let sess = sess_guard
        .as_mut()
        .ok_or_else(|| "Vault is locked".to_string())?;
    sess.touch();
    save_kdbx_file_atomic(
        PathBuf::from(&dest_path).as_path(),
        &sess.vault,
        &sess.credentials,
    )
    .map_err(|e| e.to_string())?;
    Ok(dest_path)
}

#[tauri::command]
fn generate_pq_keypair_cmd() -> Result<MlKem1024Keypair, String> {
    generate_mlkem1024_keypair().map_err(|e| e.to_string())
}

#[tauri::command]
fn export_pq_armored_vault(
    dest_path: String,
    public_key_b64: String,
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
    atomic_write_file(PathBuf::from(&dest_path).as_path(), &sealed).map_err(|e| e.to_string())?;
    Ok(dest_path)
}

#[tauri::command]
fn unseal_pq_armored_vault(
    src_pq_path: String,
    dest_kdbx_path: String,
    secret_key_b64: String,
) -> Result<String, String> {
    let secret_key_b64 = Zeroizing::new(secret_key_b64);
    let sealed = fs::read(&src_pq_path).map_err(|e| format!("Failed to read .kdbx.pq: {e}"))?;
    let kdbx_bytes =
        pq_unseal_bytes(&sealed, secret_key_b64.as_str()).map_err(|e| e.to_string())?;
    atomic_write_file(
        PathBuf::from(&dest_kdbx_path).as_path(),
        kdbx_bytes.as_slice(),
    )
    .map_err(|e| e.to_string())?;
    Ok(dest_kdbx_path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let shared_state = Arc::new(SharedState::new());
    let monitor_state = Arc::clone(&shared_state);

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(shared_state)
        .setup(move |app| {
            // Background inactivity auto-lock watchdog (zeroizes secrets & clears clipboard)
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
            get_vault_status,
            create_vault,
            open_vault,
            lock_vault,
            save_vault,
            generate_keyfile_to_path,
            list_groups,
            create_group,
            delete_group,
            list_entries,
            get_entry,
            upsert_entry,
            delete_entry,
            toggle_favorite,
            get_totp_code,
            generate_password_cmd,
            generate_passphrase_cmd,
            evaluate_password_cmd,
            copy_secret_with_auto_clear,
            update_security_settings,
            run_security_audit_cmd,
            export_vault_backup,
            generate_pq_keypair_cmd,
            export_pq_armored_vault,
            unseal_pq_armored_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherPass Tauri application");
}
