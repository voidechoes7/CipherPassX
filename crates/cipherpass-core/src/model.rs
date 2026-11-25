use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::{CipherAlgorithm, KdfConfig};
use crate::variant_dict::VariantDictionary;

pub const FAVORITE_TAG: &str = "Favorites";

/// Protected in-memory string that is zeroized automatically when dropped.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ProtectedString(String);

impl ProtectedString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedString([REDACTED])")
    }
}

impl From<String> for ProtectedString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for ProtectedString {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryTimes {
    pub creation_time: DateTime<Utc>,
    pub last_modification_time: DateTime<Utc>,
    pub last_access_time: DateTime<Utc>,
    pub expiry_time: DateTime<Utc>,
    pub expires: bool,
    pub usage_count: u64,
    pub location_changed: DateTime<Utc>,
}

impl Default for EntryTimes {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            creation_time: now,
            last_modification_time: now,
            last_access_time: now,
            expiry_time: now,
            expires: false,
            usage_count: 0,
            location_changed: now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub key: String,
    pub value: ProtectedString,
    pub protected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryHistoryItem {
    pub title: String,
    pub username: String,
    pub password: ProtectedString,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomField>,
    pub times: EntryTimes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub uuid: Uuid,
    pub icon_id: u32,
    pub title: String,
    pub username: String,
    pub password: ProtectedString,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub custom_fields: Vec<CustomField>,
    pub history: Vec<EntryHistoryItem>,
    pub times: EntryTimes,
    pub custom_data: BTreeMap<String, String>,
    pub auto_type_enabled: bool,
}

impl VaultEntry {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            icon_id: 0,
            title: title.into(),
            username: String::new(),
            password: ProtectedString::default(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            custom_fields: Vec::new(),
            history: Vec::new(),
            times: EntryTimes::default(),
            custom_data: BTreeMap::new(),
            auto_type_enabled: true,
        }
    }

    pub fn is_favorite(&self) -> bool {
        self.tags
            .iter()
            .any(|t| t.eq_ignore_ascii_case(FAVORITE_TAG))
    }

    pub fn set_favorite(&mut self, fav: bool) {
        self.tags.retain(|t| !t.eq_ignore_ascii_case(FAVORITE_TAG));
        if fav {
            self.tags.push(FAVORITE_TAG.to_string());
        }
    }

    /// Snapshot current state into password/entry history before applying edits.
    pub fn push_history_snapshot(&mut self, max_items: usize) {
        if max_items == 0 {
            return;
        }
        self.history.push(EntryHistoryItem {
            title: self.title.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            url: self.url.clone(),
            notes: self.notes.clone(),
            tags: self.tags.clone(),
            custom_fields: self.custom_fields.clone(),
            times: self.times.clone(),
        });
        while self.history.len() > max_items {
            self.history.remove(0);
        }
    }

    /// Extract TOTP `otpauth://` URI from standard KeePassXC (`otp`) or KeePassDX (`TimeOtp-Secret-Base32`) fields.
    pub fn totp_uri(&self) -> Option<String> {
        // 1. KeePassXC / standard `otp` field
        if let Some(f) = self
            .custom_fields
            .iter()
            .find(|f| f.key.eq_ignore_ascii_case("otp"))
        {
            let val = f.value.expose().trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }

        // 2. KeePassDX / KeePass 2.47+ `TimeOtp-Secret-Base32`
        if let Some(secret_field) = self
            .custom_fields
            .iter()
            .find(|f| f.key == "TimeOtp-Secret-Base32")
        {
            let secret = secret_field.value.expose().trim();
            if !secret.is_empty() {
                let period = self
                    .custom_fields
                    .iter()
                    .find(|f| f.key == "TimeOtp-Period")
                    .map(|f| f.value.expose().trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "30".to_string());
                let digits = self
                    .custom_fields
                    .iter()
                    .find(|f| f.key == "TimeOtp-Length")
                    .map(|f| f.value.expose().trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "6".to_string());
                let alg_raw = self
                    .custom_fields
                    .iter()
                    .find(|f| f.key == "TimeOtp-Algorithm")
                    .map(|f| f.value.expose().trim().to_uppercase())
                    .unwrap_or_else(|| "SHA1".to_string());
                let alg = if alg_raw.contains("256") {
                    "SHA256"
                } else if alg_raw.contains("512") {
                    "SHA512"
                } else {
                    "SHA1"
                };
                return Some(format!(
                    "otpauth://totp/{}?secret={}&algorithm={}&digits={}&period={}",
                    self.title.replace(' ', "%20"),
                    secret,
                    alg,
                    digits,
                    period
                ));
            }
        }

        None
    }

    /// Set or clear the `otp` protected custom field.
    pub fn set_totp_uri(&mut self, uri: Option<String>) {
        self.custom_fields
            .retain(|f| !f.key.eq_ignore_ascii_case("otp"));
        if let Some(u) = uri {
            let trimmed = u.trim();
            if !trimmed.is_empty() {
                self.custom_fields.push(CustomField {
                    key: "otp".to_string(),
                    value: ProtectedString::new(trimmed),
                    protected: true,
                });
            }
        }
    }

    pub fn matches_query(&self, query_lower: &str) -> bool {
        if query_lower.is_empty() {
            return true;
        }
        self.title.to_lowercase().contains(query_lower)
            || self.username.to_lowercase().contains(query_lower)
            || self.url.to_lowercase().contains(query_lower)
            || self.notes.to_lowercase().contains(query_lower)
            || self
                .tags
                .iter()
                .any(|t| t.to_lowercase().contains(query_lower))
            || self
                .custom_fields
                .iter()
                .any(|f| f.key.to_lowercase().contains(query_lower))
    }

    pub fn zeroize_secrets(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
        for f in &mut self.custom_fields {
            f.value.zeroize();
        }
        for h in &mut self.history {
            h.username.zeroize();
            h.password.zeroize();
            h.notes.zeroize();
            for f in &mut h.custom_fields {
                f.value.zeroize();
            }
        }
    }
}

impl Drop for EntryHistoryItem {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
        self.notes.zeroize();
        for f in &mut self.custom_fields {
            f.value.zeroize();
        }
    }
}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultGroup {
    pub uuid: Uuid,
    pub name: String,
    pub notes: String,
    pub icon_id: u32,
    pub is_expanded: bool,
    pub times: EntryTimes,
    pub entries: Vec<VaultEntry>,
    pub subgroups: Vec<VaultGroup>,
}

impl VaultGroup {
    pub fn new(name: impl Into<String>, icon_id: u32) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: name.into(),
            notes: String::new(),
            icon_id,
            is_expanded: true,
            times: EntryTimes::default(),
            entries: Vec::new(),
            subgroups: Vec::new(),
        }
    }

    pub fn find_group(&self, id: Uuid) -> Option<&VaultGroup> {
        if self.uuid == id {
            return Some(self);
        }
        for sub in &self.subgroups {
            if let Some(found) = sub.find_group(id) {
                return Some(found);
            }
        }
        None
    }

    pub fn find_group_mut(&mut self, id: Uuid) -> Option<&mut VaultGroup> {
        if self.uuid == id {
            return Some(self);
        }
        for sub in &mut self.subgroups {
            if let Some(found) = sub.find_group_mut(id) {
                return Some(found);
            }
        }
        None
    }

    pub fn remove_subgroup(&mut self, id: Uuid) -> Option<VaultGroup> {
        if let Some(pos) = self.subgroups.iter().position(|g| g.uuid == id) {
            return Some(self.subgroups.remove(pos));
        }
        for sub in &mut self.subgroups {
            if let Some(removed) = sub.remove_subgroup(id) {
                return Some(removed);
            }
        }
        None
    }

    pub fn find_entry(&self, entry_id: Uuid) -> Option<(Uuid, &VaultEntry)> {
        if let Some(entry) = self.entries.iter().find(|e| e.uuid == entry_id) {
            return Some((self.uuid, entry));
        }
        for sub in &self.subgroups {
            if let Some(found) = sub.find_entry(entry_id) {
                return Some(found);
            }
        }
        None
    }

    pub fn find_entry_mut(&mut self, entry_id: Uuid) -> Option<(Uuid, &mut VaultEntry)> {
        let gid = self.uuid;
        if let Some(entry) = self.entries.iter_mut().find(|e| e.uuid == entry_id) {
            return Some((gid, entry));
        }
        for sub in &mut self.subgroups {
            if let Some(found) = sub.find_entry_mut(entry_id) {
                return Some(found);
            }
        }
        None
    }

    pub fn remove_entry(&mut self, entry_id: Uuid) -> Option<VaultEntry> {
        if let Some(pos) = self.entries.iter().position(|e| e.uuid == entry_id) {
            return Some(self.entries.remove(pos));
        }
        for sub in &mut self.subgroups {
            if let Some(removed) = sub.remove_entry(entry_id) {
                return Some(removed);
            }
        }
        None
    }

    pub fn collect_all_entries<'a>(&'a self, out: &mut Vec<(Uuid, &'a VaultEntry)>) {
        for entry in &self.entries {
            out.push((self.uuid, entry));
        }
        for sub in &self.subgroups {
            sub.collect_all_entries(out);
        }
    }

    pub fn zeroize_secrets(&mut self) {
        for e in &mut self.entries {
            e.zeroize_secrets();
        }
        for sub in &mut self.subgroups {
            sub.zeroize_secrets();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeletedObject {
    pub uuid: Uuid,
    pub deletion_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    pub generator: String,
    pub database_name: String,
    pub database_description: String,
    pub default_username: String,
    pub recycle_bin_enabled: bool,
    pub recycle_bin_uuid: Uuid,
    pub history_max_items: usize,
    pub history_max_size: usize,
    pub custom_data: BTreeMap<String, String>,
}

impl Default for VaultMeta {
    fn default() -> Self {
        Self {
            generator: "CipherPass".to_string(),
            database_name: "CipherPass Vault".to_string(),
            database_description: "100% Offline KDBX 4 Vault".to_string(),
            default_username: String::new(),
            recycle_bin_enabled: true,
            recycle_bin_uuid: Uuid::nil(),
            history_max_items: 15,
            history_max_size: 6 * 1024 * 1024,
            custom_data: BTreeMap::new(),
        }
    }
}

/// Raw inner-header binary attachment (preserved transparently for KeePassXC/DX compatibility).
#[derive(Debug, Clone)]
pub struct InnerBinary {
    pub flags: u8,
    pub data: Vec<u8>,
}

/// Complete in-memory representation of a KDBX 4 / 4.1 vault.
#[derive(Debug, Clone)]
pub struct Vault {
    pub version_minor: u16,
    pub cipher: CipherAlgorithm,
    pub kdf: KdfConfig,
    pub compression: bool,
    pub meta: VaultMeta,
    pub root_group: VaultGroup,
    pub deleted_objects: Vec<DeletedObject>,
    pub inner_binaries: Vec<InnerBinary>,
    pub public_custom_data: Option<VariantDictionary>,
}

impl Vault {
    pub fn new(name: impl Into<String>, cipher: CipherAlgorithm, kdf: KdfConfig) -> Self {
        let name_str = name.into();
        let mut root = VaultGroup::new(&name_str, 48);
        root.subgroups.push(VaultGroup::new("General", 48));
        root.subgroups.push(VaultGroup::new("Email", 19));
        root.subgroups
            .push(VaultGroup::new("Banking & Finance", 37));
        root.subgroups.push(VaultGroup::new("Developer & SSH", 30));
        root.subgroups.push(VaultGroup::new("2FA & Recovery", 1));

        let meta = VaultMeta {
            database_name: name_str,
            ..Default::default()
        };

        Self {
            version_minor: 0, // KDBX 4.0 (maximum compatibility with KeePassXC & KeePassDX)
            cipher,
            kdf,
            compression: true,
            meta,
            root_group: root,
            deleted_objects: Vec::new(),
            inner_binaries: Vec::new(),
            public_custom_data: None,
        }
    }

    pub fn all_entries(&self) -> Vec<(Uuid, &VaultEntry)> {
        let mut out = Vec::new();
        self.root_group.collect_all_entries(&mut out);
        out
    }

    pub fn search(&self, query: &str) -> Vec<(Uuid, &VaultEntry)> {
        let q = query.trim().to_lowercase();
        self.all_entries()
            .into_iter()
            .filter(|(_, e)| e.matches_query(&q))
            .collect()
    }

    pub fn zeroize_secrets(&mut self) {
        self.root_group.zeroize_secrets();
        for bin in &mut self.inner_binaries {
            bin.data.zeroize();
        }
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}
