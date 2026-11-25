use std::collections::HashMap;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::generator::evaluate_password;
use crate::model::Vault;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditIssueItem {
    pub entry_id: Uuid,
    pub title: String,
    pub username: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditReport {
    pub total_entries: usize,
    pub weak_passwords: Vec<AuditIssueItem>,
    pub reused_passwords: Vec<AuditIssueItem>,
    pub expired_entries: Vec<AuditIssueItem>,
    pub missing_totp_count: usize,
    pub kdf_meets_safe_floor: bool,
    pub kdf_summary: String,
    pub cipher_summary: String,
    pub post_quantum_ready: bool,
    pub overall_score: u8,
}

/// Run a 100% offline cryptographic & password-hygiene audit on the unlocked vault.
/// Entries in the Recycle Bin are excluded so deleted credentials do not penalize the score.
pub fn run_vault_audit(vault: &Vault) -> SecurityAuditReport {
    let recycle_id = if vault.meta.recycle_bin_enabled && !vault.meta.recycle_bin_uuid.is_nil() {
        Some(vault.meta.recycle_bin_uuid)
    } else {
        None
    };
    let entries: Vec<_> = vault
        .all_entries()
        .into_iter()
        .filter(|(gid, _)| Some(*gid) != recycle_id)
        .collect();
    let total_entries = entries.len();
    let now = Utc::now();

    let mut weak_passwords = Vec::new();
    let mut expired_entries = Vec::new();
    let mut missing_totp_count = 0usize;

    // Group entries by SHA-256(password) to detect password reuse without storing plaintext in report
    let mut hash_groups: HashMap<[u8; 32], Vec<(Uuid, String, String)>> = HashMap::new();

    for (_, entry) in &entries {
        let pw = entry.password.expose();
        if !pw.is_empty() {
            let report = evaluate_password(pw);
            if report.entropy_bits < 60.0 {
                weak_passwords.push(AuditIssueItem {
                    entry_id: entry.uuid,
                    title: entry.title.clone(),
                    username: entry.username.clone(),
                    detail: format!(
                        "{} ({:.1} bits / {:.1} PQ-bits)",
                        report.strength, report.entropy_bits, report.post_quantum_bits
                    ),
                });
            }

            let mut digest = [0u8; 32];
            digest.copy_from_slice(&Sha256::digest(pw.as_bytes()));
            hash_groups.entry(digest).or_default().push((
                entry.uuid,
                entry.title.clone(),
                entry.username.clone(),
            ));
        }

        if entry.times.expires && entry.times.expiry_time < now {
            expired_entries.push(AuditIssueItem {
                entry_id: entry.uuid,
                title: entry.title.clone(),
                username: entry.username.clone(),
                detail: format!("Expired on {}", entry.times.expiry_time.format("%Y-%m-%d")),
            });
        }

        if entry.totp_uri().is_none() {
            missing_totp_count += 1;
        }
    }

    let mut reused_passwords = Vec::new();
    for group in hash_groups.values() {
        if group.len() > 1 {
            let count = group.len();
            for (id, title, username) in group {
                reused_passwords.push(AuditIssueItem {
                    entry_id: *id,
                    title: title.clone(),
                    username: username.clone(),
                    detail: format!("Shared across {count} entries"),
                });
            }
        }
    }

    let kdf_meets_safe_floor = vault.kdf.meets_safe_floor();
    let kdf_summary = format!(
        "{:?} v0x{:02x} — {} MiB, {} rounds, {} lanes",
        vault.kdf.algorithm,
        vault.kdf.version,
        vault.kdf.memory_mib,
        vault.kdf.iterations,
        vault.kdf.parallelism
    );
    let cipher_summary = vault.cipher.display_name().to_string();
    let post_quantum_ready = kdf_meets_safe_floor && weak_passwords.is_empty();

    let mut score: i32 = 100;
    if !kdf_meets_safe_floor {
        score -= 25;
    }
    score -= (weak_passwords.len() as i32 * 10).min(40);
    score -= (reused_passwords.len() as i32 * 8).min(30);
    score -= (expired_entries.len() as i32 * 5).min(15);

    SecurityAuditReport {
        total_entries,
        weak_passwords,
        reused_passwords,
        expired_entries,
        missing_totp_count,
        kdf_meets_safe_floor,
        kdf_summary,
        cipher_summary,
        post_quantum_ready,
        overall_score: score.clamp(0, 100) as u8,
    }
}
