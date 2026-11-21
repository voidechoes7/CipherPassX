use cipherpass_core::{
    evaluate_password, generate_keyfile_v2_xml, generate_passphrase, generate_password,
    generate_totp_at, open_kdbx_bytes, open_kdbx_file, parse_keyfile_bytes, parse_totp_uri,
    run_vault_audit, save_kdbx_bytes, save_kdbx_file_atomic, CipherAlgorithm, CipherPassError,
    CustomField, KdfAlgorithm, KdfConfig, MasterCredentials, PassphraseGenOptions,
    PasswordGenOptions, ProtectedString, Vault, VaultEntry,
};

fn build_sample_vault(cipher: CipherAlgorithm, kdf: KdfConfig) -> Vault {
    let mut vault = Vault::new("CipherPass Synthetic KDBX4", cipher, kdf);
    let mut entry = VaultEntry::new("GitHub Production");
    entry.username = "voidechoes7".to_string();
    entry.password = ProtectedString::new("S3cur3!PQ#Passphrase-2026");
    entry.url = "https://github.com".to_string();
    entry.notes = "Primary repository credentials".to_string();
    entry.set_favorite(true);
    entry.tags.push("dev".to_string());
    entry.tags.push("critical".to_string());
    entry.custom_fields.push(CustomField {
        key: "RecoveryCode".to_string(),
        value: ProtectedString::new("ABCD-1234-EFGH-5678"),
        protected: true,
    });
    entry.set_totp_uri(Some(
        "otpauth://totp/GitHub:voidechoes7?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub"
            .to_string(),
    ));

    // Record a password history snapshot
    entry.push_history_snapshot(10);
    entry.password = ProtectedString::new("R0tat3d!PQ#UltraSecure-99");

    vault.root_group.subgroups[0].entries.push(entry);
    vault
}

#[test]
fn kdbx4_chacha20_argon2id_full_roundtrip() {
    let vault = build_sample_vault(CipherAlgorithm::ChaCha20, KdfConfig::test_fast());
    let creds = MasterCredentials::from_password("master-pass-pq-2026!");

    let bytes = save_kdbx_bytes(&vault, &creds).expect("save KDBX 4 ChaCha20");
    let opened = open_kdbx_bytes(&bytes, &creds).expect("open KDBX 4 ChaCha20");

    assert_eq!(opened.cipher, CipherAlgorithm::ChaCha20);
    assert_eq!(opened.kdf.algorithm, KdfAlgorithm::Argon2id);
    assert_eq!(opened.meta.database_name, "CipherPass Synthetic KDBX4");

    let all = opened.all_entries();
    assert_eq!(all.len(), 1);
    let (_, e) = all[0];
    assert_eq!(e.title, "GitHub Production");
    assert_eq!(e.username, "voidechoes7");
    assert_eq!(e.password.expose(), "R0tat3d!PQ#UltraSecure-99");
    assert!(e.is_favorite());
    assert!(e.tags.contains(&"dev".to_string()));
    assert_eq!(e.history.len(), 1);
    assert_eq!(e.history[0].password.expose(), "S3cur3!PQ#Passphrase-2026");

    let recovery = e
        .custom_fields
        .iter()
        .find(|f| f.key == "RecoveryCode")
        .expect("custom protected field");
    assert!(recovery.protected);
    assert_eq!(recovery.value.expose(), "ABCD-1234-EFGH-5678");
    assert!(e.totp_uri().is_some());
}

#[test]
fn kdbx41_aes256_cbc_argon2d_uncompressed_roundtrip() {
    let mut kdf = KdfConfig::test_fast();
    kdf.algorithm = KdfAlgorithm::Argon2d;
    let mut vault = build_sample_vault(CipherAlgorithm::Aes256Cbc, kdf);
    vault.version_minor = 1; // KDBX 4.1
    vault.compression = false;

    let creds = MasterCredentials::from_password("aes256-argon2d-test");
    let bytes = save_kdbx_bytes(&vault, &creds).expect("save KDBX 4.1 AES-256-CBC");
    let opened = open_kdbx_bytes(&bytes, &creds).expect("open KDBX 4.1 AES-256-CBC");

    assert_eq!(opened.version_minor, 1);
    assert_eq!(opened.cipher, CipherAlgorithm::Aes256Cbc);
    assert_eq!(opened.kdf.algorithm, KdfAlgorithm::Argon2d);
    assert!(!opened.compression);
    assert_eq!(
        opened.all_entries()[0].1.password.expose(),
        "R0tat3d!PQ#UltraSecure-99"
    );
}

#[test]
fn keyfile_v2_xml_authentication_and_integrity() {
    let kf_xml = generate_keyfile_v2_xml();
    let kf_bytes = kf_xml.as_bytes().to_vec();

    // Valid keyfile parses cleanly
    let parsed = parse_keyfile_bytes(&kf_bytes).expect("parse generated Keyfile v2.0 XML");
    assert_eq!(parsed.len(), 32);

    // Tampered keyfile Hash must be rejected
    let tampered_xml = kf_xml.replace("Hash=\"", "Hash=\"00000000\" ignore=\"");
    assert!(matches!(
        parse_keyfile_bytes(tampered_xml.as_bytes()),
        Err(CipherPassError::InvalidKeyfile(_))
    ));

    // Save with password + keyfile
    let vault = build_sample_vault(CipherAlgorithm::ChaCha20, KdfConfig::test_fast());
    let creds = MasterCredentials::from_password_and_keyfile(
        Some("strong-pw".to_string()),
        Some(kf_bytes.clone()),
    )
    .unwrap();
    let bytes = save_kdbx_bytes(&vault, &creds).expect("save with keyfile");

    // Reopen with password + keyfile succeeds
    let opened = open_kdbx_bytes(&bytes, &creds).expect("open with password + keyfile");
    assert_eq!(opened.all_entries().len(), 1);

    // Missing keyfile fails authentication
    let pw_only = MasterCredentials::from_password("strong-pw");
    assert!(matches!(
        open_kdbx_bytes(&bytes, &pw_only),
        Err(CipherPassError::HeaderHmacMismatch)
    ));

    // Wrong password fails authentication
    let wrong_pw =
        MasterCredentials::from_password_and_keyfile(Some("wrong-pw".to_string()), Some(kf_bytes))
            .unwrap();
    assert!(matches!(
        open_kdbx_bytes(&bytes, &wrong_pw),
        Err(CipherPassError::HeaderHmacMismatch)
    ));
}

#[test]
fn tamper_detection_header_and_hmac_blocks() {
    let vault = build_sample_vault(CipherAlgorithm::ChaCha20, KdfConfig::test_fast());
    let creds = MasterCredentials::from_password("tamper-test-password");
    let valid_bytes = save_kdbx_bytes(&vault, &creds).expect("save valid kdbx");

    // 1. Flip a byte inside the outer header (byte 18 is inside CipherID data)
    let mut header_tampered = valid_bytes.clone();
    header_tampered[18] ^= 0x01;
    let err = open_kdbx_bytes(&header_tampered, &creds).unwrap_err();
    assert!(
        matches!(
            err,
            CipherPassError::HeaderHashMismatch | CipherPassError::UnsupportedCipher(_)
        ),
        "Unexpected error for outer header tamper: {err:?}"
    );

    // 2. Flip a byte inside the encrypted HMAC block payload (near the end, before the 36-byte terminator)
    let mut block_tampered = valid_bytes.clone();
    let target_idx = block_tampered.len() - 45;
    block_tampered[target_idx] ^= 0x80;
    let err = open_kdbx_bytes(&block_tampered, &creds).unwrap_err();
    assert!(
        matches!(err, CipherPassError::BlockHmacMismatch { .. }),
        "Expected BlockHmacMismatch, got: {err:?}"
    );
}

#[test]
fn rfc6238_totp_official_test_vectors() {
    // RFC 6238 Appendix B test secret for SHA1: "12345678901234567890"
    // Base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    let uri = "otpauth://totp/Test:user@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1";
    let cfg = parse_totp_uri(uri).expect("parse RFC 6238 URI");

    assert_eq!(generate_totp_at(&cfg, 59).code, "94287082");
    assert_eq!(generate_totp_at(&cfg, 1_111_111_109).code, "07081804");
    assert_eq!(generate_totp_at(&cfg, 1_234_567_890).code, "89005924");
    assert_eq!(generate_totp_at(&cfg, 2_000_000_000).code, "69279037");
}

#[test]
fn kdf_safe_floor_enforcement() {
    let default_kdf = KdfConfig::default();
    assert!(default_kdf.validate_safe_floor().is_ok());

    let weak_kdf = KdfConfig::test_fast();
    assert!(matches!(
        weak_kdf.validate_safe_floor(),
        Err(CipherPassError::UnsafeKdfParams(_))
    ));
}

#[test]
fn csprng_generator_and_diceware_entropy() {
    let pw = generate_password(&PasswordGenOptions {
        length: 28,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
        exclude_ambiguous: true,
    });
    assert_eq!(pw.value.chars().count(), 28);
    assert!(pw.entropy.entropy_bits > 150.0);
    assert!(pw.entropy.post_quantum_bits > 75.0);

    let phrase = generate_passphrase(&PassphraseGenOptions {
        word_count: 7,
        separator: "-".to_string(),
        capitalize: true,
        include_number: true,
    });
    assert_eq!(phrase.value.split('-').count(), 7);
    assert!(phrase.entropy.entropy_bits > 70.0);

    let weak = evaluate_password("password123");
    assert!(weak.entropy_bits < 45.0);
}

#[test]
fn atomic_save_and_reopen_leaves_no_tmp_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("personal.kdbx");

    let vault = build_sample_vault(CipherAlgorithm::ChaCha20, KdfConfig::test_fast());
    let creds = MasterCredentials::from_password("atomic-sync-test");

    save_kdbx_file_atomic(&vault_path, &vault, &creds).expect("atomic save 1");
    save_kdbx_file_atomic(&vault_path, &vault, &creds).expect("atomic save 2");

    let opened = open_kdbx_file(&vault_path, &creds).expect("open atomic file");
    assert_eq!(opened.all_entries().len(), 1);

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .collect();
    assert_eq!(entries.len(), 1, "No leftover .tmp files should exist");
}

#[test]
fn offline_security_audit_detects_weak_and_reused_passwords() {
    let mut vault = Vault::new(
        "Audit Test",
        CipherAlgorithm::ChaCha20,
        KdfConfig::default(),
    );
    let mut e1 = VaultEntry::new("Service A");
    e1.password = ProtectedString::new("123456");
    let mut e2 = VaultEntry::new("Service B");
    e2.password = ProtectedString::new("123456");
    vault.root_group.subgroups[0].entries.push(e1);
    vault.root_group.subgroups[0].entries.push(e2);

    let report = run_vault_audit(&vault);
    assert_eq!(report.total_entries, 2);
    assert_eq!(report.weak_passwords.len(), 2);
    assert_eq!(report.reused_passwords.len(), 2);
    assert!(report.kdf_meets_safe_floor);
    assert!(!report.post_quantum_ready);
}

#[test]
fn fips203_mlkem1024_post_quantum_armor_roundtrip_and_tamper_detection() {
    use cipherpass_core::{generate_mlkem1024_keypair, pq_seal_bytes, pq_unseal_bytes};

    let vault = build_sample_vault(CipherAlgorithm::ChaCha20, KdfConfig::test_fast());
    let creds = MasterCredentials::from_password("quantum-armor-master");
    let kdbx_bytes = save_kdbx_bytes(&vault, &creds).expect("save KDBX 4");

    let kp1 = generate_mlkem1024_keypair().expect("generate ML-KEM-1024 keypair 1");
    let kp2 = generate_mlkem1024_keypair().expect("generate ML-KEM-1024 keypair 2");
    assert_eq!(kp1.fingerprint.len(), 16);

    // Seal .kdbx inside FIPS 203 ML-KEM-1024 + ChaCha20-Poly1305 envelope
    let sealed = pq_seal_bytes(&kdbx_bytes, &kp1.public_key_b64).expect("PQ seal");

    // Unseal with matching ML-KEM-1024 secret key -> exact byte-for-byte match
    let unsealed = pq_unseal_bytes(&sealed, &kp1.secret_key_b64).expect("PQ unseal");
    assert_eq!(unsealed.as_slice(), kdbx_bytes.as_slice());

    // Reopen inner KDBX 4 vault cleanly
    let reopened = open_kdbx_bytes(unsealed.as_slice(), &creds).expect("open unsealed KDBX");
    assert_eq!(
        reopened.all_entries()[0].1.password.expose(),
        "R0tat3d!PQ#UltraSecure-99"
    );

    // Wrong ML-KEM-1024 secret key MUST fail authentication
    assert!(pq_unseal_bytes(&sealed, &kp2.secret_key_b64).is_err());

    // Flipping 1 bit in the sealed ciphertext MUST fail Poly1305 AAD/tag check
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(pq_unseal_bytes(&tampered, &kp1.secret_key_b64).is_err());
}
