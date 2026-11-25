//! Offensive & Defensive Security Audit Regression Test Suite (v0.7.0)
//!
//! Verifies all cryptographic, parsing, memory-hygiene, and DoS mitigations across:
//! - KDBX 4 / 4.1 framing, Argon2 KDF bounds, HMAC-SHA256 blocks, ChaCha20 & AES-256-CBC
//! - KDBX XML parser (XXE/DOCTYPE rejection, recursion depth caps, injection metacharacters)
//! - Keyfile v2.0 XML integrity & parser hardening
//! - NIST FIPS 203 ML-KEM-1024 post-quantum armor envelope & key validation
//! - Bitwarden Encrypted JSON / CSV interchange (Encrypt-then-MAC, KDF bounds, folder depth)
//! - Biometric keyslot (`CPBIO002` + legacy `CPBIO001`, AAD binding, redaction)
//! - TOTP RFC 6238 edge cases & secret redaction

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use cipherpass_core::crypto::{InnerStreamCipher, KdfConfig};
use cipherpass_core::kdbx_xml::parse_kdbx_xml;
use cipherpass_core::totp::TotpConfig;
use cipherpass_core::variant_dict::{VariantDictionary, VariantValue};
use cipherpass_core::{
    export_encrypted_bitwarden_json, generate_keyfile_v2_xml, generate_mlkem1024_keypair,
    generate_password, generate_totp_at, import_bitwarden_json, open_kdbx_bytes,
    parse_keyfile_bytes, parse_totp_uri, pq_seal_bytes, pq_unseal_bytes, save_kdbx_bytes,
    seal_biometric_slot, unseal_biometric_slot, validate_mlkem1024_key_b64,
    BiometricVaultCredentials, CipherAlgorithm, CustomField, KdfAlgorithm, MasterCredentials,
    PasswordGenOptions, ProtectedString, TotpAlgorithm, Vault, VaultEntry,
};
use sha2::{Digest, Sha256};

fn fast_test_kdf() -> KdfConfig {
    KdfConfig {
        algorithm: KdfAlgorithm::Argon2id,
        memory_mib: 1,
        iterations: 1,
        parallelism: 1,
        version: 0x13,
    }
}

fn build_synthetic_kdbx4_header_with_kdf(kdf_dict: &VariantDictionary) -> Vec<u8> {
    let mut out = Vec::new();
    // KDBX 4 signature + version 4.0
    out.extend_from_slice(&0x9AA2_D903u32.to_le_bytes());
    out.extend_from_slice(&0xB54B_FB67u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());

    let push_tlv = |buf: &mut Vec<u8>, id: u8, val: &[u8]| {
        buf.push(id);
        buf.extend_from_slice(&(val.len() as u32).to_le_bytes());
        buf.extend_from_slice(val);
    };

    // CipherID = ChaCha20
    let chacha_uuid: [u8; 16] = [
        0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5,
        0x9A,
    ];
    push_tlv(&mut out, 2, &chacha_uuid);
    // Compression = 1 (Gzip)
    push_tlv(&mut out, 3, &1u32.to_le_bytes());
    // MasterSeed = 32 bytes
    push_tlv(&mut out, 4, &[0x11u8; 32]);
    // EncryptionIV = 12 bytes
    push_tlv(&mut out, 7, &[0x22u8; 12]);
    // KdfParameters
    let kdf_bytes = kdf_dict.serialize();
    push_tlv(&mut out, 11, &kdf_bytes);
    // EndOfHeader
    push_tlv(&mut out, 0, b"\r\n\r\n");

    // Append dummy Header SHA-256 (32B) + Header HMAC (32B)
    let hdr_hash = Sha256::digest(&out);
    out.extend_from_slice(&hdr_hash);
    out.extend_from_slice(&[0u8; 32]);
    out
}

#[test]
fn kdbx4_bitflip_matrix_chacha20_and_aes256cbc() {
    for cipher in [CipherAlgorithm::ChaCha20, CipherAlgorithm::Aes256Cbc] {
        let mut vault = Vault::new("BitFlipAudit", cipher, fast_test_kdf());
        let mut e = VaultEntry::new("Production DB");
        e.username = "admin".to_string();
        e.password = ProtectedString::new("S3cur3!Pass#2026");
        vault.root_group.entries.push(e);

        let creds = MasterCredentials::from_password_and_keyfile(Some("Master!123".into()), None)
            .expect("creds");
        let kdbx = save_kdbx_bytes(&vault, &creds).expect("save kdbx");

        // Sanity check: unmodified opens cleanly
        assert!(open_kdbx_bytes(&kdbx, &creds).is_ok());

        // Sample positions spanning magic, header TLVs, Header SHA-256, Header HMAC,
        // first HMAC block MAC/length/payload, middle ciphertext, and terminating block
        let len = kdbx.len();
        let positions = [
            0,
            4,
            10,
            24,
            64,
            120,
            len / 3,
            len / 2,
            (len * 3) / 4,
            len - 40,
            len - 20,
            len - 5,
            len - 1,
        ];
        for pos in positions {
            let mut tampered = kdbx.clone();
            tampered[pos] ^= 0x01;
            assert!(
                open_kdbx_bytes(&tampered, &creds).is_err(),
                "Bit-flip at offset {pos}/{len} for cipher {cipher:?} was NOT rejected!"
            );
        }
    }
}

#[test]
fn kdbx4_rejects_unauthenticated_trailing_bytes() {
    let vault = Vault::new("TrailingCheck", CipherAlgorithm::ChaCha20, fast_test_kdf());
    let creds = MasterCredentials::from_password_and_keyfile(Some("Pass!".into()), None).unwrap();
    let mut kdbx = save_kdbx_bytes(&vault, &creds).unwrap();
    kdbx.extend_from_slice(b"UNAUTHENTICATED_TRAILING_GARBAGE");
    assert!(
        open_kdbx_bytes(&kdbx, &creds).is_err(),
        "Trailing unauthenticated bytes after terminating HMAC block must be rejected"
    );
}

#[test]
fn kdbx4_rejects_malicious_argon2_dos_headers_immediately() {
    let argon2id_uuid: [u8; 16] = [
        0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1,
        0xE6,
    ];
    let creds = MasterCredentials::from_password_and_keyfile(Some("test".into()), None).unwrap();

    // Case 1: 16 GiB Argon2 memory (OOM DoS)
    let mut d_oom = VariantDictionary::new();
    d_oom.insert("$UUID", VariantValue::Bytes(argon2id_uuid.to_vec()));
    d_oom.insert("S", VariantValue::Bytes(vec![0xAA; 32]));
    d_oom.insert("M", VariantValue::UInt64(16 * 1024 * 1024 * 1024));
    d_oom.insert("I", VariantValue::UInt64(2));
    d_oom.insert("P", VariantValue::UInt32(2));
    d_oom.insert("V", VariantValue::UInt32(0x13));
    let hdr_oom = build_synthetic_kdbx4_header_with_kdf(&d_oom);
    assert!(open_kdbx_bytes(&hdr_oom, &creds).is_err());

    // Case 2: 100,000 Argon2 rounds (CPU DoS)
    let mut d_cpu = VariantDictionary::new();
    d_cpu.insert("$UUID", VariantValue::Bytes(argon2id_uuid.to_vec()));
    d_cpu.insert("S", VariantValue::Bytes(vec![0xAA; 32]));
    d_cpu.insert("M", VariantValue::UInt64(1024 * 1024));
    d_cpu.insert("I", VariantValue::UInt64(100_000));
    d_cpu.insert("P", VariantValue::UInt32(2));
    d_cpu.insert("V", VariantValue::UInt32(0x13));
    let hdr_cpu = build_synthetic_kdbx4_header_with_kdf(&d_cpu);
    assert!(open_kdbx_bytes(&hdr_cpu, &creds).is_err());

    // Case 3: Zero iterations / excessive parallelism / tiny salt
    for (mem, iter, par, salt_len) in [
        (1024 * 1024u64, 0u64, 1u32, 32usize),
        (1024 * 1024, 1, 64, 32),
        (1024 * 1024, 1, 0, 32),
        (1024 * 1024, 1, 1, 4),
    ] {
        let mut d = VariantDictionary::new();
        d.insert("$UUID", VariantValue::Bytes(argon2id_uuid.to_vec()));
        d.insert("S", VariantValue::Bytes(vec![0xBB; salt_len]));
        d.insert("M", VariantValue::UInt64(mem));
        d.insert("I", VariantValue::UInt64(iter));
        d.insert("P", VariantValue::UInt32(par));
        d.insert("V", VariantValue::UInt32(0x13));
        let hdr = build_synthetic_kdbx4_header_with_kdf(&d);
        assert!(open_kdbx_bytes(&hdr, &creds).is_err());
    }
}

#[test]
fn kdbx4_malformed_and_overflowing_headers_do_not_panic() {
    let creds = MasterCredentials::from_password_and_keyfile(Some("x".into()), None).unwrap();

    // Truncated inputs
    assert!(open_kdbx_bytes(&[], &creds).is_err());
    assert!(open_kdbx_bytes(&[0u8; 11], &creds).is_err());

    // Outer TLV with 0xFFFFFFFF length (32-bit usize wrap test)
    let mut tlv_overflow = Vec::new();
    tlv_overflow.extend_from_slice(&0x9AA2_D903u32.to_le_bytes());
    tlv_overflow.extend_from_slice(&0xB54B_FB67u32.to_le_bytes());
    tlv_overflow.extend_from_slice(&0u16.to_le_bytes());
    tlv_overflow.extend_from_slice(&4u16.to_le_bytes());
    tlv_overflow.push(4);
    tlv_overflow.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(open_kdbx_bytes(&tlv_overflow, &creds).is_err());

    // VariantDictionary with >256 entries
    let mut huge_vd = vec![0x00, 0x01]; // v1.0
    for i in 0..300u32 {
        let name = format!("k{i}");
        huge_vd.push(0x04); // UInt32
        huge_vd.extend_from_slice(&(name.len() as u32).to_le_bytes());
        huge_vd.extend_from_slice(name.as_bytes());
        huge_vd.extend_from_slice(&4u32.to_le_bytes());
        huge_vd.extend_from_slice(&i.to_le_bytes());
    }
    huge_vd.push(0x00);
    assert!(VariantDictionary::parse(&huge_vd).is_err());

    // VariantDictionary with u32::MAX name length
    let mut vd_overflow = vec![0x00, 0x01, 0x04];
    vd_overflow.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(VariantDictionary::parse(&vd_overflow).is_err());

    // Empty InnerRandomStreamKey must be rejected for ChaCha20 / Salsa20
    assert!(InnerStreamCipher::new(3, &[]).is_err());
    assert!(InnerStreamCipher::new(2, &[]).is_err());
}

#[test]
fn kdbx_xml_injection_metacharacters_roundtrip_and_xxe_dos_rejection() {
    // 1. XML injection payload round-trip inside KDBX 4
    let mut vault = Vault::new("Xml</DatabaseName><Evil/>", CipherAlgorithm::ChaCha20, fast_test_kdf());
    let mut entry = VaultEntry::new("Login & <\"'> ]]> </Value>");
    entry.username = "user</Value><Key>Password</Key><Value>pwned".to_string();
    entry.password = ProtectedString::new("p@ss<&>'\"</Value><String>");
    entry.notes = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>&xxe;".to_string();
    entry.custom_fields.push(CustomField {
        key: "Weird<Key>&\"".to_string(),
        value: ProtectedString::new("Val</Value>]]>"),
        protected: true,
    });
    vault.root_group.entries.push(entry.clone());

    let creds = MasterCredentials::from_password_and_keyfile(Some("XmlTest!".into()), None).unwrap();
    let bytes = save_kdbx_bytes(&vault, &creds).unwrap();
    let opened = open_kdbx_bytes(&bytes, &creds).unwrap();
    assert_eq!(opened.meta.database_name, vault.meta.database_name);
    let restored = &opened.root_group.entries[0];
    assert_eq!(restored.title, entry.title);
    assert_eq!(restored.username, entry.username);
    assert_eq!(restored.password.expose(), entry.password.expose());
    assert_eq!(restored.notes, entry.notes);
    assert_eq!(restored.custom_fields[0].key, "Weird<Key>&\"");
    assert_eq!(restored.custom_fields[0].value.expose(), "Val</Value>]]>");

    // 2. Reject DOCTYPE / XXE declaration in KDBX XML
    let mut cipher = InnerStreamCipher::new(0, &[]).unwrap();
    let xxe_xml = br#"<?xml version="1.0"?><!DOCTYPE KeePassFile [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><KeePassFile><Root><Group><Name>Root</Name></Group></Root></KeePassFile>"#;
    assert!(
        parse_kdbx_xml(xxe_xml, &mut cipher).is_err(),
        "DOCTYPE declaration in KDBX XML must be rejected"
    );

    // 3. Reject deeply nested <Group> elements (>64 levels) without stack overflow
    let mut deep_xml = String::from("<KeePassFile><Root>");
    for _ in 0..80 {
        deep_xml.push_str("<Group><Name>G</Name>");
    }
    for _ in 0..80 {
        deep_xml.push_str("</Group>");
    }
    deep_xml.push_str("</Root></KeePassFile>");
    let mut cipher2 = InnerStreamCipher::new(0, &[]).unwrap();
    assert!(
        parse_kdbx_xml(deep_xml.as_bytes(), &mut cipher2).is_err(),
        "Deeply nested <Group> tree (>64) must be rejected"
    );

    // 4. Reject recursive <History><Entry><History> nesting
    let nested_history_xml = br#"<KeePassFile><Root><Group><Name>R</Name><Entry><History><Entry><History><Entry/></History></Entry></History></Entry></Group></Root></KeePassFile>"#;
    let mut cipher3 = InnerStreamCipher::new(0, &[]).unwrap();
    assert!(
        parse_kdbx_xml(nested_history_xml, &mut cipher3).is_err(),
        "Nested <History> inside <History><Entry> must be rejected"
    );
}

#[test]
fn keyfile_v2_rejects_missing_hash_tampered_hash_duplicate_data_and_doctype() {
    let valid_xml = generate_keyfile_v2_xml();
    assert!(parse_keyfile_bytes(valid_xml.as_bytes()).is_ok());

    // Missing Hash attribute in KeyFile v2.0
    let missing_hash = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeyFile>
  <Meta><Version>2.0</Version></Meta>
  <Key><Data>00112233 44556677 8899AABB CCDDEEFF 00112233 44556677 8899AABB CCDDEEFF</Data></Key>
</KeyFile>"#;
    assert!(parse_keyfile_bytes(missing_hash).is_err());

    // Tampered Hash attribute
    let tampered_hash = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeyFile>
  <Meta><Version>2.0</Version></Meta>
  <Key><Data Hash="00000000">00112233 44556677 8899AABB CCDDEEFF 00112233 44556677 8899AABB CCDDEEFF</Data></Key>
</KeyFile>"#;
    assert!(parse_keyfile_bytes(tampered_hash).is_err());

    // Duplicate <Data> elements
    let dup_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeyFile>
  <Meta><Version>2.0</Version></Meta>
  <Key>
    <Data Hash="AABBCCDD">00112233 44556677 8899AABB CCDDEEFF 00112233 44556677 8899AABB CCDDEEFF</Data>
    <Data Hash="AABBCCDD">00112233 44556677 8899AABB CCDDEEFF 00112233 44556677 8899AABB CCDDEEFF</Data>
  </Key>
</KeyFile>"#;
    assert!(parse_keyfile_bytes(dup_data).is_err());

    // DOCTYPE / XXE in KeyFile XML
    let doctype_kf = br#"<?xml version="1.0"?><!DOCTYPE KeyFile [<!ENTITY a "b">]><KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash="00000000">00</Data></Key></KeyFile>"#;
    assert!(parse_keyfile_bytes(doctype_kf).is_err());

    // Oversized (>64 KiB) XML-looking payload is NOT fed to XML parser (falls back to SHA-256 raw keyfile)
    let mut big = b"<KeyFile>".to_vec();
    big.resize(80 * 1024, b'A');
    assert!(parse_keyfile_bytes(&big).is_ok());
}

#[test]
fn pq_armor_mlkem1024_bitflips_truncation_wrong_key_and_debug_redaction() {
    let kp = generate_mlkem1024_keypair().expect("ml-kem-1024 keygen");
    let other_kp = generate_mlkem1024_keypair().expect("second keygen");

    // Debug must NOT leak secret_key_b64
    let dbg = format!("{kp:?}");
    assert!(!dbg.contains(&kp.secret_key_b64));
    assert!(dbg.contains("[REDACTED]"));

    // Key validation
    assert!(validate_mlkem1024_key_b64(&kp.public_key_b64).is_ok());
    assert!(validate_mlkem1024_key_b64(&kp.secret_key_b64).is_ok());
    assert!(validate_mlkem1024_key_b64("not-a-valid-key").is_err());
    assert!(validate_mlkem1024_key_b64(&B64.encode([0u8; 64])).is_err());

    let payload = b"Top-secret KDBX 4 bytes wrapped in FIPS 203 ML-KEM-1024";
    let sealed = pq_seal_bytes(payload, &kp.public_key_b64).expect("seal");
    let unsealed = pq_unseal_bytes(&sealed, &kp.secret_key_b64).expect("unseal");
    assert_eq!(unsealed.as_slice(), payload);

    // Wrong secret key must fail AEAD verification (ML-KEM implicit rejection -> wrong shared secret)
    assert!(pq_unseal_bytes(&sealed, &other_kp.secret_key_b64).is_err());

    // Bit-flip magic, ct_len, KEM ciphertext, nonce, AEAD ciphertext, and Poly1305 tag
    let len = sealed.len();
    for pos in [0, 7, 8, 12, 100, 1500, 1580, 1590, len - 17, len - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x80;
        assert!(
            pq_unseal_bytes(&bad, &kp.secret_key_b64).is_err(),
            "PQ envelope bit-flip at offset {pos}/{len} was NOT rejected!"
        );
    }

    // Truncated envelope must fail
    assert!(pq_unseal_bytes(&sealed[..16], &kp.secret_key_b64).is_err());
    assert!(pq_unseal_bytes(&sealed[..len - 1], &kp.secret_key_b64).is_err());
}

#[test]
fn bitwarden_interchange_mac_before_decrypt_kdf_bounds_whitespace_and_depth() {
    let mut src_vault = Vault::new("BwAudit", CipherAlgorithm::ChaCha20, fast_test_kdf());
    let mut e = VaultEntry::new("GitHub");
    e.username = "dev@example.com".to_string();
    e.password = ProtectedString::new("Gh!Pass#999");
    src_vault.root_group.entries.push(e);

    // 1. Password with leading & trailing spaces must round-trip cleanly (no asymmetric .trim())
    let spaced_pw = "  export pass with spaces  ";
    let exported = export_encrypted_bitwarden_json(&src_vault, spaced_pw).expect("export");

    let mut dst_vault = Vault::new("Dst", CipherAlgorithm::ChaCha20, fast_test_kdf());
    let summary = import_bitwarden_json(&exported, Some(spaced_pw), &mut dst_vault).expect("import");
    assert_eq!(summary.imported_entries, 1);

    // 2. Bit-flipping IV, ciphertext, or MAC in `data` must fail Encrypt-then-MAC
    let mut parsed: serde_json::Value = serde_json::from_slice(&exported).unwrap();
    let data_str = parsed["data"].as_str().unwrap().to_string();
    let parts: Vec<&str> = data_str.split('.').nth(1).unwrap().split('|').collect();
    assert_eq!(parts.len(), 3);
    for idx in 0..3 {
        let mut raw_part = B64.decode(parts[idx]).unwrap();
        raw_part[0] ^= 0x01;
        let mut bad_parts = parts.clone();
        let mutated_b64 = B64.encode(&raw_part);
        bad_parts[idx] = &mutated_b64;
        let mut tampered_json = parsed.clone();
        tampered_json["data"] = serde_json::Value::String(format!("2.{}", bad_parts.join("|")));
        let tampered_bytes = serde_json::to_vec(&tampered_json).unwrap();
        let mut out_v = Vault::new("Tmp", CipherAlgorithm::ChaCha20, fast_test_kdf());
        assert!(
            import_bitwarden_json(&tampered_bytes, Some(spaced_pw), &mut out_v).is_err(),
            "Bitwarden cipherstring component {idx} bit-flip was NOT rejected!"
        );
    }

    // 3. Extreme KDF DoS parameters must be rejected immediately (no silent clamping, no OOM)
    for (kdf_type, iter, mem, par) in [
        (1, 3, 4096, 4),        // 4 GiB Argon2
        (1, 500, 64, 4),        // 500 Argon2 rounds
        (1, 3, 64, 64),         // 64 Argon2 lanes
        (1, 3, 4, 4),           // Below 16 MiB minimum
        (0, 5_000_000, 64, 4),  // 5M PBKDF2 rounds
        (0, 0, 64, 4),          // 0 PBKDF2 rounds
    ] {
        parsed["kdfType"] = serde_json::json!(kdf_type);
        parsed["kdfIterations"] = serde_json::json!(iter);
        parsed["kdfMemory"] = serde_json::json!(mem);
        parsed["kdfParallelism"] = serde_json::json!(par);
        let bad_bytes = serde_json::to_vec(&parsed).unwrap();
        let mut out_v = Vault::new("Tmp", CipherAlgorithm::ChaCha20, fast_test_kdf());
        assert!(
            import_bitwarden_json(&bad_bytes, Some(spaced_pw), &mut out_v).is_err(),
            "Extreme Bitwarden KDF params ({kdf_type}, {iter}, {mem}, {par}) must be rejected"
        );
    }

    // 4. Deeply nested folder path (500 slashes) must be capped safely without stack overflow
    let deep_folder = "a/".repeat(500) + "leaf";
    let deep_json = serde_json::json!({
        "encrypted": false,
        "folders": [{ "id": "f1", "name": deep_folder }],
        "items": [{
            "id": "i1",
            "folderId": "f1",
            "type": 1,
            "name": "DeepItem",
            "login": { "username": "u", "password": "p" }
        }]
    });
    let mut deep_vault = Vault::new("Deep", CipherAlgorithm::ChaCha20, fast_test_kdf());
    let res = import_bitwarden_json(&serde_json::to_vec(&deep_json).unwrap(), None, &mut deep_vault)
        .expect("deep folder import should succeed safely");
    assert_eq!(res.imported_entries, 1);
    assert!(
        res.created_folders <= 32,
        "Folder depth must be capped at 32 (got {})",
        res.created_folders
    );
}

#[test]
fn biometric_slot_v2_v1_compat_aad_mismatch_bitflips_and_validation() {
    let creds = BiometricVaultCredentials {
        master_password: Some("UltraSecretMaster#1".into()),
        keyfile_path: Some("/vaults/key.keyx".into()),
    };

    // Debug must redact master_password
    let dbg = format!("{creds:?}");
    assert!(!dbg.contains("UltraSecretMaster#1"));
    assert!(dbg.contains("[REDACTED]"));

    let key = [0x5Au8; 32];
    let sealed = seal_biometric_slot(&creds, &key, "vault_alpha").expect("seal v2");
    assert_eq!(&sealed[..8], b"CPBIO002");

    // Round-trip succeeds
    let opened = unseal_biometric_slot(&sealed, &key, "vault_alpha").expect("unseal v2");
    assert_eq!(opened.master_password, creds.master_password);

    // Cross-vault AAD mismatch fails
    assert!(unseal_biometric_slot(&sealed, &key, "vault_beta").is_err());

    // Invalid vault_id lengths fail
    assert!(seal_biometric_slot(&creds, &key, "").is_err());
    assert!(seal_biometric_slot(&creds, &key, &"x".repeat(300)).is_err());

    // Bit-flip magic, nonce, ciphertext, and tag
    for pos in [0, 7, 8, 19, 25, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x01;
        assert!(unseal_biometric_slot(&bad, &key, "vault_alpha").is_err());
    }

    // Legacy CPBIO001 compatibility check (Sha3_512 KDF + nonce-bound AAD)
    let nonce = [0x33u8; 12];
    let mut legacy_kdf = sha3::Sha3_512::new();
    legacy_kdf.update(b"CipherPass-Biometric-Vault-Keyslot-v1");
    legacy_kdf.update(key);
    legacy_kdf.update(b"vault_legacy");
    legacy_kdf.update(nonce);
    let legacy_digest = legacy_kdf.finalize();
    let cipher = ChaCha20Poly1305::new_from_slice(&legacy_digest[..32]).unwrap();
    let plain = serde_json::to_vec(&creds).unwrap();
    let aad = [
        b"CPBIO001".as_slice(),
        nonce.as_slice(),
        b"vault_legacy".as_slice(),
    ]
    .concat();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: &aad,
            },
        )
        .unwrap();
    let mut legacy_blob = Vec::new();
    legacy_blob.extend_from_slice(b"CPBIO001");
    legacy_blob.extend_from_slice(&nonce);
    legacy_blob.extend_from_slice(&ct);

    let legacy_opened = unseal_biometric_slot(&legacy_blob, &key, "vault_legacy").expect("v1 compat");
    assert_eq!(legacy_opened.master_password, creds.master_password);
}

#[test]
fn totp_edge_cases_and_debug_redaction() {
    assert!(parse_totp_uri("").is_err());
    assert!(parse_totp_uri("!!!INVALID_BASE32!!!").is_err());

    let cfg = parse_totp_uri("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP").unwrap();
    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("72")); // ASCII 'H' from secret bytes
    assert!(dbg.contains("[REDACTED]"));

    // Pathological period=0 and digits=99 must not panic or divide by zero
    let weird = TotpConfig {
        secret: b"12345678901234567890".to_vec().into(),
        algorithm: TotpAlgorithm::Sha1,
        digits: 99,
        period: 0,
        issuer: "Test".into(),
        account: "u".into(),
    };
    let code = generate_totp_at(&weird, 1_700_000_000);
    assert_eq!(code.code.len(), 8);
    assert_eq!(code.period, 1);
}

#[test]
fn vault_entry_and_generator_zeroize_and_redaction() {
    let mut entry = VaultEntry::new("Bank");
    entry.username = "alice@bank.example".to_string();
    entry.password = ProtectedString::new("BankPass!2026");
    entry.notes = "Secret recovery codes".to_string();
    entry.custom_fields.push(CustomField {
        key: "PIN".to_string(),
        value: ProtectedString::new("987654"),
        protected: true,
    });
    entry.push_history_snapshot(5);
    entry.zeroize_secrets();

    assert!(entry.password.expose().is_empty());
    assert!(entry.username.is_empty());
    assert!(entry.notes.is_empty());
    assert!(entry.custom_fields[0].value.expose().is_empty());
    assert!(entry.history[0].password.expose().is_empty());
    assert!(entry.history[0].username.is_empty());
    assert!(entry.history[0].notes.is_empty());

    let gen = generate_password(&PasswordGenOptions::default());
    let gen_dbg = format!("{gen:?}");
    assert!(!gen_dbg.contains(&gen.value));
    assert!(gen_dbg.contains("[REDACTED]"));
}
