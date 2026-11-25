use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypto::{
    compute_block_hmac, compute_header_hmac, constant_time_eq_32, decrypt_outer, encrypt_outer,
    random_bytes, random_vec, CipherAlgorithm, DerivedVaultKeys, InnerStreamCipher, KdfConfig,
    MasterCredentials, INNER_STREAM_CHACHA20,
};
use crate::error::{CipherPassError, Result};
use crate::kdbx_xml::{parse_kdbx_xml, serialize_kdbx_xml};
use crate::model::{InnerBinary, Vault};
use crate::variant_dict::VariantDictionary;

const KDBX_SIG1: u32 = 0x9AA2_D903;
const KDBX_SIG2: u32 = 0xB54B_FB67;
const KDBX_VERSION_MAJOR: u16 = 4;

// Outer header field IDs
const OUTER_END_OF_HEADER: u8 = 0;
const OUTER_CIPHER_ID: u8 = 2;
const OUTER_COMPRESSION_FLAGS: u8 = 3;
const OUTER_MASTER_SEED: u8 = 4;
const OUTER_ENCRYPTION_IV: u8 = 7;
const OUTER_KDF_PARAMETERS: u8 = 11;
const OUTER_PUBLIC_CUSTOM_DATA: u8 = 12;

// Inner header field IDs
const INNER_END_OF_HEADER: u8 = 0;
const INNER_RANDOM_STREAM_ID: u8 = 1;
const INNER_RANDOM_STREAM_KEY: u8 = 2;
const INNER_BINARY: u8 = 3;

const HMAC_BLOCK_SIZE: usize = 64 * 1024; // 64 KiB chunks per KDBX 4 convention
/// Hard cap on decompressed inner KDBX payload (64 MiB) to defend against GZip zip-bomb DoS.
const MAX_DECOMPRESSED_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

fn write_tlv(out: &mut Vec<u8>, field_id: u8, data: &[u8]) {
    out.push(field_id);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

/// Serialize a `Vault` into KDBX 4 / 4.1 binary bytes.
pub fn save_kdbx_bytes(vault: &Vault, credentials: &MasterCredentials) -> Result<Vec<u8>> {
    let composite_key = credentials.composite_key()?;

    // Fresh cryptographic randomness on every save (unique salt, master seed, IV, inner stream key)
    let kdf_salt: [u8; 32] = random_bytes();
    let master_seed: [u8; 32] = random_bytes();
    let encryption_iv = random_vec(vault.cipher.iv_len());
    let inner_stream_key = Zeroizing::new(random_vec(64));

    let kdf_dict = vault.kdf.to_variant_dict(&kdf_salt);
    let kdf_dict_bytes = kdf_dict.serialize();

    // 1. Build Outer Header
    let mut header = Vec::new();
    header.extend_from_slice(&KDBX_SIG1.to_le_bytes());
    header.extend_from_slice(&KDBX_SIG2.to_le_bytes());
    header.extend_from_slice(&vault.version_minor.to_le_bytes());
    header.extend_from_slice(&KDBX_VERSION_MAJOR.to_le_bytes());

    write_tlv(&mut header, OUTER_CIPHER_ID, &vault.cipher.uuid());
    let comp_flag: u32 = u32::from(vault.compression);
    write_tlv(
        &mut header,
        OUTER_COMPRESSION_FLAGS,
        &comp_flag.to_le_bytes(),
    );
    write_tlv(&mut header, OUTER_MASTER_SEED, &master_seed);
    write_tlv(&mut header, OUTER_ENCRYPTION_IV, &encryption_iv);
    write_tlv(&mut header, OUTER_KDF_PARAMETERS, &kdf_dict_bytes);
    if let Some(ref pcd) = vault.public_custom_data {
        write_tlv(&mut header, OUTER_PUBLIC_CUSTOM_DATA, &pcd.serialize());
    }
    write_tlv(&mut header, OUTER_END_OF_HEADER, b"\r\n\r\n");

    // 2. Derive keys (Argon2id/Argon2d -> MasterKey + HmacKeyBase)
    let transformed_key = vault
        .kdf
        .derive_transformed_key(&composite_key, &kdf_salt, None)?;
    let keys = DerivedVaultKeys::derive(&master_seed, &transformed_key);

    // 3. Header SHA-256 + Header HMAC-SHA256
    let header_sha256 = Sha256::digest(&header);
    let header_hmac_key = keys.header_hmac_key();
    let header_hmac = compute_header_hmac(&header_hmac_key, &header);

    // 4. Build Inner Header + ChaCha20-protected XML payload
    let mut inner_cipher =
        InnerStreamCipher::new(INNER_STREAM_CHACHA20, inner_stream_key.as_slice())?;
    let xml_bytes = serialize_kdbx_xml(
        &vault.meta,
        &vault.root_group,
        &vault.deleted_objects,
        &mut inner_cipher,
    )?;

    let mut inner_payload = Zeroizing::new(Vec::new());
    write_tlv(
        &mut inner_payload,
        INNER_RANDOM_STREAM_ID,
        &INNER_STREAM_CHACHA20.to_le_bytes(),
    );
    write_tlv(
        &mut inner_payload,
        INNER_RANDOM_STREAM_KEY,
        inner_stream_key.as_slice(),
    );
    for bin in &vault.inner_binaries {
        let mut raw = Zeroizing::new(Vec::with_capacity(1 + bin.data.len()));
        raw.push(bin.flags);
        raw.extend_from_slice(&bin.data);
        write_tlv(&mut inner_payload, INNER_BINARY, raw.as_slice());
    }
    write_tlv(&mut inner_payload, INNER_END_OF_HEADER, &[]);
    inner_payload.extend_from_slice(xml_bytes.as_slice());

    // 5. Optional GZip compression
    let plaintext = if vault.compression {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(inner_payload.as_slice())?;
        Zeroizing::new(encoder.finish()?)
    } else {
        inner_payload
    };

    // 6. Outer encryption (ChaCha20 or AES-256-CBC)
    let ciphertext = encrypt_outer(
        vault.cipher,
        &keys.master_key,
        &encryption_iv,
        plaintext.as_slice(),
    )?;

    // 7. Assemble KDBX 4 output: Header || HeaderSHA256 || HeaderHMAC || HMAC Block Stream
    let mut out = Vec::with_capacity(header.len() + 64 + ciphertext.len() + 128);
    out.extend_from_slice(&header);
    out.extend_from_slice(&header_sha256);
    out.extend_from_slice(&header_hmac);

    let mut block_index: u64 = 0;
    for chunk in ciphertext.chunks(HMAC_BLOCK_SIZE) {
        let block_size = chunk.len() as u32;
        let bkey = keys.block_hmac_key(block_index);
        let bmac = compute_block_hmac(&bkey, block_index, block_size, chunk);
        out.extend_from_slice(&bmac);
        out.extend_from_slice(&block_size.to_le_bytes());
        out.extend_from_slice(chunk);
        block_index += 1;
    }

    // Final terminating 0-length authenticated block
    let final_bkey = keys.block_hmac_key(block_index);
    let final_bmac = compute_block_hmac(&final_bkey, block_index, 0, &[]);
    out.extend_from_slice(&final_bmac);
    out.extend_from_slice(&0u32.to_le_bytes());

    Ok(out)
}

/// Parse, authenticate, and decrypt a KDBX 4 / 4.1 vault from raw bytes.
pub fn open_kdbx_bytes(data: &[u8], credentials: &MasterCredentials) -> Result<Vault> {
    const MAX_OUTER_TLV_FIELDS: usize = 64;
    const MAX_INNER_TLV_FIELDS: usize = 2048;

    if data.len() < 12 {
        return Err(CipherPassError::InvalidSignature);
    }

    let sig1 = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let sig2 = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if sig1 != KDBX_SIG1 || sig2 != KDBX_SIG2 {
        return Err(CipherPassError::InvalidSignature);
    }

    let version_minor = u16::from_le_bytes(data[8..10].try_into().unwrap());
    let version_major = u16::from_le_bytes(data[10..12].try_into().unwrap());
    if version_major != KDBX_VERSION_MAJOR || version_minor > 1 {
        return Err(CipherPassError::UnsupportedVersion {
            major: version_major,
            minor: version_minor,
        });
    }

    // 1. Parse Outer Header TLV fields
    let mut offset = 12usize;
    let mut outer_field_count = 0usize;
    let mut cipher: Option<CipherAlgorithm> = None;
    let mut compression: Option<bool> = None;
    let mut master_seed: Option<[u8; 32]> = None;
    let mut encryption_iv: Option<Vec<u8>> = None;
    let mut kdf_dict: Option<VariantDictionary> = None;
    let mut public_custom_data: Option<VariantDictionary> = None;

    loop {
        outer_field_count += 1;
        if outer_field_count > MAX_OUTER_TLV_FIELDS {
            return Err(CipherPassError::MalformedFormat(
                "Outer header exceeds maximum TLV field count".into(),
            ));
        }
        let header_tlv_end = offset.checked_add(5).ok_or_else(|| {
            CipherPassError::MalformedFormat("Outer header TLV offset overflow".into())
        })?;
        if header_tlv_end > data.len() {
            return Err(CipherPassError::MalformedFormat(
                "Truncated outer header TLV".into(),
            ));
        }
        let field_id = data[offset];
        let field_len =
            u32::from_le_bytes(data[offset + 1..header_tlv_end].try_into().unwrap()) as usize;
        offset = header_tlv_end;

        let field_end = offset.checked_add(field_len).ok_or_else(|| {
            CipherPassError::MalformedFormat("Outer header TLV length overflow".into())
        })?;
        if field_end > data.len() {
            return Err(CipherPassError::MalformedFormat(
                "Outer header TLV length exceeds file size".into(),
            ));
        }
        let field_data = &data[offset..field_end];
        offset = field_end;

        match field_id {
            OUTER_END_OF_HEADER => break,
            OUTER_CIPHER_ID => {
                cipher = Some(CipherAlgorithm::from_uuid(field_data)?);
            }
            OUTER_COMPRESSION_FLAGS => {
                if field_data.len() != 4 {
                    return Err(CipherPassError::MalformedFormat(
                        "Invalid compression flags length".into(),
                    ));
                }
                let flag = u32::from_le_bytes(field_data.try_into().unwrap());
                match flag {
                    0 => compression = Some(false),
                    1 => compression = Some(true),
                    other => return Err(CipherPassError::UnsupportedCompression(other)),
                }
            }
            OUTER_MASTER_SEED => {
                if field_data.len() != 32 {
                    return Err(CipherPassError::MalformedFormat(
                        "MasterSeed must be 32 bytes".into(),
                    ));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(field_data);
                master_seed = Some(seed);
            }
            OUTER_ENCRYPTION_IV => {
                encryption_iv = Some(field_data.to_vec());
            }
            OUTER_KDF_PARAMETERS => {
                kdf_dict = Some(VariantDictionary::parse(field_data)?);
            }
            OUTER_PUBLIC_CUSTOM_DATA => {
                public_custom_data = Some(VariantDictionary::parse(field_data)?);
            }
            _ => {
                // Ignore unknown future optional outer header fields per KDBX 4 spec
            }
        }
    }

    let header_end = offset;
    let header_bytes = &data[..header_end];

    let cipher =
        cipher.ok_or_else(|| CipherPassError::MalformedFormat("Missing CipherID".into()))?;
    let compression = compression.unwrap_or(true);
    let master_seed =
        master_seed.ok_or_else(|| CipherPassError::MalformedFormat("Missing MasterSeed".into()))?;
    let encryption_iv = encryption_iv
        .ok_or_else(|| CipherPassError::MalformedFormat("Missing EncryptionIV".into()))?;
    let kdf_dict =
        kdf_dict.ok_or_else(|| CipherPassError::MalformedFormat("Missing KdfParameters".into()))?;

    let exact_mem_bytes = kdf_dict.get_u64("M");
    let (kdf_config, kdf_salt) = KdfConfig::from_variant_dict(&kdf_dict)?;

    // 2. Verify Header SHA-256 (fast integrity check before expensive KDF)
    let macs_end = header_end
        .checked_add(64)
        .ok_or_else(|| CipherPassError::MalformedFormat("Header HMAC offset overflow".into()))?;
    if macs_end > data.len() {
        return Err(CipherPassError::MalformedFormat(
            "Truncated header hash / HMAC".into(),
        ));
    }
    let stored_header_sha256 = &data[header_end..header_end + 32];
    let stored_header_hmac = &data[header_end + 32..macs_end];

    let computed_header_sha256 = Sha256::digest(header_bytes);
    if !constant_time_eq_32(&computed_header_sha256, stored_header_sha256) {
        return Err(CipherPassError::HeaderHashMismatch);
    }

    // 3. Derive keys & verify Header HMAC-SHA256
    let composite_key = credentials.composite_key()?;
    let transformed_key =
        kdf_config.derive_transformed_key(&composite_key, &kdf_salt, exact_mem_bytes)?;
    let keys = DerivedVaultKeys::derive(&master_seed, &transformed_key);

    let header_hmac_key = keys.header_hmac_key();
    let computed_header_hmac = compute_header_hmac(&header_hmac_key, header_bytes);
    if !constant_time_eq_32(&computed_header_hmac, stored_header_hmac) {
        return Err(CipherPassError::HeaderHmacMismatch);
    }

    // 4. Parse & authenticate HMAC Block Stream
    let mut stream_offset = macs_end;
    let mut block_index: u64 = 0;
    let mut ciphertext = Vec::new();
    let mut saw_terminator = false;

    while stream_offset < data.len() {
        let blk_hdr_end = stream_offset.checked_add(36).ok_or_else(|| {
            CipherPassError::MalformedFormat("HMAC block header offset overflow".into())
        })?;
        if blk_hdr_end > data.len() {
            return Err(CipherPassError::MalformedFormat(
                "Truncated HMAC block header".into(),
            ));
        }
        let stored_block_hmac = &data[stream_offset..stream_offset + 32];
        let block_size =
            u32::from_le_bytes(data[stream_offset + 32..blk_hdr_end].try_into().unwrap());
        stream_offset = blk_hdr_end;

        let block_len = block_size as usize;
        let blk_data_end = stream_offset
            .checked_add(block_len)
            .ok_or_else(|| CipherPassError::MalformedFormat("HMAC block length overflow".into()))?;
        if blk_data_end > data.len() {
            return Err(CipherPassError::MalformedFormat(
                "Truncated HMAC block payload".into(),
            ));
        }
        let block_data = &data[stream_offset..blk_data_end];
        stream_offset = blk_data_end;

        let bkey = keys.block_hmac_key(block_index);
        let computed_block_hmac = compute_block_hmac(&bkey, block_index, block_size, block_data);
        if !constant_time_eq_32(&computed_block_hmac, stored_block_hmac) {
            return Err(CipherPassError::BlockHmacMismatch { block_index });
        }

        if block_size == 0 {
            saw_terminator = true;
            break;
        }
        ciphertext.extend_from_slice(block_data);
        block_index = block_index
            .checked_add(1)
            .ok_or_else(|| CipherPassError::MalformedFormat("HMAC block index overflow".into()))?;
    }

    if !saw_terminator {
        return Err(CipherPassError::MalformedFormat(
            "Missing terminating HMAC block".into(),
        ));
    }
    if stream_offset != data.len() {
        return Err(CipherPassError::MalformedFormat(
            "Unexpected unauthenticated trailing data after KDBX HMAC block stream".into(),
        ));
    }

    // 5. Decrypt outer payload
    let decrypted = decrypt_outer(cipher, &keys.master_key, &encryption_iv, &ciphertext)?;

    // 6. Optional GZip decompression (bounded to prevent zip-bomb OOM DoS)
    let inner_bytes = if compression {
        let decoder = GzDecoder::new(decrypted.as_slice());
        let mut bounded = decoder.take(MAX_DECOMPRESSED_PAYLOAD_BYTES + 1);
        let mut out = Zeroizing::new(Vec::new());
        bounded.read_to_end(&mut out)?;
        if out.len() as u64 > MAX_DECOMPRESSED_PAYLOAD_BYTES {
            return Err(CipherPassError::MalformedFormat(
                "Decompressed KDBX payload exceeds 64 MiB safety limit".into(),
            ));
        }
        out
    } else {
        decrypted
    };

    // 7. Parse Inner Header TLV fields
    let mut inner_off = 0usize;
    let mut inner_field_count = 0usize;
    let mut inner_stream_id: u32 = 0;
    let mut inner_stream_key = Zeroizing::new(Vec::new());
    let mut inner_binaries = Vec::new();

    loop {
        inner_field_count += 1;
        if inner_field_count > MAX_INNER_TLV_FIELDS {
            return Err(CipherPassError::MalformedFormat(
                "Inner header exceeds maximum TLV field count".into(),
            ));
        }
        let inner_hdr_end = inner_off.checked_add(5).ok_or_else(|| {
            CipherPassError::MalformedFormat("Inner header TLV offset overflow".into())
        })?;
        if inner_hdr_end > inner_bytes.len() {
            return Err(CipherPassError::MalformedFormat(
                "Truncated inner header TLV".into(),
            ));
        }
        let fid = inner_bytes[inner_off];
        let flen = u32::from_le_bytes(
            inner_bytes[inner_off + 1..inner_hdr_end]
                .try_into()
                .unwrap(),
        ) as usize;
        inner_off = inner_hdr_end;

        let inner_data_end = inner_off.checked_add(flen).ok_or_else(|| {
            CipherPassError::MalformedFormat("Inner header TLV length overflow".into())
        })?;
        if inner_data_end > inner_bytes.len() {
            return Err(CipherPassError::MalformedFormat(
                "Inner header TLV exceeds decrypted payload".into(),
            ));
        }
        let fdata = &inner_bytes[inner_off..inner_data_end];
        inner_off = inner_data_end;

        match fid {
            INNER_END_OF_HEADER => break,
            INNER_RANDOM_STREAM_ID => {
                if fdata.len() != 4 {
                    return Err(CipherPassError::MalformedFormat(
                        "Invalid InnerRandomStreamID length".into(),
                    ));
                }
                inner_stream_id = u32::from_le_bytes(fdata.try_into().unwrap());
            }
            INNER_RANDOM_STREAM_KEY => {
                inner_stream_key = Zeroizing::new(fdata.to_vec());
            }
            INNER_BINARY if !fdata.is_empty() => {
                inner_binaries.push(InnerBinary {
                    flags: fdata[0],
                    data: fdata[1..].to_vec(),
                });
            }
            _ => {}
        }
    }

    let xml_slice = &inner_bytes[inner_off..];
    let mut inner_cipher = InnerStreamCipher::new(inner_stream_id, inner_stream_key.as_slice())?;
    let (meta, root_group, deleted_objects) = parse_kdbx_xml(xml_slice, &mut inner_cipher)?;

    Ok(Vault {
        version_minor,
        cipher,
        kdf: kdf_config,
        compression,
        meta,
        root_group,
        deleted_objects,
        inner_binaries,
        public_custom_data,
    })
}

/// Atomically write KDBX 4 bytes to disk: `.tmp.<rand>` -> write -> fsync -> atomic rename.
/// Prevents vault corruption during iCloud / Syncthing / Google Drive sync.
pub fn atomic_write_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault.kdbx");
    let nonce: [u8; 8] = random_bytes();
    let tmp_name = format!(".{file_name}.tmp.{}", hex::encode(nonce));
    let tmp_path = parent.join(tmp_name);

    let write_result = (|| -> Result<()> {
        let mut opts = OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp_path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(CipherPassError::Io(err));
    }

    // Best-effort parent directory fsync on Unix-like systems
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub fn save_kdbx_file_atomic(
    path: &Path,
    vault: &Vault,
    credentials: &MasterCredentials,
) -> Result<()> {
    let bytes = save_kdbx_bytes(vault, credentials)?;
    atomic_write_file(path, &bytes)
}

pub fn open_kdbx_file(path: &Path, credentials: &MasterCredentials) -> Result<Vault> {
    let bytes = fs::read(path)?;
    open_kdbx_bytes(&bytes, credentials)
}
