use std::collections::BTreeMap;
use std::io::Cursor;

use base64::Engine;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::InnerStreamCipher;
use crate::error::{CipherPassError, Result};
use crate::model::{
    CustomField, DeletedObject, EntryHistoryItem, EntryTimes, ProtectedString, VaultEntry,
    VaultGroup, VaultMeta,
};

/// Seconds between 0001-01-01T00:00:00Z and 1970-01-01T00:00:00Z (KeePass KDBX 4 epoch offset).
const KEEPASS_EPOCH_OFFSET_SECS: i64 = 62_135_596_800;

fn encode_uuid_b64(uuid: &Uuid) -> String {
    base64::engine::general_purpose::STANDARD.encode(uuid.as_bytes())
}

fn decode_uuid_b64(s: &str) -> Uuid {
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s.trim()) {
        if bytes.len() == 16 {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            return Uuid::from_bytes(arr);
        }
    }
    Uuid::parse_str(s.trim()).unwrap_or_else(|_| Uuid::new_v4())
}

fn encode_kdbx4_time(dt: &DateTime<Utc>) -> String {
    let secs = dt.timestamp().saturating_add(KEEPASS_EPOCH_OFFSET_SECS);
    base64::engine::general_purpose::STANDARD.encode(secs.to_le_bytes())
}

fn decode_kdbx_time(s: &str) -> DateTime<Utc> {
    let trimmed = s.trim();
    // 1. Try ISO-8601 (KDBX 3.1 / XML text format)
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return dt.with_timezone(&Utc);
    }
    // 2. Try KDBX 4 Base64-encoded 8-byte little-endian seconds since 0001-01-01T00:00:00Z
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if bytes.len() == 8 {
            let secs_since_0001 = i64::from_le_bytes(bytes.try_into().unwrap());
            let unix_secs = secs_since_0001.saturating_sub(KEEPASS_EPOCH_OFFSET_SECS);
            if let Some(dt) = Utc.timestamp_opt(unix_secs, 0).single() {
                return dt;
            }
        }
    }
    NaiveDate::from_ymd_opt(2026, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
}

fn parse_bool(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn encode_bool(v: bool) -> &'static str {
    if v {
        "True"
    } else {
        "False"
    }
}

fn write_text_elem<W: std::io::Write>(w: &mut Writer<W>, tag: &str, text: &str) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new(tag)))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    w.write_event(Event::Text(BytesText::new(text)))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    w.write_event(Event::End(BytesEnd::new(tag)))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_string_kv<W: std::io::Write>(
    w: &mut Writer<W>,
    key: &str,
    value: &str,
    protected: bool,
    inner_cipher: &mut InnerStreamCipher,
) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new("String")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(w, "Key", key)?;

    if protected {
        let mut raw = Zeroizing::new(value.as_bytes().to_vec());
        inner_cipher.apply(raw.as_mut_slice());
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw.as_slice());

        let mut val_start = BytesStart::new("Value");
        val_start.push_attribute(("Protected", "True"));
        w.write_event(Event::Start(val_start))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
        w.write_event(Event::Text(BytesText::new(&encoded)))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
        w.write_event(Event::End(BytesEnd::new("Value")))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    } else {
        write_text_elem(w, "Value", value)?;
    }

    w.write_event(Event::End(BytesEnd::new("String")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_times<W: std::io::Write>(w: &mut Writer<W>, times: &EntryTimes) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new("Times")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(w, "CreationTime", &encode_kdbx4_time(&times.creation_time))?;
    write_text_elem(
        w,
        "LastModificationTime",
        &encode_kdbx4_time(&times.last_modification_time),
    )?;
    write_text_elem(
        w,
        "LastAccessTime",
        &encode_kdbx4_time(&times.last_access_time),
    )?;
    write_text_elem(w, "ExpiryTime", &encode_kdbx4_time(&times.expiry_time))?;
    write_text_elem(w, "Expires", encode_bool(times.expires))?;
    write_text_elem(w, "UsageCount", &times.usage_count.to_string())?;
    write_text_elem(
        w,
        "LocationChanged",
        &encode_kdbx4_time(&times.location_changed),
    )?;
    w.write_event(Event::End(BytesEnd::new("Times")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_custom_data<W: std::io::Write>(
    w: &mut Writer<W>,
    map: &BTreeMap<String, String>,
) -> Result<()> {
    if map.is_empty() {
        return Ok(());
    }
    w.write_event(Event::Start(BytesStart::new("CustomData")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    for (k, v) in map {
        w.write_event(Event::Start(BytesStart::new("Item")))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
        write_text_elem(w, "Key", k)?;
        write_text_elem(w, "Value", v)?;
        w.write_event(Event::End(BytesEnd::new("Item")))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    }
    w.write_event(Event::End(BytesEnd::new("CustomData")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_history_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    uuid: &Uuid,
    icon_id: u32,
    item: &EntryHistoryItem,
    inner_cipher: &mut InnerStreamCipher,
) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new("Entry")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(w, "UUID", &encode_uuid_b64(uuid))?;
    write_text_elem(w, "IconID", &icon_id.to_string())?;
    write_text_elem(w, "Tags", &item.tags.join(";"))?;
    write_times(w, &item.times)?;

    write_string_kv(w, "Title", &item.title, false, inner_cipher)?;
    write_string_kv(w, "UserName", &item.username, false, inner_cipher)?;
    write_string_kv(w, "Password", item.password.expose(), true, inner_cipher)?;
    write_string_kv(w, "URL", &item.url, false, inner_cipher)?;
    write_string_kv(w, "Notes", &item.notes, false, inner_cipher)?;
    for cf in &item.custom_fields {
        write_string_kv(w, &cf.key, cf.value.expose(), cf.protected, inner_cipher)?;
    }

    w.write_event(Event::End(BytesEnd::new("Entry")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    entry: &VaultEntry,
    inner_cipher: &mut InnerStreamCipher,
) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new("Entry")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(w, "UUID", &encode_uuid_b64(&entry.uuid))?;
    write_text_elem(w, "IconID", &entry.icon_id.to_string())?;
    write_text_elem(w, "Tags", &entry.tags.join(";"))?;
    write_times(w, &entry.times)?;
    write_custom_data(w, &entry.custom_data)?;

    write_string_kv(w, "Title", &entry.title, false, inner_cipher)?;
    write_string_kv(w, "UserName", &entry.username, false, inner_cipher)?;
    write_string_kv(w, "Password", entry.password.expose(), true, inner_cipher)?;
    write_string_kv(w, "URL", &entry.url, false, inner_cipher)?;
    write_string_kv(w, "Notes", &entry.notes, false, inner_cipher)?;
    for cf in &entry.custom_fields {
        write_string_kv(w, &cf.key, cf.value.expose(), cf.protected, inner_cipher)?;
    }

    w.write_event(Event::Start(BytesStart::new("AutoType")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(w, "Enabled", encode_bool(entry.auto_type_enabled))?;
    w.write_event(Event::End(BytesEnd::new("AutoType")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    w.write_event(Event::Start(BytesStart::new("History")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    for h in &entry.history {
        write_history_entry(w, &entry.uuid, entry.icon_id, h, inner_cipher)?;
    }
    w.write_event(Event::End(BytesEnd::new("History")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    w.write_event(Event::End(BytesEnd::new("Entry")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

fn write_group<W: std::io::Write>(
    w: &mut Writer<W>,
    group: &VaultGroup,
    inner_cipher: &mut InnerStreamCipher,
) -> Result<()> {
    w.write_event(Event::Start(BytesStart::new("Group")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(w, "UUID", &encode_uuid_b64(&group.uuid))?;
    write_text_elem(w, "Name", &group.name)?;
    write_text_elem(w, "Notes", &group.notes)?;
    write_text_elem(w, "IconID", &group.icon_id.to_string())?;
    write_times(w, &group.times)?;
    write_text_elem(w, "IsExpanded", encode_bool(group.is_expanded))?;

    for entry in &group.entries {
        write_entry(w, entry, inner_cipher)?;
    }
    for sub in &group.subgroups {
        write_group(w, sub, inner_cipher)?;
    }

    w.write_event(Event::End(BytesEnd::new("Group")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    Ok(())
}

/// Serialize KDBX 4 XML payload with ChaCha20 inner-stream protection for protected fields.
pub fn serialize_kdbx_xml(
    meta: &VaultMeta,
    root_group: &VaultGroup,
    deleted_objects: &[DeletedObject],
    inner_cipher: &mut InnerStreamCipher,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));

    writer
        .write_event(Event::Decl(BytesDecl::new(
            "1.0",
            Some("utf-8"),
            Some("yes"),
        )))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    writer
        .write_event(Event::Start(BytesStart::new("KeePassFile")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    // <Meta>
    writer
        .write_event(Event::Start(BytesStart::new("Meta")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(&mut writer, "Generator", &meta.generator)?;
    write_text_elem(&mut writer, "DatabaseName", &meta.database_name)?;
    write_text_elem(
        &mut writer,
        "DatabaseDescription",
        &meta.database_description,
    )?;
    write_text_elem(&mut writer, "DefaultUserName", &meta.default_username)?;
    write_text_elem(
        &mut writer,
        "RecycleBinEnabled",
        encode_bool(meta.recycle_bin_enabled),
    )?;
    write_text_elem(
        &mut writer,
        "RecycleBinUUID",
        &encode_uuid_b64(&meta.recycle_bin_uuid),
    )?;
    write_text_elem(
        &mut writer,
        "HistoryMaxItems",
        &meta.history_max_items.to_string(),
    )?;
    write_text_elem(
        &mut writer,
        "HistoryMaxSize",
        &meta.history_max_size.to_string(),
    )?;
    // MemoryProtection flags (standard KeePassXC / KeePass 2)
    writer
        .write_event(Event::Start(BytesStart::new("MemoryProtection")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_text_elem(&mut writer, "ProtectTitle", "False")?;
    write_text_elem(&mut writer, "ProtectUserName", "False")?;
    write_text_elem(&mut writer, "ProtectPassword", "True")?;
    write_text_elem(&mut writer, "ProtectURL", "False")?;
    write_text_elem(&mut writer, "ProtectNotes", "False")?;
    writer
        .write_event(Event::End(BytesEnd::new("MemoryProtection")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_custom_data(&mut writer, &meta.custom_data)?;
    writer
        .write_event(Event::End(BytesEnd::new("Meta")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    // <Root>
    writer
        .write_event(Event::Start(BytesStart::new("Root")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    write_group(&mut writer, root_group, inner_cipher)?;

    writer
        .write_event(Event::Start(BytesStart::new("DeletedObjects")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    for del in deleted_objects {
        writer
            .write_event(Event::Start(BytesStart::new("DeletedObject")))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
        write_text_elem(&mut writer, "UUID", &encode_uuid_b64(&del.uuid))?;
        write_text_elem(
            &mut writer,
            "DeletionTime",
            &encode_kdbx4_time(&del.deletion_time),
        )?;
        writer
            .write_event(Event::End(BytesEnd::new("DeletedObject")))
            .map_err(|e| CipherPassError::XmlError(e.to_string()))?;
    }
    writer
        .write_event(Event::End(BytesEnd::new("DeletedObjects")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    writer
        .write_event(Event::End(BytesEnd::new("Root")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    writer
        .write_event(Event::End(BytesEnd::new("KeePassFile")))
        .map_err(|e| CipherPassError::XmlError(e.to_string()))?;

    Ok(Zeroizing::new(writer.into_inner().into_inner()))
}

/// Maximum allowed `<Group>` nesting depth in KDBX XML to prevent stack overflow DoS.
const MAX_XML_GROUP_DEPTH: usize = 64;

/// Recursive DOM-free streaming parser for KDBX 4 XML payloads.
pub fn parse_kdbx_xml(
    xml_bytes: &[u8],
    inner_cipher: &mut InnerStreamCipher,
) -> Result<(VaultMeta, VaultGroup, Vec<DeletedObject>)> {
    let mut reader = Reader::from_reader(xml_bytes);
    reader.config_mut().trim_text(false);

    let mut meta = VaultMeta::default();
    let mut root_group: Option<VaultGroup> = None;
    let mut deleted_objects: Vec<DeletedObject> = Vec::new();
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::DocType(_)) => {
                return Err(CipherPassError::XmlError(
                    "XML DOCTYPE declarations are forbidden in KDBX payloads".into(),
                ));
            }
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Meta" => {
                    meta = parse_meta(&mut reader)?;
                }
                b"Root" => {
                    let (grp, dels) = parse_root(&mut reader, inner_cipher)?;
                    root_group = grp;
                    deleted_objects = dels;
                }
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }

    let root = root_group.unwrap_or_else(|| VaultGroup::new("Root", 48));
    Ok((meta, root, deleted_objects))
}

fn read_text_until_end(reader: &mut Reader<&[u8]>, end_tag: &[u8]) -> Result<String> {
    let mut out = String::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::DocType(_)) => {
                return Err(CipherPassError::XmlError(
                    "XML DOCTYPE declarations are forbidden in KDBX payloads".into(),
                ));
            }
            Ok(Event::Text(e)) => {
                let s = e
                    .unescape()
                    .map_err(|err| CipherPassError::XmlError(err.to_string()))?;
                out.push_str(&s);
            }
            Ok(Event::CData(e)) => {
                out.push_str(&String::from_utf8_lossy(e.as_ref()));
            }
            Ok(Event::End(e)) if e.name().as_ref() == end_tag => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }
    Ok(out)
}

fn parse_custom_data(reader: &mut Reader<&[u8]>) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    let mut buf = Vec::new();
    let mut cur_key = String::new();
    let mut cur_val = String::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Item" => {
                    cur_key.clear();
                    cur_val.clear();
                }
                b"Key" => cur_key = read_text_until_end(reader, b"Key")?,
                b"Value" => cur_val = read_text_until_end(reader, b"Value")?,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"Item" => {
                    if !cur_key.is_empty() {
                        map.insert(cur_key.clone(), cur_val.clone());
                    }
                }
                b"CustomData" => break,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }
    Ok(map)
}

fn parse_meta(reader: &mut Reader<&[u8]>) -> Result<VaultMeta> {
    let mut meta = VaultMeta::default();
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Generator" => meta.generator = read_text_until_end(reader, b"Generator")?,
                b"DatabaseName" => {
                    meta.database_name = read_text_until_end(reader, b"DatabaseName")?
                }
                b"DatabaseDescription" => {
                    meta.database_description = read_text_until_end(reader, b"DatabaseDescription")?
                }
                b"DefaultUserName" => {
                    meta.default_username = read_text_until_end(reader, b"DefaultUserName")?
                }
                b"RecycleBinEnabled" => {
                    meta.recycle_bin_enabled =
                        parse_bool(&read_text_until_end(reader, b"RecycleBinEnabled")?)
                }
                b"RecycleBinUUID" => {
                    meta.recycle_bin_uuid =
                        decode_uuid_b64(&read_text_until_end(reader, b"RecycleBinUUID")?)
                }
                b"HistoryMaxItems" => {
                    if let Ok(v) = read_text_until_end(reader, b"HistoryMaxItems")?
                        .trim()
                        .parse::<usize>()
                    {
                        meta.history_max_items = v;
                    }
                }
                b"HistoryMaxSize" => {
                    if let Ok(v) = read_text_until_end(reader, b"HistoryMaxSize")?
                        .trim()
                        .parse::<usize>()
                    {
                        meta.history_max_size = v;
                    }
                }
                b"CustomData" => meta.custom_data = parse_custom_data(reader)?,
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"Meta" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }

    Ok(meta)
}

fn parse_times(reader: &mut Reader<&[u8]>) -> Result<EntryTimes> {
    let mut t = EntryTimes::default();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"CreationTime" => {
                    t.creation_time =
                        decode_kdbx_time(&read_text_until_end(reader, b"CreationTime")?)
                }
                b"LastModificationTime" => {
                    t.last_modification_time =
                        decode_kdbx_time(&read_text_until_end(reader, b"LastModificationTime")?)
                }
                b"LastAccessTime" => {
                    t.last_access_time =
                        decode_kdbx_time(&read_text_until_end(reader, b"LastAccessTime")?)
                }
                b"ExpiryTime" => {
                    t.expiry_time = decode_kdbx_time(&read_text_until_end(reader, b"ExpiryTime")?)
                }
                b"Expires" => t.expires = parse_bool(&read_text_until_end(reader, b"Expires")?),
                b"UsageCount" => {
                    if let Ok(v) = read_text_until_end(reader, b"UsageCount")?
                        .trim()
                        .parse::<u64>()
                    {
                        t.usage_count = v;
                    }
                }
                b"LocationChanged" => {
                    t.location_changed =
                        decode_kdbx_time(&read_text_until_end(reader, b"LocationChanged")?)
                }
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"Times" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }
    Ok(t)
}

fn parse_string_kv(
    reader: &mut Reader<&[u8]>,
    inner_cipher: &mut InnerStreamCipher,
) -> Result<(String, ProtectedString, bool)> {
    let mut key = String::new();
    let mut value = ProtectedString::default();
    let mut protected = false;
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Key" => key = read_text_until_end(reader, b"Key")?,
                b"Value" => {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Protected"
                            && parse_bool(&String::from_utf8_lossy(attr.value.as_ref()))
                        {
                            protected = true;
                        }
                    }
                    let raw_text = Zeroizing::new(read_text_until_end(reader, b"Value")?);
                    if protected {
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(raw_text.trim())
                            .map_err(|err| {
                                CipherPassError::XmlError(format!(
                                    "Invalid Base64 in protected Value: {err}"
                                ))
                            })?;
                        let mut plain = Zeroizing::new(decoded);
                        inner_cipher.apply(plain.as_mut_slice());
                        let owned_bytes = std::mem::take(&mut *plain);
                        let s = String::from_utf8(owned_bytes).map_err(|err| {
                            let _wiped = Zeroizing::new(err.into_bytes());
                            CipherPassError::XmlError(
                                "Decrypted protected Value is not valid UTF-8".into(),
                            )
                        })?;
                        value = ProtectedString::new(s);
                    } else {
                        value = ProtectedString::new(raw_text.as_str());
                    }
                }
                _ => {}
            },
            Ok(Event::Empty(e)) => {
                if e.name().as_ref() == b"Value" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"Protected"
                            && parse_bool(&String::from_utf8_lossy(attr.value.as_ref()))
                        {
                            protected = true;
                        }
                    }
                }
            }
            Ok(Event::End(e)) if e.name().as_ref() == b"String" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }

    Ok((key, value, protected))
}

fn parse_tags(raw: &str) -> Vec<String> {
    raw.split([';', ','])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_entry(
    reader: &mut Reader<&[u8]>,
    inner_cipher: &mut InnerStreamCipher,
    in_history: bool,
) -> Result<VaultEntry> {
    let mut entry = VaultEntry::new("");
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"UUID" => entry.uuid = decode_uuid_b64(&read_text_until_end(reader, b"UUID")?),
                b"IconID" => {
                    if let Ok(v) = read_text_until_end(reader, b"IconID")?
                        .trim()
                        .parse::<u32>()
                    {
                        entry.icon_id = v;
                    }
                }
                b"Tags" => entry.tags = parse_tags(&read_text_until_end(reader, b"Tags")?),
                b"Times" => entry.times = parse_times(reader)?,
                b"CustomData" => entry.custom_data = parse_custom_data(reader)?,
                b"String" => {
                    let (k, v, prot) = parse_string_kv(reader, inner_cipher)?;
                    match k.as_str() {
                        "Title" => entry.title = v.expose().to_string(),
                        "UserName" => entry.username = v.expose().to_string(),
                        "Password" => entry.password = v,
                        "URL" => entry.url = v.expose().to_string(),
                        "Notes" => entry.notes = v.expose().to_string(),
                        _ => entry.custom_fields.push(CustomField {
                            key: k,
                            value: v,
                            protected: prot,
                        }),
                    }
                }
                b"AutoType" => {
                    let mut abuf = Vec::new();
                    loop {
                        abuf.clear();
                        match reader.read_event_into(&mut abuf) {
                            Ok(Event::Start(ae)) if ae.name().as_ref() == b"Enabled" => {
                                entry.auto_type_enabled =
                                    parse_bool(&read_text_until_end(reader, b"Enabled")?);
                            }
                            Ok(Event::End(ae)) if ae.name().as_ref() == b"AutoType" => break,
                            Ok(Event::Eof) => break,
                            Err(err) => return Err(CipherPassError::XmlError(err.to_string())),
                            _ => {}
                        }
                    }
                }
                b"History" => {
                    if in_history {
                        return Err(CipherPassError::XmlError(
                            "Nested <History> elements are forbidden in KDBX XML".into(),
                        ));
                    }
                    let mut hbuf = Vec::new();
                    loop {
                        hbuf.clear();
                        match reader.read_event_into(&mut hbuf) {
                            Ok(Event::Start(he)) if he.name().as_ref() == b"Entry" => {
                                let hist_e = parse_entry(reader, inner_cipher, true)?;
                                entry.history.push(EntryHistoryItem {
                                    title: hist_e.title.clone(),
                                    username: hist_e.username.clone(),
                                    password: hist_e.password.clone(),
                                    url: hist_e.url.clone(),
                                    notes: hist_e.notes.clone(),
                                    tags: hist_e.tags.clone(),
                                    custom_fields: hist_e.custom_fields.clone(),
                                    times: hist_e.times.clone(),
                                });
                            }
                            Ok(Event::End(he)) if he.name().as_ref() == b"History" => break,
                            Ok(Event::Eof) => break,
                            Err(err) => return Err(CipherPassError::XmlError(err.to_string())),
                            _ => {}
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"Entry" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }

    Ok(entry)
}

fn parse_group(
    reader: &mut Reader<&[u8]>,
    inner_cipher: &mut InnerStreamCipher,
    depth: usize,
) -> Result<VaultGroup> {
    if depth > MAX_XML_GROUP_DEPTH {
        return Err(CipherPassError::XmlError(format!(
            "KDBX XML group nesting exceeds maximum depth ({MAX_XML_GROUP_DEPTH})"
        )));
    }
    let mut group = VaultGroup::new("", 48);
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"UUID" => group.uuid = decode_uuid_b64(&read_text_until_end(reader, b"UUID")?),
                b"Name" => group.name = read_text_until_end(reader, b"Name")?,
                b"Notes" => group.notes = read_text_until_end(reader, b"Notes")?,
                b"IconID" => {
                    if let Ok(v) = read_text_until_end(reader, b"IconID")?
                        .trim()
                        .parse::<u32>()
                    {
                        group.icon_id = v;
                    }
                }
                b"IsExpanded" => {
                    group.is_expanded = parse_bool(&read_text_until_end(reader, b"IsExpanded")?)
                }
                b"Times" => group.times = parse_times(reader)?,
                b"Entry" => group
                    .entries
                    .push(parse_entry(reader, inner_cipher, false)?),
                b"Group" => group
                    .subgroups
                    .push(parse_group(reader, inner_cipher, depth + 1)?),
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"Group" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }

    Ok(group)
}

fn parse_deleted_objects(reader: &mut Reader<&[u8]>) -> Result<Vec<DeletedObject>> {
    let mut out = Vec::new();
    let mut buf = Vec::new();
    let mut cur_uuid = Uuid::nil();
    let mut cur_time = Utc::now();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"DeletedObject" => {
                    cur_uuid = Uuid::nil();
                    cur_time = Utc::now();
                }
                b"UUID" => cur_uuid = decode_uuid_b64(&read_text_until_end(reader, b"UUID")?),
                b"DeletionTime" => {
                    cur_time = decode_kdbx_time(&read_text_until_end(reader, b"DeletionTime")?)
                }
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"DeletedObject" => out.push(DeletedObject {
                    uuid: cur_uuid,
                    deletion_time: cur_time,
                }),
                b"DeletedObjects" => break,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }
    Ok(out)
}

fn parse_root(
    reader: &mut Reader<&[u8]>,
    inner_cipher: &mut InnerStreamCipher,
) -> Result<(Option<VaultGroup>, Vec<DeletedObject>)> {
    let mut root_group = None;
    let mut deleted = Vec::new();
    let mut buf = Vec::new();

    loop {
        buf.clear();
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"Group" => root_group = Some(parse_group(reader, inner_cipher, 0)?),
                b"DeletedObjects" => deleted = parse_deleted_objects(reader)?,
                _ => {}
            },
            Ok(Event::End(e)) if e.name().as_ref() == b"Root" => break,
            Ok(Event::Eof) => break,
            Err(e) => return Err(CipherPassError::XmlError(e.to_string())),
            _ => {}
        }
    }
    Ok((root_group, deleted))
}
