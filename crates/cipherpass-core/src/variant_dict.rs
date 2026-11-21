use std::collections::BTreeMap;

use crate::error::{CipherPassError, Result};

const VARIANT_DICT_VERSION: u16 = 0x0100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantValue {
    UInt32(u32),
    UInt64(u64),
    Bool(bool),
    Int32(i32),
    Int64(i64),
    String(String),
    Bytes(Vec<u8>),
}

/// KDBX 4 VariantDictionary (version 0x0100) used for KdfParameters and PublicCustomData.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariantDictionary {
    pub entries: BTreeMap<String, VariantValue>,
}

impl VariantDictionary {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: impl Into<String>, value: VariantValue) {
        self.entries.insert(key.into(), value);
    }

    pub fn get_bytes(&self, key: &str) -> Option<&[u8]> {
        match self.entries.get(key) {
            Some(VariantValue::Bytes(b)) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        match self.entries.get(key) {
            Some(VariantValue::UInt32(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.entries.get(key) {
            Some(VariantValue::UInt64(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.entries.get(key) {
            Some(VariantValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(CipherPassError::MalformedFormat(
                "VariantDictionary truncated (missing version)".into(),
            ));
        }

        let version = u16::from_le_bytes([data[0], data[1]]);
        if (version & 0xFF00) != VARIANT_DICT_VERSION {
            return Err(CipherPassError::MalformedFormat(format!(
                "Unsupported VariantDictionary version: 0x{version:04x}"
            )));
        }

        let mut offset = 2usize;
        let mut dict = Self::new();

        while offset < data.len() {
            let value_type = data[offset];
            offset += 1;
            if value_type == 0x00 {
                break;
            }

            if offset + 4 > data.len() {
                return Err(CipherPassError::MalformedFormat(
                    "VariantDictionary truncated key length".into(),
                ));
            }
            let key_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + key_len > data.len() {
                return Err(CipherPassError::MalformedFormat(
                    "VariantDictionary truncated key".into(),
                ));
            }
            let key = std::str::from_utf8(&data[offset..offset + key_len])
                .map_err(|_| {
                    CipherPassError::MalformedFormat(
                        "VariantDictionary key is not valid UTF-8".into(),
                    )
                })?
                .to_string();
            offset += key_len;

            if offset + 4 > data.len() {
                return Err(CipherPassError::MalformedFormat(
                    "VariantDictionary truncated value length".into(),
                ));
            }
            let val_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;

            if offset + val_len > data.len() {
                return Err(CipherPassError::MalformedFormat(
                    "VariantDictionary truncated value".into(),
                ));
            }
            let raw = &data[offset..offset + val_len];
            offset += val_len;

            let value = match value_type {
                0x04 => {
                    if raw.len() != 4 {
                        return Err(CipherPassError::MalformedFormat(
                            "VariantDictionary UInt32 wrong length".into(),
                        ));
                    }
                    VariantValue::UInt32(u32::from_le_bytes(raw.try_into().unwrap()))
                }
                0x05 => {
                    if raw.len() != 8 {
                        return Err(CipherPassError::MalformedFormat(
                            "VariantDictionary UInt64 wrong length".into(),
                        ));
                    }
                    VariantValue::UInt64(u64::from_le_bytes(raw.try_into().unwrap()))
                }
                0x08 => {
                    if raw.len() != 1 {
                        return Err(CipherPassError::MalformedFormat(
                            "VariantDictionary Bool wrong length".into(),
                        ));
                    }
                    VariantValue::Bool(raw[0] != 0)
                }
                0x0C => {
                    if raw.len() != 4 {
                        return Err(CipherPassError::MalformedFormat(
                            "VariantDictionary Int32 wrong length".into(),
                        ));
                    }
                    VariantValue::Int32(i32::from_le_bytes(raw.try_into().unwrap()))
                }
                0x0D => {
                    if raw.len() != 8 {
                        return Err(CipherPassError::MalformedFormat(
                            "VariantDictionary Int64 wrong length".into(),
                        ));
                    }
                    VariantValue::Int64(i64::from_le_bytes(raw.try_into().unwrap()))
                }
                0x18 => {
                    let s = std::str::from_utf8(raw).map_err(|_| {
                        CipherPassError::MalformedFormat(
                            "VariantDictionary String is not valid UTF-8".into(),
                        )
                    })?;
                    VariantValue::String(s.to_string())
                }
                0x42 => VariantValue::Bytes(raw.to_vec()),
                other => {
                    return Err(CipherPassError::MalformedFormat(format!(
                        "Unknown VariantDictionary type 0x{other:02x}"
                    )));
                }
            };

            dict.insert(key, value);
        }

        Ok(dict)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VARIANT_DICT_VERSION.to_le_bytes());

        for (key, value) in &self.entries {
            let (tag, bytes): (u8, Vec<u8>) = match value {
                VariantValue::UInt32(v) => (0x04, v.to_le_bytes().to_vec()),
                VariantValue::UInt64(v) => (0x05, v.to_le_bytes().to_vec()),
                VariantValue::Bool(v) => (0x08, vec![u8::from(*v)]),
                VariantValue::Int32(v) => (0x0C, v.to_le_bytes().to_vec()),
                VariantValue::Int64(v) => (0x0D, v.to_le_bytes().to_vec()),
                VariantValue::String(s) => (0x18, s.as_bytes().to_vec()),
                VariantValue::Bytes(b) => (0x42, b.clone()),
            };

            out.push(tag);
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }

        out.push(0x00);
        out
    }
}
