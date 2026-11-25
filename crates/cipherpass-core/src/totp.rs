use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::error::{CipherPassError, Result};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, PartialEq, Eq)]
pub struct TotpConfig {
    pub secret: Zeroizing<Vec<u8>>,
    pub algorithm: TotpAlgorithm,
    pub digits: u32,
    pub period: u64,
    pub issuer: String,
    pub account: String,
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u64,
    pub period: u64,
    pub issuer: String,
    pub account: String,
}

fn percent_decode(input: &str) -> Zeroizing<String> {
    let bytes = input.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(val) = u8::from_str_radix(hex_str, 16) {
                    out.push(val);
                    i += 3;
                    continue;
                }
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(out.as_slice()).to_string())
}

fn decode_base32_secret(raw: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        raw.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    if cleaned.is_empty() {
        return Err(CipherPassError::InvalidTotp("Empty TOTP secret".into()));
    }
    let decoded = base32::decode(
        base32::Alphabet::Rfc4648 { padding: false },
        cleaned.as_str(),
    )
    .ok_or_else(|| CipherPassError::InvalidTotp("Invalid Base32 TOTP secret".into()))?;
    if decoded.is_empty() {
        return Err(CipherPassError::InvalidTotp(
            "Decoded TOTP secret is empty".into(),
        ));
    }
    Ok(Zeroizing::new(decoded))
}

/// Parse an `otpauth://totp/...` URI or a raw Base32 secret string.
pub fn parse_totp_uri(input: &str) -> Result<TotpConfig> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(CipherPassError::InvalidTotp("Empty TOTP input".into()));
    }

    // Convenience: if user pasted a raw Base32 secret instead of otpauth:// URI
    if !trimmed.to_ascii_lowercase().starts_with("otpauth://") {
        let secret = decode_base32_secret(trimmed)?;
        return Ok(TotpConfig {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: String::new(),
            account: String::new(),
        });
    }

    let rest = &trimmed["otpauth://".len()..];
    let (otp_type, after_type) = rest
        .split_once('/')
        .ok_or_else(|| CipherPassError::InvalidTotp("Missing otpauth path".into()))?;
    if !otp_type.eq_ignore_ascii_case("totp") {
        return Err(CipherPassError::InvalidTotp(format!(
            "Unsupported OTP type '{otp_type}' (only totp supported)"
        )));
    }

    let (label_raw, query) = after_type.split_once('?').ok_or_else(|| {
        CipherPassError::InvalidTotp("Missing query parameters in otpauth URI".into())
    })?;

    let label = percent_decode(label_raw);
    let (mut issuer, account) = if let Some((iss, acc)) = label.split_once(':') {
        (iss.trim().to_string(), acc.trim().to_string())
    } else {
        (String::new(), label.trim().to_string())
    };

    let mut secret_str: Option<Zeroizing<String>> = None;
    let mut algorithm = TotpAlgorithm::Sha1;
    let mut digits: u32 = 6;
    let mut period: u64 = 30;

    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let key = k.to_ascii_lowercase();
            let val = percent_decode(v);
            match key.as_str() {
                "secret" => secret_str = Some(val),
                "issuer" => {
                    if !val.trim().is_empty() {
                        issuer = val.trim().to_string();
                    }
                }
                "algorithm" => {
                    algorithm = match val.trim().to_ascii_uppercase().as_str() {
                        "SHA1" | "HMAC-SHA-1" => TotpAlgorithm::Sha1,
                        "SHA256" | "HMAC-SHA-256" => TotpAlgorithm::Sha256,
                        "SHA512" | "HMAC-SHA-512" => TotpAlgorithm::Sha512,
                        other => {
                            return Err(CipherPassError::InvalidTotp(format!(
                                "Unsupported TOTP algorithm: {other}"
                            )))
                        }
                    };
                }
                "digits" => {
                    let d = val.trim().parse::<u32>().map_err(|_| {
                        CipherPassError::InvalidTotp("Invalid digits parameter".into())
                    })?;
                    if !(6..=8).contains(&d) {
                        return Err(CipherPassError::InvalidTotp(
                            "TOTP digits must be 6, 7, or 8".into(),
                        ));
                    }
                    digits = d;
                }
                "period" => {
                    let p = val.trim().parse::<u64>().map_err(|_| {
                        CipherPassError::InvalidTotp("Invalid period parameter".into())
                    })?;
                    if p == 0 || p > 300 {
                        return Err(CipherPassError::InvalidTotp(
                            "TOTP period must be between 1 and 300 seconds".into(),
                        ));
                    }
                    period = p;
                }
                _ => {}
            }
        }
    }

    let secret_raw = secret_str
        .ok_or_else(|| CipherPassError::InvalidTotp("Missing secret parameter".into()))?;
    let secret = decode_base32_secret(secret_raw.as_str())?;

    Ok(TotpConfig {
        secret,
        algorithm,
        digits,
        period,
        issuer,
        account,
    })
}

/// Generate an RFC 6238 TOTP code at the specified UNIX timestamp (in seconds).
pub fn generate_totp_at(config: &TotpConfig, unix_secs: u64) -> TotpCode {
    let period = config.period.clamp(1, 300);
    let digits = config.digits.clamp(6, 8);
    let counter = unix_secs / period;
    let counter_bytes = counter.to_be_bytes();

    let digest = Zeroizing::new(match config.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac =
                HmacSha1::new_from_slice(config.secret.as_slice()).expect("HMAC accepts any key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                HmacSha256::new_from_slice(config.secret.as_slice()).expect("HMAC accepts any key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac =
                HmacSha512::new_from_slice(config.secret.as_slice()).expect("HMAC accepts any key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    });

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin_code: u32 = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);

    let modulo = 10u32.pow(digits);
    let otp = bin_code % modulo;
    let code = format!("{:0width$}", otp, width = digits as usize);
    let remaining_seconds = period - (unix_secs % period);

    TotpCode {
        code,
        remaining_seconds,
        period,
        issuer: config.issuer.clone(),
        account: config.account.clone(),
    }
}

/// Generate a live TOTP code from an `otpauth://` URI or raw Base32 secret using system UTC time.
pub fn generate_totp_now(uri_or_secret: &str) -> Result<TotpCode> {
    let config = parse_totp_uri(uri_or_secret)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CipherPassError::InvalidTotp(e.to_string()))?
        .as_secs();
    Ok(generate_totp_at(&config, now))
}
