//! Append-only operator audit.
//!
//! Threats: login and break-glass lines must not contain a token or a key.
//! `token_fp` is the first eight hex characters of SHA-256 over the raw 32
//! token bytes. That is an identifier, not a password hash. The file is
//! mode 0600, owned by this euid, and a symlink or a group-readable file is
//! refused. Lines cannot carry CR or LF.

use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::Error;
use crate::guard::append_private_line;
use crate::policy::graphic_label;

const MAX_AUDIT: u64 = 1_048_576;

#[derive(Serialize)]
struct Event<'a> {
    at_ms: i64,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_fp: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    problem: Option<&'a str>,
}

pub struct AuditLine<'a> {
    pub at_ms: i64,
    pub event: &'a str,
    pub token_fp: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub expires_at_ms: Option<i64>,
    pub problem: Option<&'a str>,
}

pub fn write(path: &Path, line: &AuditLine<'_>) -> Result<(), Error> {
    check_shape(line)?;
    let event = Event {
        at_ms: line.at_ms,
        event: line.event,
        token_fp: line.token_fp,
        actor: line.actor,
        reason: line.reason,
        expires_at_ms: line.expires_at_ms,
        problem: line.problem,
    };
    let mut text = serde_json::to_string(&event).map_err(|_| Error::Config("audit"))?;
    if text.len() > 2048 || text.contains('\n') || text.contains('\r') {
        text.zeroize();
        return Err(Error::Config("audit"));
    }
    let result = append_private_line(path, &text, MAX_AUDIT);
    text.zeroize();
    result
}

fn check_shape(line: &AuditLine<'_>) -> Result<(), Error> {
    match line.event {
        "login_ok" => fp_only(line),
        "login_fail" => empty_extra(line),
        "break_glass" => glass_fields(line),
        "settings_rejected" => problem_only(line),
        _ => Err(Error::Config("audit")),
    }
}

fn fp_only(line: &AuditLine<'_>) -> Result<(), Error> {
    if line.actor.is_some()
        || line.reason.is_some()
        || line.expires_at_ms.is_some()
        || line.problem.is_some()
    {
        return Err(Error::Config("audit"));
    }
    match line.token_fp {
        Some(fp) if fingerprint_shape(fp) => Ok(()),
        _ => Err(Error::Config("audit")),
    }
}

fn empty_extra(line: &AuditLine<'_>) -> Result<(), Error> {
    if line.token_fp.is_some()
        || line.actor.is_some()
        || line.reason.is_some()
        || line.expires_at_ms.is_some()
        || line.problem.is_some()
    {
        return Err(Error::Config("audit"));
    }
    Ok(())
}

fn glass_fields(line: &AuditLine<'_>) -> Result<(), Error> {
    if line.token_fp.is_some() || line.problem.is_some() || line.expires_at_ms.is_none() {
        return Err(Error::Config("audit"));
    }
    match (line.actor, line.reason) {
        (Some(actor), Some(reason)) => {
            graphic_label(actor, 1, 64)?;
            graphic_label(reason, 8, 160)?;
            Ok(())
        }
        _ => Err(Error::Config("audit")),
    }
}

fn problem_only(line: &AuditLine<'_>) -> Result<(), Error> {
    if line.token_fp.is_some()
        || line.actor.is_some()
        || line.reason.is_some()
        || line.expires_at_ms.is_some()
    {
        return Err(Error::Config("audit"));
    }
    match line.problem {
        Some(problem) if problem_shape(problem) => Ok(()),
        _ => Err(Error::Config("audit")),
    }
}

fn fingerprint_shape(fp: &str) -> bool {
    fp.len() == 8
        && fp
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn problem_shape(problem: &str) -> bool {
    let n = problem.len();
    (1..=32).contains(&n)
        && problem
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub fn decode_hex32(text: &str, out: &mut [u8; 32]) -> bool {
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        out.fill(0);
        return false;
    }
    match hex::decode(text) {
        Ok(bytes) if bytes.len() == 32 => {
            out.copy_from_slice(&bytes);
            true
        }
        _ => {
            out.fill(0);
            false
        }
    }
}

/// SHA-256 of the raw token bytes, first four bytes as eight hex chars.
/// Not a password verifier.
pub fn fingerprint_of_hex(token_hex: &str) -> Result<String, Error> {
    let mut raw = [0u8; 32];
    if !decode_hex32(token_hex, &mut raw) || bool::from(raw.ct_eq(&[0u8; 32])) {
        raw.zeroize();
        return Err(Error::Config("token"));
    }
    let digest = Sha256::digest(raw);
    raw.zeroize();
    Ok(hex::encode(&digest[..4]))
}
