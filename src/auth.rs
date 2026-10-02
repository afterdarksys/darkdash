//! Operator token and in-memory sessions.
//!
//! Threats: the token is 32 bytes from the OS CSPRNG, stored mode 0600, and
//! compared with `subtle` over the decoded bytes. A short or non-hex guess
//! still runs a compare against a dummy buffer. Eight failures lock the
//! listener for 60 seconds even if the next guess is right. Session ids are
//! not the operator token. SHA-256 is used only as an audit fingerprint.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::audit::decode_hex32;
use crate::error::Error;
use crate::guard::{read_private, write_private_new};

pub type Clock = Arc<dyn Fn() -> Result<i64, ()> + Send + Sync>;

const MAX_FAILS: u32 = 8;
const LOCK_MS: i64 = 60_000;
pub const SESSION_MS: i64 = 8 * 60 * 60 * 1000;
const MAX_SESSIONS: usize = 8;
const TOKEN_MAX: u64 = 80;

pub fn system_now() -> Result<i64, ()> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?;
    i64::try_from(dur.as_millis()).map_err(|_| ())
}

pub struct AuthState {
    failures: u32,
    locked_until: i64,
}

impl AuthState {
    pub fn new() -> Self {
        Self {
            failures: 0,
            locked_until: 0,
        }
    }

    pub fn allowed(&mut self, now: i64) -> bool {
        if now < self.locked_until {
            return false;
        }
        if self.locked_until != 0 {
            self.failures = 0;
            self.locked_until = 0;
        }
        true
    }

    pub fn fail(&mut self, now: i64) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= MAX_FAILS {
            self.locked_until = now.saturating_add(LOCK_MS);
        }
    }

    pub fn succeed(&mut self) {
        self.failures = 0;
        self.locked_until = 0;
    }
}

struct Session {
    id: [u8; 32],
    expires: i64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.id.zeroize();
    }
}

pub struct Sessions {
    items: VecDeque<Session>,
}

impl Sessions {
    pub fn new() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }

    pub fn insert(&mut self, id: [u8; 32], expires: i64) {
        if self.items.len() >= MAX_SESSIONS {
            self.items.pop_front();
        }
        self.items.push_back(Session { id, expires });
    }

    /// Constant-time membership. Expired rows stay until eviction and do not match.
    pub fn matches(&self, presented: &[u8; 32], now: i64) -> bool {
        let nonzero = !presented.ct_eq(&[0u8; 32]);
        let mut found = subtle::Choice::from(0u8);
        for session in &self.items {
            let fresh = subtle::Choice::from(u8::from(now < session.expires));
            let same = session.id.ct_eq(presented);
            found |= fresh & same & nonzero;
        }
        bool::from(found)
    }

    pub fn revoke(&mut self, presented: &[u8; 32]) {
        let nonzero = !presented.ct_eq(&[0u8; 32]);
        self.items
            .retain(|session| !bool::from(session.id.ct_eq(presented) & nonzero));
    }
}

pub fn new_session_id() -> Result<[u8; 32], Error> {
    let mut id = [0u8; 32];
    if getrandom::fill(&mut id).is_err() {
        id.zeroize();
        return Err(Error::Closed("closed"));
    }
    if bool::from(id.ct_eq(&[0u8; 32])) {
        id.zeroize();
        return Err(Error::Closed("closed"));
    }
    Ok(id)
}

pub fn tokens_match(presented: &str, expected: &str) -> bool {
    let mut left = [0u8; 32];
    let mut right = [0u8; 32];
    let decoded_left = decode_hex32(presented, &mut left);
    let decoded_right = decode_hex32(expected, &mut right);
    let shape = subtle::Choice::from(u8::from(decoded_left && decoded_right));
    let same = left.ct_eq(&right);
    let nonzero = !left.ct_eq(&[0u8; 32]);
    let ok = bool::from(shape & same & nonzero);
    left.zeroize();
    right.zeroize();
    ok
}

pub fn load_token(path: &Path) -> Result<String, Error> {
    let mut bytes = read_private(path, TOKEN_MAX)?;
    let text = match std::str::from_utf8(&bytes) {
        Ok(raw) => raw.trim().to_string(),
        Err(_) => {
            bytes.zeroize();
            return Err(Error::Config("token"));
        }
    };
    bytes.zeroize();
    if !tokens_match(&text, &text) {
        let mut owned = text;
        owned.zeroize();
        return Err(Error::Config("token"));
    }
    Ok(text)
}

pub fn write_token(path: &Path) -> Result<(), Error> {
    let mut raw = [0u8; 32];
    if getrandom::fill(&mut raw).is_err() {
        raw.zeroize();
        return Err(Error::Config("random"));
    }
    if bool::from(raw.ct_eq(&[0u8; 32])) {
        raw.zeroize();
        return Err(Error::Config("random"));
    }
    let mut text = hex::encode(raw);
    raw.zeroize();
    text.push('\n');
    let result = write_private_new(path, text.as_bytes());
    text.zeroize();
    if result.is_ok() {
        eprintln!("darkdash: wrote token");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eighth_failure_locks_until_the_window_passes() {
        let mut auth = AuthState::new();
        let now = 1_000_000_i64;
        for _ in 0..7 {
            assert!(auth.allowed(now));
            auth.fail(now);
        }
        assert!(auth.allowed(now));
        auth.fail(now);
        assert!(!auth.allowed(now));
        assert!(!auth.allowed(now + 59_000));
        assert!(auth.allowed(now + 61_000));
    }

    #[test]
    fn token_compare_rejects_shape_and_zero() {
        let good = "ab".repeat(32);
        assert!(tokens_match(&good, &good));
        assert!(!tokens_match(&"cd".repeat(32), &good));
        assert!(!tokens_match("AB", &good));
        assert!(!tokens_match(&"0".repeat(64), &"0".repeat(64)));
        assert!(!tokens_match("short", &good));
    }
}
