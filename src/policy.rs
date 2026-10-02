//! Signed view policy.
//!
//! Threats: the server signature decides which tools, window, and poll
//! interval the console will render. A local break-glass signature can
//! replace that policy for at most four hours when the settings server is
//! unreachable. It cannot change the bind address, the state directory, the
//! token, or TLS. Verification uses ed25519-dalek `verify_strict` over a
//! domain-separated message. A settings signature does not verify as
//! break-glass. An invalid break-glass file is a closed console, not a
//! fallback to the server.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::error::Error;

pub const SETTINGS_SCHEMA: &str = "darkdash.settings.v1";
pub const GLASS_SCHEMA: &str = "darkdash.break_glass.v1";
pub const POLICY_SCHEMA: &str = "darkdash.policy.v1";
pub const SETTINGS_DOMAIN: &[u8] = b"darkdash.settings.v1\n";
pub const GLASS_DOMAIN: &[u8] = b"darkdash.break_glass.v1\n";
pub const MAX_POLICY_BYTES: usize = 4096;
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
pub const SETTINGS_MAX_SPAN_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub const GLASS_MAX_SPAN_MS: i64 = 4 * 60 * 60 * 1000;
pub(crate) const CLOCK_SKEW_MS: i64 = 120_000;

const TOOLS: &[&str] = &[
    "aftercve",
    "afterseal",
    "afterzero",
    "cveguard",
    "darkapple",
    "nocve-store",
    "nocved",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub refresh_seconds: u32,
    pub window_hours: u32,
    pub silence_seconds: u32,
    pub site: String,
    pub tools: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BreakGlass {
    pub policy: Policy,
    pub reason: String,
    pub actor: String,
    pub identity: String,
}

#[derive(Debug, Serialize)]
struct SettingsEnvelope<'a> {
    schema: &'a str,
    policy_canonical: &'a str,
    signature: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsEnvelopeIn {
    schema: String,
    policy_canonical: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct GlassEnvelope<'a> {
    schema: &'a str,
    policy_canonical: &'a str,
    signature: &'a str,
    reason: &'a str,
    actor: &'a str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GlassEnvelopeIn {
    schema: String,
    policy_canonical: String,
    signature: String,
    reason: String,
    actor: String,
}

pub fn canonical(policy: &Policy) -> String {
    format!(
        "schema={POLICY_SCHEMA}\nissued_at_ms={}\nexpires_at_ms={}\nrefresh_seconds={}\nwindow_hours={}\nsilence_seconds={}\nsite={}\ntools={}\n",
        policy.issued_at_ms,
        policy.expires_at_ms,
        policy.refresh_seconds,
        policy.window_hours,
        policy.silence_seconds,
        policy.site,
        policy.tools.join(",")
    )
}

pub fn parse_policy(text: &str) -> Result<Policy, Error> {
    if text.len() > MAX_POLICY_BYTES || text.contains('\r') {
        return Err(Error::Config("policy"));
    }
    let body = text.strip_suffix('\n').unwrap_or(text);
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() != 8 {
        return Err(Error::Config("policy"));
    }
    if lines[0] != format!("schema={POLICY_SCHEMA}") {
        return Err(Error::Config("policy"));
    }
    let issued_at_ms = expect_i64(lines[1], "issued_at_ms")?;
    let expires_at_ms = expect_i64(lines[2], "expires_at_ms")?;
    if issued_at_ms <= 0 || expires_at_ms <= 0 {
        return Err(Error::Config("policy"));
    }
    let refresh_seconds = expect_u32(lines[3], "refresh_seconds", 5, 120)?;
    let window_hours = expect_u32(lines[4], "window_hours", 1, 168)?;
    let silence_seconds = expect_u32(lines[5], "silence_seconds", 30, 3600)?;
    let site = expect_value(lines[6], "site")?;
    let tools_raw = expect_value(lines[7], "tools")?;
    if !site_ok(site) {
        return Err(Error::Config("policy"));
    }
    let tools = parse_tools(tools_raw)?;
    let policy = Policy {
        issued_at_ms,
        expires_at_ms,
        refresh_seconds,
        window_hours,
        silence_seconds,
        site: site.to_string(),
        tools,
    };
    if canonical(&policy) != text && canonical(&policy) != format!("{text}\n") {
        return Err(Error::Config("policy"));
    }
    Ok(policy)
}

fn expect_value<'a>(line: &'a str, key: &str) -> Result<&'a str, Error> {
    let prefix = format!("{key}=");
    line.strip_prefix(&prefix)
        .filter(|value| !value.is_empty() && !value.contains('='))
        .ok_or(Error::Config("policy"))
}

fn expect_i64(line: &str, key: &str) -> Result<i64, Error> {
    let raw = expect_raw(line, key)?;
    parse_i64(raw)
}

fn expect_u32(line: &str, key: &str, min: u32, max: u32) -> Result<u32, Error> {
    let raw = expect_raw(line, key)?;
    let value = parse_u32(raw)?;
    if value < min || value > max {
        return Err(Error::Config("policy"));
    }
    Ok(value)
}

fn expect_raw<'a>(line: &'a str, key: &str) -> Result<&'a str, Error> {
    let prefix = format!("{key}=");
    line.strip_prefix(&prefix).ok_or(Error::Config("policy"))
}

fn parse_i64(raw: &str) -> Result<i64, Error> {
    if !integer_text(raw) {
        return Err(Error::Config("policy"));
    }
    raw.parse().map_err(|_| Error::Config("policy"))
}

fn parse_u32(raw: &str) -> Result<u32, Error> {
    if !integer_text(raw) {
        return Err(Error::Config("policy"));
    }
    raw.parse().map_err(|_| Error::Config("policy"))
}

fn integer_text(raw: &str) -> bool {
    if raw.is_empty() || raw.starts_with('+') || (raw.len() > 1 && raw.starts_with('0')) {
        return false;
    }
    raw.bytes().all(|b| b.is_ascii_digit())
}

fn site_ok(site: &str) -> bool {
    let len = site.chars().count();
    (1..=64).contains(&len)
        && site
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == '.' || c == '_' || c == '-')
}

fn parse_tools(raw: &str) -> Result<Vec<String>, Error> {
    if raw.is_empty() {
        return Err(Error::Config("policy"));
    }
    let mut previous = "";
    let mut tools = Vec::new();
    for part in raw.split(',') {
        if part <= previous || !TOOLS.contains(&part) {
            return Err(Error::Config("policy"));
        }
        previous = part;
        tools.push(part.to_string());
    }
    if tools.is_empty() {
        return Err(Error::Config("policy"));
    }
    Ok(tools)
}

pub fn enforce_lifetime(policy: &Policy, now_ms: i64, max_span_ms: i64) -> Result<(), Error> {
    if now_ms < 0 {
        return Err(Error::Closed("clock"));
    }
    if policy.issued_at_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(Error::Closed("settings_expired"));
    }
    if policy.expires_at_ms <= now_ms {
        return Err(Error::Closed("settings_expired"));
    }
    let span = policy
        .expires_at_ms
        .checked_sub(policy.issued_at_ms)
        .ok_or(Error::Closed("settings_expired"))?;
    if span <= 0 || span > max_span_ms {
        return Err(Error::Closed("settings_expired"));
    }
    Ok(())
}

pub fn graphic_label(value: &str, min: usize, max: usize) -> Result<(), Error> {
    let bytes = value.as_bytes();
    if bytes.len() < min || bytes.len() > max {
        return Err(Error::Config("label"));
    }
    if bytes[0] == b' ' || bytes[bytes.len() - 1] == b' ' {
        return Err(Error::Config("label"));
    }
    if !bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(Error::Config("label"));
    }
    Ok(())
}

fn signing_key(secret: &[u8; 32]) -> Result<SigningKey, Error> {
    if bool::from(secret.ct_eq(&[0u8; 32])) {
        return Err(Error::Config("key"));
    }
    Ok(SigningKey::from_bytes(secret))
}

fn verifying_key(public: &[u8; 32]) -> Result<VerifyingKey, Error> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::Config("pubkey"))?;
    if key.is_weak() {
        return Err(Error::Config("pubkey"));
    }
    Ok(key)
}

fn signature_bytes(hex_text: &str) -> Result<[u8; 64], Error> {
    if hex_text.len() != 128
        || !hex_text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Config("signature"));
    }
    let bytes = hex::decode(hex_text).map_err(|_| Error::Config("signature"))?;
    let mut out = [0u8; 64];
    if bytes.len() != 64 {
        return Err(Error::Config("signature"));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn settings_message(canonical_text: &str) -> Vec<u8> {
    let mut message = Vec::with_capacity(SETTINGS_DOMAIN.len() + canonical_text.len());
    message.extend_from_slice(SETTINGS_DOMAIN);
    message.extend_from_slice(canonical_text.as_bytes());
    message
}

fn glass_message(reason: &str, actor: &str, canonical_text: &str) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(GLASS_DOMAIN);
    message.extend_from_slice(b"reason=");
    message.extend_from_slice(reason.as_bytes());
    message.extend_from_slice(b"\nactor=");
    message.extend_from_slice(actor.as_bytes());
    message.extend_from_slice(b"\n");
    message.extend_from_slice(canonical_text.as_bytes());
    message
}

fn prepare(text: &str, now_ms: i64, max_span_ms: i64) -> Result<(Policy, String), Error> {
    let policy = parse_policy(text)?;
    let canonical_text = canonical(&policy);
    enforce_lifetime(&policy, now_ms, max_span_ms)?;
    Ok((policy, canonical_text))
}

pub fn sign_settings(secret: &[u8; 32], policy_text: &str, now_ms: i64) -> Result<Vec<u8>, Error> {
    let (_policy, canonical_text) = prepare(policy_text, now_ms, SETTINGS_MAX_SPAN_MS)?;
    let key = signing_key(secret)?;
    let signature = key.sign(&settings_message(&canonical_text));
    let hex_sig = hex::encode(signature.to_bytes());
    let envelope = SettingsEnvelope {
        schema: SETTINGS_SCHEMA,
        policy_canonical: &canonical_text,
        signature: &hex_sig,
    };
    serde_json::to_vec(&envelope).map_err(|_| Error::Config("json"))
}

pub fn sign_break_glass(
    secret: &[u8; 32],
    policy_text: &str,
    reason: &str,
    actor: &str,
    now_ms: i64,
) -> Result<Vec<u8>, Error> {
    graphic_label(reason, 8, 160)?;
    graphic_label(actor, 1, 64)?;
    let (_policy, canonical_text) = prepare(policy_text, now_ms, GLASS_MAX_SPAN_MS)?;
    let key = signing_key(secret)?;
    let signature = key.sign(&glass_message(reason, actor, &canonical_text));
    let hex_sig = hex::encode(signature.to_bytes());
    let envelope = GlassEnvelope {
        schema: GLASS_SCHEMA,
        policy_canonical: &canonical_text,
        signature: &hex_sig,
        reason,
        actor,
    };
    serde_json::to_vec(&envelope).map_err(|_| Error::Config("json"))
}

fn verify_message(public: &[u8; 32], message: &[u8], signature_hex: &str) -> Result<(), Error> {
    let key = verifying_key(public)?;
    let raw = signature_bytes(signature_hex)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Error::Config("signature"))?;
    key.verify_strict(message, &signature)
        .map_err(|_| Error::Config("signature"))
}

pub fn verify_settings(body: &[u8], public: &[u8; 32], now_ms: i64) -> Result<Policy, Error> {
    if body.is_empty() || body.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::Closed("settings_rejected"));
    }
    let envelope: SettingsEnvelopeIn =
        serde_json::from_slice(body).map_err(|_| Error::Closed("settings_rejected"))?;
    if envelope.schema != SETTINGS_SCHEMA || envelope.policy_canonical.len() > MAX_POLICY_BYTES {
        return Err(Error::Closed("settings_rejected"));
    }
    verify_message(
        public,
        &settings_message(&envelope.policy_canonical),
        &envelope.signature,
    )
    .map_err(|_| Error::Closed("settings_rejected"))?;
    let policy =
        parse_policy(&envelope.policy_canonical).map_err(|_| Error::Closed("settings_rejected"))?;
    if canonical(&policy) != envelope.policy_canonical {
        return Err(Error::Closed("settings_rejected"));
    }
    enforce_lifetime(&policy, now_ms, SETTINGS_MAX_SPAN_MS)
        .map_err(|_| Error::Closed("settings_expired"))?;
    Ok(policy)
}

pub fn verify_break_glass(
    body: &[u8],
    public: &[u8; 32],
    now_ms: i64,
) -> Result<BreakGlass, Error> {
    if body.is_empty() || body.len() > MAX_ENVELOPE_BYTES {
        return Err(Error::Closed("break_glass_invalid"));
    }
    let envelope: GlassEnvelopeIn =
        serde_json::from_slice(body).map_err(|_| Error::Closed("break_glass_invalid"))?;
    if envelope.schema != GLASS_SCHEMA || envelope.policy_canonical.len() > MAX_POLICY_BYTES {
        return Err(Error::Closed("break_glass_invalid"));
    }
    if graphic_label(&envelope.reason, 8, 160).is_err()
        || graphic_label(&envelope.actor, 1, 64).is_err()
    {
        return Err(Error::Closed("break_glass_invalid"));
    }
    verify_message(
        public,
        &glass_message(
            &envelope.reason,
            &envelope.actor,
            &envelope.policy_canonical,
        ),
        &envelope.signature,
    )
    .map_err(|_| Error::Closed("break_glass_invalid"))?;
    let policy = parse_policy(&envelope.policy_canonical)
        .map_err(|_| Error::Closed("break_glass_invalid"))?;
    if canonical(&policy) != envelope.policy_canonical {
        return Err(Error::Closed("break_glass_invalid"));
    }
    enforce_lifetime(&policy, now_ms, GLASS_MAX_SPAN_MS)
        .map_err(|_| Error::Closed("break_glass_expired"))?;
    Ok(BreakGlass {
        policy,
        reason: envelope.reason,
        actor: envelope.actor,
        identity: envelope.signature,
    })
}

pub fn public_from_secret(secret: &[u8; 32]) -> Result<[u8; 32], Error> {
    let key = signing_key(secret)?;
    Ok(key.verifying_key().to_bytes())
}

pub fn generate_secret() -> Result<[u8; 32], Error> {
    let mut secret = [0u8; 32];
    if getrandom::fill(&mut secret).is_err() {
        secret.zeroize();
        return Err(Error::Config("random"));
    }
    if bool::from(secret.ct_eq(&[0u8; 32])) {
        secret.zeroize();
        return Err(Error::Config("random"));
    }
    Ok(secret)
}

pub fn parse_pubkey(hex_text: &str) -> Result<[u8; 32], Error> {
    if hex_text.len() != 64
        || !hex_text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::Config("pubkey"));
    }
    let bytes = hex::decode(hex_text).map_err(|_| Error::Config("pubkey"))?;
    let mut out = [0u8; 32];
    if bytes.len() != 32 {
        return Err(Error::Config("pubkey"));
    }
    out.copy_from_slice(&bytes);
    if bool::from(out.ct_eq(&[0u8; 32])) {
        return Err(Error::Config("pubkey"));
    }
    verifying_key(&out)?;
    Ok(out)
}

pub fn pubkeys_differ(left: &[u8; 32], right: &[u8; 32]) -> bool {
    !bool::from(left.ct_eq(right))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::Verifier;

    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn policy_text() -> String {
        sample(
            NOW,
            NOW + 3_600_000,
            30,
            24,
            90,
            "Lab One",
            "afterzero,cveguard,darkapple,nocved",
        )
    }

    fn sample(
        issued: i64,
        expires: i64,
        refresh: u32,
        window: u32,
        silence: u32,
        site: &str,
        tools: &str,
    ) -> String {
        format!(
            "schema=darkdash.policy.v1\nissued_at_ms={issued}\nexpires_at_ms={expires}\nrefresh_seconds={refresh}\nwindow_hours={window}\nsilence_seconds={silence}\nsite={site}\ntools={tools}\n"
        )
    }

    fn secret(byte: u8) -> [u8; 32] {
        let mut raw = [byte; 32];
        raw[0] = byte.wrapping_add(3);
        raw
    }

    #[test]
    fn parser_rejects_shape_lifetime_and_tool_errors() {
        let ok = parse_policy(&policy_text()).unwrap();
        assert_eq!(ok.issued_at_ms, NOW);
        assert_eq!(ok.tools.len(), 4);
        assert!(parse_policy(&format!("{}extra=1\n", policy_text())).is_err());
        assert!(
            parse_policy(&sample(
                NOW,
                NOW + 1000,
                30,
                24,
                90,
                "Lab",
                "nocved,afterzero"
            ))
            .is_err()
        );
        assert!(parse_policy(&sample(NOW, NOW + 1000, 30, 24, 90, "Lab", "falcon")).is_err());
        assert!(parse_policy(&sample(NOW, NOW + 1000, 5, 24, 90, "Lab", "afterzero")).is_ok());
        assert!(parse_policy(&format!(
            "schema=darkdash.policy.v1\nissued_at_ms={NOW}\nexpires_at_ms={}\nrefresh_seconds=05\nwindow_hours=24\nsilence_seconds=90\nsite=Lab\ntools=afterzero\n",
            NOW + 1000
        ))
        .is_err());
        assert!(enforce_lifetime(&ok, NOW + 3_600_000, SETTINGS_MAX_SPAN_MS).is_err());
        let future = parse_policy(&sample(
            NOW + 120_001,
            NOW + 130_000,
            30,
            24,
            90,
            "Lab",
            "afterzero",
        ))
        .unwrap();
        assert!(enforce_lifetime(&future, NOW, SETTINGS_MAX_SPAN_MS).is_err());
        let long = parse_policy(&sample(
            NOW,
            NOW + SETTINGS_MAX_SPAN_MS + 1,
            30,
            24,
            90,
            "Lab",
            "afterzero",
        ))
        .unwrap();
        assert!(enforce_lifetime(&long, NOW, SETTINGS_MAX_SPAN_MS).is_err());
        assert!(parse_policy(&sample(NOW, NOW + 1000, 30, 169, 90, "Lab", "afterzero")).is_err());
        let glass_span = parse_policy(&sample(
            NOW,
            NOW + GLASS_MAX_SPAN_MS + 1,
            30,
            24,
            90,
            "Lab",
            "afterzero",
        ))
        .unwrap();
        assert!(enforce_lifetime(&glass_span, NOW, GLASS_MAX_SPAN_MS).is_err());
    }

    #[test]
    fn signatures_fail_closed() {
        let text = policy_text();
        let server = secret(1);
        let glass = secret(2);
        let server_pub = public_from_secret(&server).unwrap();
        let glass_pub = public_from_secret(&glass).unwrap();
        let body = sign_settings(&server, &text, NOW).unwrap();
        let policy = verify_settings(&body, &server_pub, NOW).unwrap();
        assert_eq!(policy.site, "Lab One");

        let mut tampered = body.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;
        assert!(verify_settings(&tampered, &server_pub, NOW).is_err());
        assert!(verify_settings(&body, &glass_pub, NOW).is_err());
        assert!(verify_break_glass(&body, &server_pub, NOW).is_err());
        assert!(verify_break_glass(&body, &glass_pub, NOW).is_err());

        let glass_body = sign_break_glass(&glass, &text, "server down", "ops", NOW).unwrap();
        let opened = verify_break_glass(&glass_body, &glass_pub, NOW).unwrap();
        assert_eq!(opened.actor, "ops");
        assert!(verify_break_glass(&glass_body, &server_pub, NOW).is_err());
        assert!(verify_settings(&glass_body, &glass_pub, NOW).is_err());
    }

    #[test]
    fn strict_verification_rejects_a_small_order_key_that_plain_verify_accepts() {
        let public: [u8; 32] =
            hex::decode("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
                .unwrap()
                .try_into()
                .unwrap();
        let raw: [u8; 64] = hex::decode("359dbf604a3b3bedc20d5408b9d4770fbe52c922979b3178d02ab8d41c9c3a4e0700000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .try_into()
            .unwrap();
        let key = VerifyingKey::from_bytes(&public).unwrap();
        let signature = Signature::from_slice(&raw).unwrap();
        let first = b"afterzero.pin.a";
        let second = b"afterzero.pin.b";
        assert!(key.is_weak());
        assert!(key.verify(first, &signature).is_ok());
        assert!(key.verify(second, &signature).is_ok());
        assert!(key.verify_strict(first, &signature).is_err());
        assert!(key.verify_strict(second, &signature).is_err());
        assert!(verifying_key(&public).is_err());
    }

    #[test]
    fn all_zero_secret_is_rejected() {
        assert!(public_from_secret(&[0u8; 32]).is_err());
        let zeros = "0".repeat(64);
        assert!(parse_pubkey(&zeros).is_err());
    }
}
