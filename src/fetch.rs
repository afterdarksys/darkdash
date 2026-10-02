//! Signed settings cache and local break-glass.
//!
//! Threats: settings are an HTTPS GET with TLS 1.3 and the platform verifier.
//! No redirects, no proxy, and no Authorization header. An absent break-glass
//! file falls through to the server. Any other read error, or a present file
//! that does not verify, closes the console. A valid file overrides the server
//! for at most the signed lifetime. The cache keeps failures. A negative clock
//! is not cached and is not served from an older success.

use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zeroize::Zeroize;

use crate::audit::{self, AuditLine};
use crate::error::Error;
use crate::guard::read_private;
use crate::pin::Pin;
use crate::policy::{
    BreakGlass, CLOCK_SKEW_MS, MAX_ENVELOPE_BYTES, Policy, SETTINGS_MAX_SPAN_MS, enforce_lifetime,
    verify_break_glass, verify_settings,
};

const FETCH_EVERY_MS: i64 = 60_000;

pub(crate) struct PolicyCache {
    inner: Mutex<Option<Hit>>,
}

struct Hit {
    at_ms: i64,
    value: Result<Policy, &'static str>,
}

impl PolicyCache {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

pub(crate) struct Active {
    pub(crate) policy: Policy,
    pub(crate) source: &'static str,
    pub(crate) glass: Option<BreakGlass>,
    pub(crate) settings_problem: Option<&'static str>,
}

impl Active {
    fn from_server(policy: Policy) -> Self {
        Self {
            policy,
            source: "server",
            glass: None,
            settings_problem: None,
        }
    }

    fn from_glass(glass: BreakGlass, problem: Option<&'static str>) -> Self {
        Self {
            policy: glass.policy.clone(),
            source: "break_glass",
            glass: Some(glass),
            settings_problem: problem,
        }
    }
}

pub(crate) struct FetchCtx<'a> {
    pub(crate) pin: &'a Pin,
    pub(crate) source: &'a dyn SettingsSource,
    pub(crate) cache: &'a PolicyCache,
    pub(crate) audited: &'a Mutex<HashSet<String>>,
    pub(crate) audit_path: &'a Path,
}

pub(crate) trait SettingsSource: Send + Sync {
    fn fetch(&self, pin: &Pin, now: i64) -> Result<Policy, Error>;
}

pub(crate) struct HttpsSource;

impl SettingsSource for HttpsSource {
    fn fetch(&self, pin: &Pin, now: i64) -> Result<Policy, Error> {
        https_fetch(pin, now)
    }
}

pub(crate) fn known(code: &str) -> &'static str {
    match code {
        "settings_unreachable" => "settings_unreachable",
        "settings_rejected" => "settings_rejected",
        "settings_expired" => "settings_expired",
        "break_glass_invalid" => "break_glass_invalid",
        "break_glass_expired" => "break_glass_expired",
        "audit" => "audit",
        "token" => "token",
        "clock" => "clock",
        _ => "closed",
    }
}

enum GlassRead {
    Absent,
    Invalid(&'static str),
    Valid(BreakGlass),
}

pub(crate) fn resolve(ctx: &FetchCtx<'_>, now: i64) -> Result<Active, &'static str> {
    if now < 0 {
        return Err("clock");
    }
    match read_glass(ctx.pin, now) {
        GlassRead::Absent => server_policy(ctx, now).map(Active::from_server),
        GlassRead::Invalid(code) => Err(code),
        GlassRead::Valid(glass) => finish_glass(ctx, glass, now),
    }
}

fn finish_glass(ctx: &FetchCtx<'_>, glass: BreakGlass, now: i64) -> Result<Active, &'static str> {
    audit_glass_once(ctx, &glass, now)?;
    let problem = server_policy(ctx, now).err();
    Ok(Active::from_glass(glass, problem))
}

fn audit_glass_once(ctx: &FetchCtx<'_>, glass: &BreakGlass, now: i64) -> Result<(), &'static str> {
    let mut seen = ctx
        .audited
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    if seen.contains(&glass.identity) {
        return Ok(());
    }
    let line = AuditLine {
        at_ms: now,
        event: "break_glass",
        token_fp: None,
        actor: Some(glass.actor.as_str()),
        reason: Some(glass.reason.as_str()),
        expires_at_ms: Some(glass.policy.expires_at_ms),
        problem: None,
    };
    match audit::write(ctx.audit_path, &line) {
        Ok(()) => {
            seen.insert(glass.identity.clone());
            Ok(())
        }
        Err(_) => Err("audit"),
    }
}

fn read_glass(pin: &Pin, now: i64) -> GlassRead {
    let max = u64::try_from(MAX_ENVELOPE_BYTES).unwrap_or(16 * 1024);
    let mut bytes = match read_private(&pin.break_glass_file, max) {
        Ok(bytes) => bytes,
        Err(Error::Io(err)) if err.kind() == ErrorKind::NotFound => return GlassRead::Absent,
        Err(_) => return GlassRead::Invalid("break_glass_invalid"),
    };
    let read = classify_glass(&bytes, pin, now);
    bytes.zeroize();
    read
}

fn classify_glass(bytes: &[u8], pin: &Pin, now: i64) -> GlassRead {
    match verify_break_glass(bytes, &pin.break_glass_pubkey, now) {
        Ok(glass) => GlassRead::Valid(glass),
        Err(Error::Closed(code)) => GlassRead::Invalid(known(code)),
        Err(_) => GlassRead::Invalid("break_glass_invalid"),
    }
}

fn server_policy(ctx: &FetchCtx<'_>, now: i64) -> Result<Policy, &'static str> {
    if let Some(hit) = fresh_hit(ctx.cache, now) {
        return hit;
    }
    let fetched = fetch_and_audit(ctx, now);
    remember(ctx.cache, now, &fetched);
    fetched
}

fn fresh_hit(cache: &PolicyCache, now: i64) -> Option<Result<Policy, &'static str>> {
    let guard = cache
        .inner
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let hit = guard.as_ref()?;
    if !cache_fresh(hit, now) {
        return None;
    }
    match &hit.value {
        Ok(policy) if enforce_lifetime(policy, now, SETTINGS_MAX_SPAN_MS).is_err() => None,
        Err("clock") => None,
        _ => Some(hit.value.clone()),
    }
}

fn cache_fresh(hit: &Hit, now: i64) -> bool {
    now.saturating_sub(hit.at_ms) < FETCH_EVERY_MS && hit.at_ms <= now.saturating_add(CLOCK_SKEW_MS)
}

fn fetch_and_audit(ctx: &FetchCtx<'_>, now: i64) -> Result<Policy, &'static str> {
    match ctx.source.fetch(ctx.pin, now) {
        Ok(policy) => Ok(policy),
        Err(err) => {
            let code = map_fetch(err);
            note_settings(ctx, now, code);
            Err(code)
        }
    }
}

fn map_fetch(err: Error) -> &'static str {
    match err {
        Error::Closed(code) => known(code),
        Error::Usage | Error::Config(_) | Error::Io(_) => "settings_unreachable",
    }
}

fn note_settings(ctx: &FetchCtx<'_>, now: i64, code: &'static str) {
    if code != "settings_rejected" && code != "settings_expired" {
        return;
    }
    let line = AuditLine {
        at_ms: now,
        event: "settings_rejected",
        token_fp: None,
        actor: None,
        reason: None,
        expires_at_ms: None,
        problem: Some(code),
    };
    if audit::write(ctx.audit_path, &line).is_err() {
        eprintln!("darkdash: audit");
    }
}

fn remember(cache: &PolicyCache, now: i64, value: &Result<Policy, &'static str>) {
    if matches!(value, Err("clock")) {
        return;
    }
    let mut guard = cache
        .inner
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *guard = Some(Hit {
        at_ms: now,
        value: value.clone(),
    });
}

fn https_fetch(pin: &Pin, now: i64) -> Result<Policy, Error> {
    let agent = https_agent();
    let mut resp = match agent.get(&pin.settings_url).call() {
        Ok(resp) => resp,
        Err(_) => return Err(Error::Closed("settings_unreachable")),
    };
    if resp.status().as_u16() != 200 {
        let mut drained = resp
            .body_mut()
            .with_config()
            .limit(1024)
            .read_to_vec()
            .unwrap_or_default();
        drained.zeroize();
        return Err(Error::Closed("settings_rejected"));
    }
    let mut body = match resp.body_mut().with_config().limit(16 * 1024).read_to_vec() {
        Ok(body) => body,
        Err(_) => return Err(Error::Closed("settings_rejected")),
    };
    let result = verify_settings(&body, &pin.server_pubkey, now);
    body.zeroize();
    result
}

fn https_agent() -> ureq::Agent {
    let tls = ureq::tls::TlsConfig::builder()
        .root_certs(ureq::tls::RootCerts::PlatformVerifier)
        .unversioned_rustls_crypto_provider(tls13_provider())
        .build();
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .proxy(None)
        .http_status_as_error(false)
        .https_only(true)
        .tls_config(tls)
        .user_agent(concat!("darkdash/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn tls13_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| suite.version().version == rustls::ProtocolVersion::TLSv1_3);
    Arc::new(provider)
}

#[cfg(test)]
pub(crate) struct ScriptedSource {
    value: Mutex<Result<Policy, &'static str>>,
    pub(crate) calls: std::sync::atomic::AtomicU32,
}

#[cfg(test)]
impl ScriptedSource {
    pub(crate) fn new(value: Result<Policy, &'static str>) -> Self {
        Self {
            value: Mutex::new(value),
            calls: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub(crate) fn set(&self, value: Result<Policy, &'static str>) {
        *self
            .value
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = value;
    }
}

#[cfg(test)]
impl SettingsSource for ScriptedSource {
    fn fetch(&self, _pin: &Pin, _now: i64) -> Result<Policy, Error> {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self
            .value
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
        {
            Ok(policy) => Ok(policy),
            Err(code) => Err(Error::Closed(code)),
        }
    }
}

#[cfg(test)]
impl SettingsSource for Arc<ScriptedSource> {
    fn fetch(&self, pin: &Pin, now: i64) -> Result<Policy, Error> {
        ScriptedSource::fetch(self.as_ref(), pin, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::write_private_new;
    use crate::pin::parse_pin;
    use crate::policy::{parse_policy, public_from_secret, sign_break_glass};
    use std::sync::atomic::Ordering;

    const NOW: i64 = 1_700_000_000_000;

    fn secret(byte: u8) -> [u8; 32] {
        let mut raw = [byte; 32];
        raw[0] = byte.wrapping_add(3);
        raw
    }

    fn problem(result: Result<Active, &'static str>) -> &'static str {
        match result {
            Ok(_) => panic!("expected a closed policy"),
            Err(code) => code,
        }
    }

    fn policy_text(now: i64, span: i64) -> String {
        format!(
            "schema=darkdash.policy.v1\nissued_at_ms={now}\nexpires_at_ms={}\nrefresh_seconds=30\nwindow_hours=24\nsilence_seconds=90\nsite=Lab One\ntools=afterzero,nocved\n",
            now + span
        )
    }

    fn pin_for(dir: &Path, server: &[u8; 32], glass: &[u8; 32]) -> Pin {
        let server_hex = hex::encode(public_from_secret(server).unwrap());
        let glass_hex = hex::encode(public_from_secret(glass).unwrap());
        let text = format!(
            "{{\"schema\":\"darkdash.pin.v1\",\"settings_url\":\"https://darkapi.example/v1/darkdash/settings\",\"server_pubkey\":\"{server_hex}\",\"break_glass_pubkey\":\"{glass_hex}\",\"break_glass_file\":\"{}\",\"state_dir\":\"{}\",\"token_file\":\"{}\",\"audit_file\":\"{}\",\"bind\":\"127.0.0.1:9\"}}",
            dir.join("glass").display(),
            dir.join("state").display(),
            dir.join("token").display(),
            dir.join("audit").display()
        );
        parse_pin(&text).unwrap()
    }

    fn ctx<'a>(
        pin: &'a Pin,
        source: &'a ScriptedSource,
        cache: &'a PolicyCache,
        audited: &'a Mutex<HashSet<String>>,
    ) -> FetchCtx<'a> {
        FetchCtx {
            pin,
            source,
            cache,
            audited,
            audit_path: &pin.audit_file,
        }
    }

    #[test]
    fn server_cache_replaces_a_failure_and_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let server = secret(1);
        let glass = secret(2);
        let pin = pin_for(dir.path(), &server, &glass);
        let policy = parse_policy(&policy_text(NOW, 3_600_000)).unwrap();
        let source = ScriptedSource::new(Ok(policy));
        let cache = PolicyCache::new();
        let audited = Mutex::new(HashSet::new());
        let view = ctx(&pin, &source, &cache, &audited);
        assert_eq!(resolve(&view, NOW).unwrap().source, "server");
        assert_eq!(resolve(&view, NOW + 1_000).unwrap().source, "server");
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        source.set(Err("settings_unreachable"));
        assert!(matches!(
            resolve(&view, NOW + 61_000),
            Err("settings_unreachable")
        ));
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        assert!(matches!(
            resolve(&view, NOW + 62_000),
            Err("settings_unreachable")
        ));
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn invalid_glass_does_not_call_the_server() {
        let dir = tempfile::tempdir().unwrap();
        let pin = pin_for(dir.path(), &secret(1), &secret(2));
        write_private_new(&pin.break_glass_file, b"not-a-valid-envelope").unwrap();
        let source = ScriptedSource::new(Ok(parse_policy(&policy_text(NOW, 3_600_000)).unwrap()));
        let cache = PolicyCache::new();
        let audited = Mutex::new(HashSet::new());
        let view = ctx(&pin, &source, &cache, &audited);
        assert_eq!(problem(resolve(&view, NOW)), "break_glass_invalid");
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn valid_glass_overrides_a_down_server_once() {
        let dir = tempfile::tempdir().unwrap();
        let server = secret(1);
        let glass_key = secret(2);
        let pin = pin_for(dir.path(), &server, &glass_key);
        let text = policy_text(NOW, 3_600_000);
        let body = sign_break_glass(&glass_key, &text, "server down", "ops", NOW).unwrap();
        let identity = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["signature"]
            .as_str()
            .unwrap()
            .to_string();
        write_private_new(&pin.break_glass_file, &body).unwrap();
        let source = ScriptedSource::new(Err("settings_unreachable"));
        let cache = PolicyCache::new();
        let audited = Mutex::new(HashSet::new());
        let view = ctx(&pin, &source, &cache, &audited);
        let first = resolve(&view, NOW).unwrap();
        assert_eq!(first.source, "break_glass");
        assert_eq!(first.settings_problem, Some("settings_unreachable"));
        let audit = std::fs::read_to_string(&pin.audit_file).unwrap();
        assert_eq!(audit.matches("\"event\":\"break_glass\"").count(), 1);
        assert!(!audit.contains(&identity));
        assert!(!audit.contains("settings_unreachable"));
        let second = resolve(&view, NOW + 1_000).unwrap();
        assert_eq!(second.source, "break_glass");
        let again = std::fs::read_to_string(&pin.audit_file).unwrap();
        assert_eq!(again.matches("\"event\":\"break_glass\"").count(), 1);
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn negative_clock_is_not_cached() {
        let dir = tempfile::tempdir().unwrap();
        let pin = pin_for(dir.path(), &secret(1), &secret(2));
        let source = ScriptedSource::new(Ok(parse_policy(&policy_text(NOW, 3_600_000)).unwrap()));
        let cache = PolicyCache::new();
        let audited = Mutex::new(HashSet::new());
        let view = ctx(&pin, &source, &cache, &audited);
        assert_eq!(problem(resolve(&view, -1)), "clock");
        assert_eq!(source.calls.load(Ordering::SeqCst), 0);
        assert_eq!(resolve(&view, NOW).unwrap().source, "server");
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_cached_policy_is_refetched() {
        let dir = tempfile::tempdir().unwrap();
        let pin = pin_for(dir.path(), &secret(1), &secret(2));
        let source = ScriptedSource::new(Ok(parse_policy(&policy_text(NOW, 1_000)).unwrap()));
        let cache = PolicyCache::new();
        let audited = Mutex::new(HashSet::new());
        let view = ctx(&pin, &source, &cache, &audited);
        assert!(resolve(&view, NOW).is_ok());
        source.set(Err("settings_expired"));
        assert_eq!(problem(resolve(&view, NOW + 1_000)), "settings_expired");
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        let audit = std::fs::read_to_string(&pin.audit_file).unwrap();
        assert!(audit.contains("\"event\":\"settings_rejected\""));
        assert!(audit.contains("\"problem\":\"settings_expired\""));
    }

    #[test]
    fn arc_source_counts_once() {
        let dir = tempfile::tempdir().unwrap();
        let pin = pin_for(dir.path(), &secret(1), &secret(2));
        let source = Arc::new(ScriptedSource::new(Ok(parse_policy(&policy_text(
            NOW, 3_600_000,
        ))
        .unwrap())));
        let fetched = SettingsSource::fetch(&source, &pin, NOW);
        assert!(fetched.is_ok());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }
}
