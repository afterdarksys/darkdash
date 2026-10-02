//! Read-only fleet panel from darkapi's reporting routes.
//!
//! Threats: the darkapi key is a report-only user key, which darkapi confines
//! to /v1/reports and /v1/sensor-keys. It is read from the pinned 0600 file on
//! each refresh, sent only as `X-API-Key` over TLS 1.3 to the pinned origin
//! with no redirects and no proxy, and wiped after use. darkdash only issues
//! GETs: it never acknowledges a signal or mints a key. Response bodies are
//! capped. Every displayed field passes an allow-list, so join, dedupe,
//! source_ref, sensor key ids, peer uids, ack notes, and item hashes never
//! reach the page. A failed refresh dashes the panel instead of drawing zeros.
//! Refreshes, failures included, run at most once per 30 s; the listener is
//! single-threaded, so a refresh can hold it for up to the 5 s timeout per
//! request.

use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroize;

use crate::fetch::https_agent_with;
use crate::guard::read_private;
use crate::pin::Fleet;
use crate::policy::CLOCK_SKEW_MS;
use crate::snapshot::{display_summary, rule_ok, summary_ok};

const FETCH_EVERY_MS: i64 = 30_000;
const TIMEOUT: Duration = Duration::from_secs(5);
const KEY_MAX: u64 = 256;
const HOSTS_CAP: u64 = 1 << 20;
const SIGNALS_CAP: u64 = 512 * 1024;
const REJECTIONS_CAP: u64 = 128 * 1024;
const HOSTS_SHOWN: usize = 200;
const HOSTS_PATH: &str = "/v1/reports/hosts";
const SIGNALS_PATH: &str = "/v1/reports/signals?state=open&limit=50";
const REJECTIONS_PATH: &str = "/v1/reports/rejections?limit=20";

/// The three raw bodies of one refresh.
pub(crate) struct RawFleet {
    pub(crate) hosts: Vec<u8>,
    pub(crate) signals: Vec<u8>,
    pub(crate) rejections: Vec<u8>,
}

pub(crate) trait FleetSource: Send + Sync {
    fn fetch(&self, fleet: &Fleet) -> Result<RawFleet, &'static str>;
}

pub(crate) struct HttpsFleet;

impl FleetSource for HttpsFleet {
    fn fetch(&self, fleet: &Fleet) -> Result<RawFleet, &'static str> {
        let mut key = load_key(fleet)?;
        let agent = https_agent_with(TIMEOUT);
        let result = fetch_all(&agent, fleet, &key);
        key.zeroize();
        result
    }
}

fn fetch_all(agent: &ureq::Agent, fleet: &Fleet, key: &str) -> Result<RawFleet, &'static str> {
    Ok(RawFleet {
        hosts: get(agent, fleet, key, HOSTS_PATH, HOSTS_CAP)?,
        signals: get(agent, fleet, key, SIGNALS_PATH, SIGNALS_CAP)?,
        rejections: get(agent, fleet, key, REJECTIONS_PATH, REJECTIONS_CAP)?,
    })
}

fn get(
    agent: &ureq::Agent,
    fleet: &Fleet,
    key: &str,
    path: &str,
    cap: u64,
) -> Result<Vec<u8>, &'static str> {
    let url = format!("{}{path}", fleet.url);
    let mut resp = agent
        .get(&url)
        .header("X-API-Key", key)
        .header("Accept", "application/json")
        .call()
        .map_err(|_| "fleet_unreachable")?;
    let status = resp.status().as_u16();
    if status != 200 {
        let mut drained = resp
            .body_mut()
            .with_config()
            .limit(1024)
            .read_to_vec()
            .unwrap_or_default();
        drained.zeroize();
        return Err(match status {
            401 | 403 => "fleet_key_rejected",
            429 => "fleet_limited",
            _ => "fleet_rejected",
        });
    }
    resp.body_mut()
        .with_config()
        .limit(cap)
        .read_to_vec()
        .map_err(|_| "fleet_rejected")
}

/// Read the pinned key: 0600, owned by this euid, one `dark_` key, an optional
/// trailing newline.
pub(crate) fn load_key(fleet: &Fleet) -> Result<String, &'static str> {
    let mut bytes = read_private(&fleet.key_file, KEY_MAX).map_err(|_| "fleet_key")?;
    let parsed = parse_key(&bytes);
    bytes.zeroize();
    parsed
}

fn parse_key(bytes: &[u8]) -> Result<String, &'static str> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let ok = body.starts_with(b"dark_")
        && (16..=200).contains(&body.len())
        && body
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-');
    if !ok {
        return Err("fleet_key");
    }
    std::str::from_utf8(body)
        .map(str::to_string)
        .map_err(|_| "fleet_key")
}

#[derive(Serialize, Clone)]
pub struct FleetOut {
    state: &'static str,
    problem: Option<&'static str>,
    fetched_at_ms: Option<i64>,
    hosts: Vec<HostOut>,
    hosts_total: u32,
    signals: Vec<SignalOut>,
    signals_more: bool,
    rejections: Vec<RejectionOut>,
    skipped: u32,
}

#[derive(Serialize, Clone)]
struct HostOut {
    host: String,
    status: &'static str,
    heartbeat_age_s: Option<i64>,
    pending: Option<u32>,
    version: Option<String>,
    darkapple: Option<&'static str>,
    active_keys: Option<u32>,
}

#[derive(Serialize, Clone)]
struct SignalOut {
    tool: &'static str,
    host: String,
    subject_host: Option<String>,
    class: &'static str,
    severity: &'static str,
    priority: &'static str,
    rule: String,
    summary: String,
    received_at: String,
    store_attributed: bool,
}

#[derive(Serialize, Clone)]
struct RejectionOut {
    route: String,
    reason: &'static str,
    received_at: String,
}

impl FleetOut {
    fn dashed(problem: &'static str) -> Self {
        Self {
            state: "dashed",
            problem: Some(problem),
            fetched_at_ms: None,
            hosts: Vec::new(),
            hosts_total: 0,
            signals: Vec::new(),
            signals_more: false,
            rejections: Vec::new(),
            skipped: 0,
        }
    }
}

pub(crate) struct FleetCache {
    inner: Mutex<Option<(i64, FleetOut)>>,
}

impl FleetCache {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

/// The panel for `now`: a fresh cached refresh, or a new one.
pub(crate) fn current(
    source: &dyn FleetSource,
    fleet: &Fleet,
    cache: &FleetCache,
    now: i64,
) -> FleetOut {
    {
        let guard = cache
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some((at, out)) = guard.as_ref()
            && now.saturating_sub(*at) < FETCH_EVERY_MS
            && *at <= now.saturating_add(CLOCK_SKEW_MS)
        {
            return out.clone();
        }
    }
    let out = match source.fetch(fleet) {
        Ok(mut raw) => {
            let folded = fold(&raw, now);
            raw.hosts.zeroize();
            raw.signals.zeroize();
            raw.rejections.zeroize();
            folded
        }
        Err(code) => FleetOut::dashed(code),
    };
    let mut guard = cache
        .inner
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *guard = Some((now, out.clone()));
    out
}

fn fold(raw: &RawFleet, now: i64) -> FleetOut {
    let (Some(hosts), Some(signals), Some(rejections)) = (
        items(&raw.hosts),
        items(&raw.signals),
        items(&raw.rejections),
    ) else {
        return FleetOut::dashed("fleet_rejected");
    };
    let mut skipped = 0u32;
    let mut host_rows = Vec::new();
    for value in &hosts.items {
        match host_row(value) {
            Some(row) => host_rows.push(row),
            None => skipped = skipped.saturating_add(1),
        }
    }
    let hosts_total = u32::try_from(host_rows.len()).unwrap_or(u32::MAX);
    host_rows.truncate(HOSTS_SHOWN);
    let mut signal_rows = Vec::new();
    for value in &signals.items {
        match signal_row(value) {
            Some(row) => signal_rows.push(row),
            None => skipped = skipped.saturating_add(1),
        }
    }
    let mut rejection_rows = Vec::new();
    for value in &rejections.items {
        match rejection_row(value) {
            Some(row) => rejection_rows.push(row),
            None => skipped = skipped.saturating_add(1),
        }
    }
    FleetOut {
        state: if skipped > 0 { "partial" } else { "shown" },
        problem: None,
        fetched_at_ms: Some(now),
        hosts: host_rows,
        hosts_total,
        signals: signal_rows,
        signals_more: signals.more,
        rejections: rejection_rows,
        skipped,
    }
}

struct Items {
    items: Vec<Value>,
    more: bool,
}

fn items(body: &[u8]) -> Option<Items> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let mut obj = match value {
        Value::Object(obj) => obj,
        _ => return None,
    };
    let more = match obj.get("next_cursor") {
        None | Some(Value::Null) => false,
        Some(Value::String(_)) => true,
        Some(_) => return None,
    };
    match obj.remove("items") {
        Some(Value::Array(items)) => Some(Items { items, more }),
        _ => None,
    }
}

fn host_row(value: &Value) -> Option<HostOut> {
    let obj = value.as_object()?;
    Some(HostOut {
        host: host_text(obj.get("host")?)?,
        status: host_status(obj.get("status")?.as_str()?)?,
        heartbeat_age_s: optional(obj.get("heartbeat_age_s"), |v| {
            v.as_i64().filter(|age| *age >= 0)
        })?,
        pending: optional(obj.get("pending"), small_count)?,
        version: optional(obj.get("darksignal_version"), version_text)?,
        darkapple: optional(obj.get("darkapple_status"), |v| {
            darkapple_status(v.as_str()?)
        })?,
        active_keys: optional(obj.get("active_keys"), small_count)?,
    })
}

fn signal_row(value: &Value) -> Option<SignalOut> {
    let obj = value.as_object()?;
    let rule = obj.get("rule")?.as_str()?;
    let summary = obj.get("summary")?.as_str()?;
    if !rule_ok(rule) || !summary_ok(summary) {
        return None;
    }
    Some(SignalOut {
        tool: tool_label(obj.get("tool")?.as_str()?)?,
        host: host_text(obj.get("host")?)?,
        subject_host: optional(obj.get("subject_host"), host_text)?,
        class: class_label(obj.get("class")?.as_str()?)?,
        severity: severity_label(obj.get("severity")?.as_str()?)?,
        priority: priority_label(obj.get("priority")?.as_str()?)?,
        rule: rule.to_string(),
        summary: display_summary(summary),
        received_at: time_text(obj.get("received_at")?)?,
        store_attributed: match obj.get("attribution") {
            None | Some(Value::Null) => false,
            Some(Value::String(text)) if text == "store" => true,
            Some(_) => return None,
        },
    })
}

fn rejection_row(value: &Value) -> Option<RejectionOut> {
    let obj = value.as_object()?;
    Some(RejectionOut {
        route: route_text(obj.get("route")?)?,
        reason: rejection_reason(obj.get("reason")?.as_str()?)?,
        received_at: time_text(obj.get("received_at")?)?,
    })
}

/// `Some(None)` for an absent or null field, `Some(Some(v))` for a valid one,
/// and `None` (row skipped) for a present value that fails `check`.
fn optional<T>(value: Option<&Value>, check: impl Fn(&Value) -> Option<T>) -> Option<Option<T>> {
    match value {
        None | Some(Value::Null) => Some(None),
        Some(value) => check(value).map(Some),
    }
}

fn small_count(value: &Value) -> Option<u32> {
    u32::try_from(value.as_u64()?).ok()
}

fn host_text(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let ok = (1..=253).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    ok.then(|| text.to_string())
}

fn version_text(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let ok = (1..=32).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'+' || b == b'-');
    ok.then(|| text.to_string())
}

fn time_text(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let ok = (10..=40).contains(&text.len())
        && text.bytes().all(|b| {
            b.is_ascii_digit() || matches!(b, b'T' | b'Z' | b':' | b'.' | b'+' | b'-')
        });
    ok.then(|| text.to_string())
}

fn route_text(value: &Value) -> Option<String> {
    let text = value.as_str()?;
    let ok = text.starts_with("/v1/")
        && text.len() <= 64
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'/' | b'_' | b'-'));
    ok.then(|| text.to_string())
}

fn host_status(value: &str) -> Option<&'static str> {
    match value {
        "online" => Some("online"),
        "stale" => Some("stale"),
        "silent" => Some("silent"),
        "never" => Some("never"),
        "clock_skew" => Some("clock_skew"),
        _ => None,
    }
}

fn darkapple_status(value: &str) -> Option<&'static str> {
    match value {
        "unseen" => Some("unseen"),
        "available" => Some("available"),
        "degraded" => Some("degraded"),
        "silent" => Some("silent"),
        _ => None,
    }
}

fn tool_label(value: &str) -> Option<&'static str> {
    match value {
        "nocved" => Some("nocved"),
        "aftercve" => Some("aftercve"),
        "cveguard" => Some("cveguard"),
        "afterseal" => Some("afterseal"),
        "nocve-store" => Some("nocve-store"),
        "darkapple" => Some("darkapple"),
        "afterzero" => Some("afterzero"),
        "darkapi" => Some("darkapi"),
        _ => None,
    }
}

fn class_label(value: &str) -> Option<&'static str> {
    match value {
        "threat" => Some("threat"),
        "breach" => Some("breach"),
        "vuln" => Some("vuln"),
        _ => None,
    }
}

fn severity_label(value: &str) -> Option<&'static str> {
    match value {
        "info" => Some("info"),
        "low" => Some("low"),
        "medium" => Some("medium"),
        "high" => Some("high"),
        "critical" => Some("critical"),
        _ => None,
    }
}

fn priority_label(value: &str) -> Option<&'static str> {
    match value {
        "p0" => Some("p0"),
        "p1" => Some("p1"),
        "p2" => Some("p2"),
        _ => None,
    }
}

fn rejection_reason(value: &str) -> Option<&'static str> {
    match value {
        "schema" => Some("schema"),
        "unknown_field" => Some("unknown_field"),
        "scope" => Some("scope"),
        "conflict" => Some("conflict"),
        "oversize" => Some("oversize"),
        "severity" => Some("severity"),
        "stale" => Some("stale"),
        "quota" => Some("quota"),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) struct ScriptedFleet {
    value: Mutex<Result<(String, String, String), &'static str>>,
    pub(crate) calls: std::sync::atomic::AtomicU32,
}

#[cfg(test)]
impl ScriptedFleet {
    pub(crate) fn new(value: Result<(String, String, String), &'static str>) -> Self {
        Self {
            value: Mutex::new(value),
            calls: std::sync::atomic::AtomicU32::new(0),
        }
    }

    pub(crate) fn set(&self, value: Result<(String, String, String), &'static str>) {
        *self
            .value
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = value;
    }
}

#[cfg(test)]
impl FleetSource for ScriptedFleet {
    fn fetch(&self, _fleet: &Fleet) -> Result<RawFleet, &'static str> {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let value = self
            .value
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()?;
        Ok(RawFleet {
            hosts: value.0.into_bytes(),
            signals: value.1.into_bytes(),
            rejections: value.2.into_bytes(),
        })
    }
}

#[cfg(test)]
impl FleetSource for std::sync::Arc<ScriptedFleet> {
    fn fetch(&self, fleet: &Fleet) -> Result<RawFleet, &'static str> {
        ScriptedFleet::fetch(self.as_ref(), fleet)
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    pub(crate) const HOSTS: &str = r#"{"items":[
        {"host":"edge-1","status":"online","heartbeat_age_s":12,"pending":3,"darksignal_version":"0.2.0",
         "darkapple_status":"available","active_keys":1,"heartbeat_problem":null,"accepted":10,
         "first_seen_at":"2026-10-01T00:00:00+00:00"},
        {"host":"ns2","status":"silent","heartbeat_age_s":900,"pending":null,"darksignal_version":null,
         "darkapple_status":null,"active_keys":1}
    ]}"#;
    pub(crate) const SIGNALS: &str = r#"{"items":[
        {"signal_id":"0192f0a0-0000-7000-8000-000000000001","sensor_key_id":"0123456789abcdef",
         "schema_version":2,"tool":"nocve-store","host":"store","subject_host":"ns2","class":"breach",
         "severity":"high","sev_rank":3,"priority":"p0","rule":"chain.rollback","summary":"chain rolled back on ns2",
         "observed_at":"2026-10-02T12:00:00+00:00","received_at":"2026-10-02T12:00:01.5+00:00",
         "joins":{"pid":"JOIN-FLEET-SECRET"},"peer_uid":0,"dedupe":"DEDUPE-FLEET-SECRET",
         "source_ref":"SOURCE-REF-SECRET","acknowledged_at":null,"ack_note":null,
         "expires_at":"2027-10-02T12:00:00+00:00","attribution":null}
    ],"next_cursor":"opaque-cursor"}"#;
    pub(crate) const REJECTIONS: &str = r#"{"items":[
        {"id":7,"sensor_key_id":"0123456789abcdef","route":"/v1/darksignal/nocved","item_index":1,
         "reason":"unknown_field","item_sha256":"ITEMHASHSECRET","received_at":"2026-10-02T11:00:00+00:00"}
    ],"next_cursor":null}"#;

    pub(crate) fn good() -> (String, String, String) {
        (HOSTS.to_string(), SIGNALS.to_string(), REJECTIONS.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{HOSTS, REJECTIONS, SIGNALS, good};
    use super::*;
    use crate::guard::write_private_new;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::Ordering;

    const NOW: i64 = 1_700_000_000_000;

    fn fleet(key_file: PathBuf) -> Fleet {
        Fleet {
            url: "https://api.darkapi.example".to_string(),
            key_file,
        }
    }

    fn render(out: &FleetOut) -> serde_json::Value {
        serde_json::to_value(out).unwrap()
    }

    #[test]
    fn good_bodies_are_shown_and_projected() {
        let source = ScriptedFleet::new(Ok(good()));
        let out = current(&source, &fleet(PathBuf::from("/k")), &FleetCache::new(), NOW);
        let value = render(&out);
        assert_eq!(value["state"], "shown");
        assert_eq!(value["hosts_total"], 2);
        assert_eq!(value["hosts"][0]["host"], "edge-1");
        assert_eq!(value["hosts"][0]["pending"], 3);
        assert_eq!(value["hosts"][1]["status"], "silent");
        assert_eq!(value["signals"][0]["subject_host"], "ns2");
        assert_eq!(value["signals"][0]["priority"], "p0");
        assert_eq!(value["signals_more"], true);
        assert_eq!(value["rejections"][0]["reason"], "unknown_field");
        let text = value.to_string();
        for secret in [
            "JOIN-FLEET-SECRET",
            "DEDUPE-FLEET-SECRET",
            "SOURCE-REF-SECRET",
            "ITEMHASHSECRET",
            "0123456789abcdef",
            "0192f0a0",
            "peer_uid",
            "ack_note",
            "first_seen_at",
        ] {
            assert!(!text.contains(secret), "{secret} leaked");
        }
    }

    #[test]
    fn a_bad_row_is_skipped_and_marks_partial() {
        let bidi = SIGNALS.replace("chain rolled back on ns2", "chain \u{202e}rolled");
        let unknown = HOSTS.replace("\"online\"", "\"sleepy\"");
        let reason = REJECTIONS.replace("unknown_field", "made_up");
        let source = ScriptedFleet::new(Ok((unknown, bidi, reason)));
        let out = current(&source, &fleet(PathBuf::from("/k")), &FleetCache::new(), NOW);
        let value = render(&out);
        assert_eq!(value["state"], "partial");
        assert_eq!(value["skipped"], 3);
        assert_eq!(value["hosts_total"], 1);
        assert!(value["signals"].as_array().unwrap().is_empty());
        assert!(value["rejections"].as_array().unwrap().is_empty());
    }

    #[test]
    fn a_bad_body_dashes_the_panel() {
        for body in ["[]", "{}", "{\"items\":{}}", "not json", "{\"items\":[],\"next_cursor\":7}"] {
            let source = ScriptedFleet::new(Ok((body.to_string(), SIGNALS.into(), REJECTIONS.into())));
            let out = current(&source, &fleet(PathBuf::from("/k")), &FleetCache::new(), NOW);
            let value = render(&out);
            assert_eq!(value["state"], "dashed", "{body}");
            assert_eq!(value["problem"], "fleet_rejected");
            assert!(value["hosts"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn hosts_are_capped_but_counted() {
        let rows: Vec<String> = (0..250)
            .map(|i| format!("{{\"host\":\"h{i}\",\"status\":\"online\"}}"))
            .collect();
        let hosts = format!("{{\"items\":[{}]}}", rows.join(","));
        let source = ScriptedFleet::new(Ok((hosts, SIGNALS.into(), REJECTIONS.into())));
        let value = render(&current(
            &source,
            &fleet(PathBuf::from("/k")),
            &FleetCache::new(),
            NOW,
        ));
        assert_eq!(value["hosts_total"], 250);
        assert_eq!(value["hosts"].as_array().unwrap().len(), HOSTS_SHOWN);
    }

    #[test]
    fn failures_dash_and_are_cached_for_the_interval() {
        let source = ScriptedFleet::new(Err("fleet_key_rejected"));
        let cache = FleetCache::new();
        let pin = fleet(PathBuf::from("/k"));
        let first = render(&current(&source, &pin, &cache, NOW));
        assert_eq!(first["state"], "dashed");
        assert_eq!(first["problem"], "fleet_key_rejected");
        source.set(Ok(good()));
        let held = render(&current(&source, &pin, &cache, NOW + 29_000));
        assert_eq!(held["state"], "dashed");
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        let fresh = render(&current(&source, &pin, &cache, NOW + 30_000));
        assert_eq!(fresh["state"], "shown");
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        let back = render(&current(&source, &pin, &cache, NOW - 200_000));
        assert_eq!(back["state"], "shown");
        assert_eq!(source.calls.load(Ordering::SeqCst), 3, "a backward clock refetches");
    }

    #[test]
    fn key_file_must_be_private_and_well_formed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fleet.key");
        write_private_new(&path, b"dark_abcdefghijklmnopqrstuvwxyz012345\n").unwrap();
        let mut key = load_key(&fleet(path.clone())).unwrap();
        assert_eq!(key, "dark_abcdefghijklmnopqrstuvwxyz012345");
        key.zeroize();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_key(&fleet(path)).unwrap_err(), "fleet_key");
        assert_eq!(
            load_key(&fleet(dir.path().join("absent"))).unwrap_err(),
            "fleet_key"
        );
        for bad in [
            &b"dsk_0123456789abcdef_0123"[..],
            b"dark_short",
            b"dark_has space in it here",
            b"dark_abcdefghijklmnopqrstuvwxyz\n\n",
            b"Bearer dark_abcdefghijklmnopqrstuvwxyz",
        ] {
            assert_eq!(parse_key(bad).unwrap_err(), "fleet_key");
        }
    }
}
