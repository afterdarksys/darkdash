//! Fold queue rows into the chart snapshot.
//!
//! Threats: a row is counted only when its tool is on the signed policy and
//! its class, severity, priority, rule, and summary match the allow-lists.
//! The summary may contain a slash. Control characters and bidi overrides are
//! dropped. The snapshot never includes join, dedupe, or evidence fields.
//! A queue that fails its file checks contributes no counts, series, or
//! recent rows. The bus is dashed unless `status.json` parsed.

use serde::Serialize;
use serde_json::Value;

use crate::fleet::FleetOut;
use crate::policy::{BreakGlass, CLOCK_SKEW_MS, Policy};
use crate::queue::{RawRow, StatusView};

const HOUR_MS: i64 = 3_600_000;
const DAY_MS: i64 = 86_400_000;
const RECENT_MAX: usize = 40;
const BUCKET_CAP: usize = 400;

pub struct FoldIn<'a> {
    pub rows: &'a [RawRow],
    pub truncated: bool,
    pub policy: &'a Policy,
    pub now: i64,
    pub queue_problem: Option<&'static str>,
    pub status: &'a StatusView,
    pub source: &'a str,
    pub settings_problem: Option<&'static str>,
    pub glass: Option<&'a BreakGlass>,
    pub fleet: Option<&'a FleetOut>,
}

pub fn window_bounds(now: i64, hours: u32) -> (i64, i64) {
    let start = now.saturating_sub(i64::from(hours).saturating_mul(HOUR_MS));
    let end = now.saturating_add(CLOCK_SKEW_MS);
    (start, end)
}

pub(crate) fn floor_bucket(ts: i64, size: i64) -> i64 {
    if size <= 0 {
        return ts;
    }
    ts.saturating_sub(ts.rem_euclid(size))
}

pub fn build(input: &FoldIn<'_>) -> Result<Vec<u8>, ()> {
    let folded = fold(input);
    serde_json::to_vec(&folded).map_err(|_| ())
}

#[derive(Serialize)]
struct Snap<'a> {
    refresh_seconds: u32,
    window_hours: u32,
    silence_seconds: u32,
    site: &'a str,
    settings_problem: Option<&'a str>,
    queue_problem: Option<&'a str>,
    break_glass: Option<GlassOut<'a>>,
    host: Option<&'a str>,
    status: &'a StatusView,
    tools: Vec<ToolOut>,
    series: Vec<SeriesOut>,
    recent: Vec<RecentOut>,
    now_ms: i64,
    policy_source: &'a str,
    skipped: u32,
    truncated: bool,
    components: Components,
    fleet: Option<&'a FleetOut>,
}

#[derive(Serialize)]
struct Components {
    bus: &'static str,
    queue: &'static str,
}

#[derive(Serialize)]
struct GlassOut<'a> {
    reason: &'a str,
    actor: &'a str,
    expires_at_ms: i64,
}

#[derive(Serialize)]
struct ToolOut {
    tool: String,
    total: u32,
    pending: u32,
    sent: u32,
    rejected: u32,
    breach: u32,
    silent: bool,
    latest_ms: Option<i64>,
}

#[derive(Serialize)]
struct SeriesOut {
    tool: String,
    points: Vec<PointOut>,
}

#[derive(Serialize)]
struct PointOut {
    bucket_start_ms: i64,
    count: u32,
}

#[derive(Serialize)]
struct RecentOut {
    tool: String,
    class: String,
    severity: String,
    priority: String,
    rule: String,
    summary: String,
    state: String,
    at_ms: i64,
}

struct Acc {
    total: u32,
    pending: u32,
    sent: u32,
    rejected: u32,
    breach: u32,
    latest_ms: Option<i64>,
    buckets: Vec<u32>,
}

struct Kept {
    index: usize,
    class: &'static str,
    severity: &'static str,
    priority: &'static str,
    rule: String,
    summary: String,
    state: &'static str,
    at_ms: i64,
}

struct Readings {
    tools: Vec<ToolOut>,
    series: Vec<SeriesOut>,
    recent: Vec<RecentOut>,
    skipped: u32,
    truncated: bool,
}

fn fold<'a>(input: &FoldIn<'a>) -> Snap<'a> {
    let readings = if input.queue_problem.is_some() {
        Readings::empty()
    } else {
        collect(input)
    };
    assemble(input, readings)
}

fn assemble<'a>(input: &FoldIn<'a>, readings: Readings) -> Snap<'a> {
    let components = Components {
        bus: bus_state(input.status),
        queue: queue_state(input.queue_problem, readings.truncated, readings.skipped),
    };
    Snap {
        refresh_seconds: input.policy.refresh_seconds,
        window_hours: input.policy.window_hours,
        silence_seconds: input.policy.silence_seconds,
        site: &input.policy.site,
        settings_problem: input.settings_problem,
        queue_problem: input.queue_problem,
        break_glass: input.glass.map(|glass| GlassOut {
            reason: &glass.reason,
            actor: &glass.actor,
            expires_at_ms: glass.policy.expires_at_ms,
        }),
        host: input.status.host.as_deref(),
        status: input.status,
        tools: readings.tools,
        series: readings.series,
        recent: readings.recent,
        now_ms: input.now,
        policy_source: input.source,
        skipped: readings.skipped,
        truncated: readings.truncated,
        components,
        fleet: input.fleet,
    }
}

fn bus_state(status: &StatusView) -> &'static str {
    if status.read == "ok" || status.read == "stale" {
        "shown"
    } else {
        "dashed"
    }
}

fn queue_state(problem: Option<&str>, truncated: bool, skipped: u32) -> &'static str {
    if problem.is_some() {
        "dashed"
    } else if truncated || skipped > 0 {
        "partial"
    } else {
        "shown"
    }
}

impl Readings {
    fn empty() -> Self {
        Self {
            tools: Vec::new(),
            series: Vec::new(),
            recent: Vec::new(),
            skipped: 0,
            truncated: false,
        }
    }
}

fn collect(input: &FoldIn<'_>) -> Readings {
    let size = bucket_size(input.policy.window_hours);
    let (start, _) = window_bounds(input.now, input.policy.window_hours);
    let starts = bucket_starts(start, input.now, size);
    let mut acc = new_acc(&input.policy.tools, starts.len());
    let mut recent = Vec::new();
    let mut skipped = 0u32;
    for row in input.rows {
        match keep_row(row, input.policy) {
            Some(kept) => {
                apply(&mut acc[kept.index], &kept, &starts, size);
                push_recent(&mut recent, &kept, input.policy);
            }
            None => skipped = skipped.saturating_add(1),
        }
    }
    Readings {
        tools: cards(
            &input.policy.tools,
            &acc,
            input.now,
            input.policy.silence_seconds,
        ),
        series: series_out(&input.policy.tools, &acc, &starts),
        recent,
        skipped,
        truncated: input.truncated,
    }
}

fn bucket_size(hours: u32) -> i64 {
    if hours <= 48 { HOUR_MS } else { DAY_MS }
}

fn bucket_starts(start: i64, now: i64, size: i64) -> Vec<i64> {
    let mut out = Vec::new();
    if size <= 0 {
        return out;
    }
    let mut cursor = floor_bucket(start, size);
    let last = floor_bucket(now, size);
    while cursor <= last && out.len() < BUCKET_CAP {
        out.push(cursor);
        cursor = cursor.saturating_add(size);
    }
    out
}

fn new_acc(tools: &[String], buckets: usize) -> Vec<Acc> {
    let mut out = Vec::with_capacity(tools.len());
    for _ in tools {
        out.push(Acc {
            total: 0,
            pending: 0,
            sent: 0,
            rejected: 0,
            breach: 0,
            latest_ms: None,
            buckets: vec![0; buckets],
        });
    }
    out
}

fn keep_row(row: &RawRow, policy: &Policy) -> Option<Kept> {
    if row.payload.is_none() || row.payload_len > 16_384 {
        return None;
    }
    let text = row.payload.as_deref()?;
    let fields = payload_fields(text)?;
    if fields.tool != row.tool {
        return None;
    }
    let index = tool_index(&policy.tools, &row.tool)?;
    let class = class_label(&fields.class)?;
    let severity = severity_label(&fields.severity)?;
    let priority = priority_label(&fields.priority)?;
    let state = state_label(&row.state)?;
    if !rule_ok(&fields.rule) || !summary_ok(&fields.summary) {
        return None;
    }
    Some(Kept {
        index,
        class,
        severity,
        priority,
        rule: fields.rule,
        summary: display_summary(&fields.summary),
        state,
        at_ms: row.created_at_ms,
    })
}

struct Fields {
    tool: String,
    class: String,
    severity: String,
    priority: String,
    rule: String,
    summary: String,
}

fn payload_fields(text: &str) -> Option<Fields> {
    let value: Value = serde_json::from_str(text).ok()?;
    let obj = value.as_object()?;
    Some(Fields {
        tool: obj.get("tool").and_then(Value::as_str)?.to_string(),
        class: obj.get("class").and_then(Value::as_str)?.to_string(),
        severity: obj.get("severity").and_then(Value::as_str)?.to_string(),
        priority: obj.get("priority").and_then(Value::as_str)?.to_string(),
        rule: obj.get("rule").and_then(Value::as_str)?.to_string(),
        summary: obj.get("summary").and_then(Value::as_str)?.to_string(),
    })
}

fn tool_index(tools: &[String], name: &str) -> Option<usize> {
    tools.iter().position(|tool| tool == name)
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

fn state_label(value: &str) -> Option<&'static str> {
    match value {
        "pending" => Some("pending"),
        "sent" => Some("sent"),
        "rejected" => Some("rejected"),
        _ => None,
    }
}

pub(crate) fn rule_ok(rule: &str) -> bool {
    let bytes = rule.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    let first = bytes[0];
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    bytes[1..].iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || *byte == b'.'
            || *byte == b'_'
            || *byte == b'-'
    })
}

pub(crate) fn summary_ok(text: &str) -> bool {
    let count = text.chars().count();
    if count == 0 || count > 512 {
        return false;
    }
    text.chars().all(|ch| {
        let code = u32::from(ch);
        code >= 0x20
            && code != 0x7f
            && !(0x202A..=0x202E).contains(&code)
            && !(0x2066..=0x2069).contains(&code)
    })
}

pub(crate) fn display_summary(text: &str) -> String {
    text.chars().take(180).collect()
}

fn apply(acc: &mut Acc, kept: &Kept, starts: &[i64], size: i64) {
    acc.total = acc.total.saturating_add(1);
    add_state(acc, kept.state);
    if kept.class == "breach" {
        acc.breach = acc.breach.saturating_add(1);
    }
    acc.latest_ms = Some(match acc.latest_ms {
        Some(prev) => prev.max(kept.at_ms),
        None => kept.at_ms,
    });
    let bucket = floor_bucket(kept.at_ms, size);
    if let Some(index) = starts.iter().position(|start| *start == bucket)
        && let Some(slot) = acc.buckets.get_mut(index)
    {
        *slot = slot.saturating_add(1);
    }
}

fn add_state(acc: &mut Acc, state: &str) {
    match state {
        "pending" => acc.pending = acc.pending.saturating_add(1),
        "sent" => acc.sent = acc.sent.saturating_add(1),
        "rejected" => acc.rejected = acc.rejected.saturating_add(1),
        _ => {}
    }
}

fn push_recent(recent: &mut Vec<RecentOut>, kept: &Kept, policy: &Policy) {
    if recent.len() >= RECENT_MAX {
        return;
    }
    let Some(tool) = policy.tools.get(kept.index) else {
        return;
    };
    recent.push(RecentOut {
        tool: tool.clone(),
        class: kept.class.to_string(),
        severity: kept.severity.to_string(),
        priority: kept.priority.to_string(),
        rule: kept.rule.clone(),
        summary: kept.summary.clone(),
        state: kept.state.to_string(),
        at_ms: kept.at_ms,
    });
}

fn cards(tools: &[String], acc: &[Acc], now: i64, silence_seconds: u32) -> Vec<ToolOut> {
    let mut out = Vec::with_capacity(tools.len());
    for (tool, row) in tools.iter().zip(acc.iter()) {
        out.push(ToolOut {
            tool: tool.clone(),
            total: row.total,
            pending: row.pending,
            sent: row.sent,
            rejected: row.rejected,
            breach: row.breach,
            silent: is_silent(row.latest_ms, now, silence_seconds),
            latest_ms: row.latest_ms,
        });
    }
    out
}

fn is_silent(latest: Option<i64>, now: i64, silence_seconds: u32) -> bool {
    match latest {
        Some(ts) => ts < now.saturating_sub(i64::from(silence_seconds).saturating_mul(1_000)),
        None => true,
    }
}

fn series_out(tools: &[String], acc: &[Acc], starts: &[i64]) -> Vec<SeriesOut> {
    let mut out = Vec::with_capacity(tools.len());
    for (tool, row) in tools.iter().zip(acc.iter()) {
        let mut points = Vec::with_capacity(starts.len());
        for (start, count) in starts.iter().zip(row.buckets.iter()) {
            points.push(PointOut {
                bucket_start_ms: *start,
                count: *count,
            });
        }
        out.push(SeriesOut {
            tool: tool.clone(),
            points,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_policy;
    use crate::queue::StatusView;

    const NOW: i64 = 1_700_002_770_000;

    fn policy(tools: &str) -> Policy {
        parse_policy(&format!(
            "schema=darkdash.policy.v1\nissued_at_ms={NOW}\nexpires_at_ms={}\nrefresh_seconds=30\nwindow_hours=24\nsilence_seconds=90\nsite=Lab One\ntools={tools}\n",
            NOW + 3_600_000
        ))
        .unwrap()
    }

    fn status() -> StatusView {
        StatusView {
            read: "ok".to_string(),
            stale: false,
            host: Some("edge-1".to_string()),
            state: Some("running".to_string()),
            mode: Some("ship".to_string()),
            problem: None,
            pending: Some(1),
            accepted: None,
            dropped: None,
            rejected: None,
            retried: None,
            peer_unreadable: None,
            evicted: None,
            ack_errors: None,
            store_errors: None,
            last_frame_ms: None,
            updated_at_ms: Some(NOW),
            started_at_ms: None,
            status_interval_ms: None,
            heartbeat_ok: Some(true),
            heartbeat_at_ms: None,
            heartbeat_http_status: None,
            heartbeat_problem: None,
            heartbeat_last_ok_ms: None,
            darkapple: Some("available".to_string()),
        }
    }

    fn row(tool: &str, at: i64, payload: Option<&str>, len: i64, state: &str) -> RawRow {
        RawRow {
            tool: tool.to_string(),
            state: state.to_string(),
            payload: payload.map(str::to_string),
            created_at_ms: at,
            payload_len: len,
        }
    }

    fn good(tool: &str, at: i64, rule: &str, summary: &str) -> RawRow {
        let payload = format!(
            "{{\"tool\":\"{tool}\",\"class\":\"vuln\",\"severity\":\"high\",\"priority\":\"p2\",\"rule\":\"{rule}\",\"summary\":\"{summary}\"}}"
        );
        row(
            tool,
            at,
            Some(&payload),
            i64::try_from(payload.len()).unwrap(),
            "pending",
        )
    }

    fn render(rows: &[RawRow], tools: &str) -> serde_json::Value {
        let policy = policy(tools);
        let status = status();
        let input = FoldIn {
            rows,
            truncated: false,
            policy: &policy,
            now: NOW,
            queue_problem: None,
            status: &status,
            source: "server",
            settings_problem: None,
            glass: None,
            fleet: None,
        };
        let bytes = build(&input).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn future_hour_counts_without_a_future_bar() {
        let floor_now = floor_bucket(NOW, HOUR_MS);
        let next = floor_now.saturating_add(HOUR_MS);
        assert_eq!(floor_now, 1_699_999_200_000);
        assert_eq!(next, 1_700_002_800_000);
        let current = floor_now + 1000;
        let mut bad_summary = good("afterzero", current, "afterzero.reachable", "ok");
        if let Some(payload) = bad_summary.payload.as_mut() {
            payload.replace_range(payload.len() - 4..payload.len() - 2, "\u{0001}x");
        }
        let rows = vec![
            good("afterzero", next, "afterzero.reachable", "later"),
            good("afterzero", current, "afterzero.reachable", "now"),
            good("nocved", current, "nocved.watch", "sensor"),
            good("afterzero", current, "../x", "bad rule"),
            bad_summary,
            row("afterzero", current, None, 20_000, "pending"),
        ];
        let value = render(&rows, "afterzero,cveguard,nocved");
        let tools = value.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools[0].get("total").unwrap().as_u64().unwrap(), 2);
        assert_eq!(tools[1].get("tool").unwrap().as_str().unwrap(), "cveguard");
        assert_eq!(tools[1].get("total").unwrap().as_u64().unwrap(), 0);
        assert!(tools[1].get("silent").unwrap().as_bool().unwrap());
        assert!(!tools[0].get("silent").unwrap().as_bool().unwrap());
        assert_eq!(tools[2].get("total").unwrap().as_u64().unwrap(), 1);
        assert_eq!(value.get("skipped").unwrap().as_u64().unwrap(), 3);
        let series = value.get("series").unwrap().to_string();
        assert!(!series.contains(&format!("\"bucket_start_ms\":{next}")));
        assert_eq!(
            value.get("series").unwrap()[0]
                .get("points")
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            25
        );
        let recent = value.get("recent").unwrap().to_string();
        assert!(recent.contains(&format!("\"at_ms\":{next}")));
        let points = value.get("series").unwrap()[0]
            .get("points")
            .unwrap()
            .as_array()
            .unwrap();
        let hour = points
            .iter()
            .find(|point| point.get("bucket_start_ms").unwrap().as_i64().unwrap() == floor_now)
            .unwrap();
        assert_eq!(hour.get("count").unwrap().as_u64().unwrap(), 1);
    }

    #[test]
    fn recent_keeps_forty_and_totals_keep_all() {
        let floor_now = floor_bucket(NOW, HOUR_MS);
        let mut rows = Vec::new();
        for i in 0..41 {
            let at = floor_now + 50_000 - i64::from(i) * 1_000;
            rows.push(good("afterzero", at, "afterzero.reachable", "row"));
        }
        let value = render(&rows, "afterzero");
        assert_eq!(value.get("recent").unwrap().as_array().unwrap().len(), 40);
        assert_eq!(
            value.get("tools").unwrap()[0]
                .get("total")
                .unwrap()
                .as_u64()
                .unwrap(),
            41
        );
        assert_eq!(
            value.get("recent").unwrap()[0]
                .get("at_ms")
                .unwrap()
                .as_i64()
                .unwrap(),
            floor_now + 50_000
        );
    }

    #[test]
    fn failed_queue_omits_counts_and_rows() {
        let policy = policy("afterzero,nocved");
        let status = status();
        let rows = vec![good(
            "afterzero",
            NOW,
            "afterzero.reachable",
            "must-stay-hidden",
        )];
        let input = FoldIn {
            rows: &rows,
            truncated: true,
            policy: &policy,
            now: NOW,
            queue_problem: Some("queue_unreadable"),
            status: &status,
            source: "server",
            settings_problem: None,
            glass: None,
            fleet: None,
        };
        let bytes = build(&input).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("must-stay-hidden"));
        assert!(value.get("tools").unwrap().as_array().unwrap().is_empty());
        assert!(value.get("series").unwrap().as_array().unwrap().is_empty());
        assert!(value.get("recent").unwrap().as_array().unwrap().is_empty());
        assert_eq!(value.get("skipped").unwrap().as_u64().unwrap(), 0);
        assert!(!value.get("truncated").unwrap().as_bool().unwrap());
        assert_eq!(
            value.get("components").unwrap().get("queue").unwrap(),
            "dashed"
        );
        assert_eq!(
            value.get("components").unwrap().get("bus").unwrap(),
            "shown"
        );
    }

    #[test]
    fn unreadable_status_dashes_the_bus() {
        let mut status = status();
        status.read = "unreadable".to_string();
        status.stale = false;
        let policy = policy("afterzero");
        let rows = vec![good("afterzero", NOW, "afterzero.reachable", "kept")];
        let input = FoldIn {
            rows: &rows,
            truncated: false,
            policy: &policy,
            now: NOW,
            queue_problem: None,
            status: &status,
            source: "server",
            settings_problem: None,
            glass: None,
            fleet: None,
        };
        let bytes = build(&input).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            value.get("components").unwrap().get("bus").unwrap(),
            "dashed"
        );
        assert_eq!(
            value.get("components").unwrap().get("queue").unwrap(),
            "shown"
        );
        assert_eq!(
            value.get("tools").unwrap()[0]
                .get("total")
                .unwrap()
                .as_u64()
                .unwrap(),
            1
        );
    }
}
