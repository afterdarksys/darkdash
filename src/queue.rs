//! Read-only view of the local darksignal queue.
//!
//! Threats: `signals.db` is opened read-only with `SQLITE_OPEN_NOFOLLOW` and
//! `query_only`. A symlink, a mode other than 0600, or another uid is
//! unreadable. Ancestor symlinks, such as macOS `/var`, are resolved first so
//! that flag still applies to the database file. Join keys, dedupe values,
//! and evidence paths stay in the payload and are not copied into this view.
//! The check does not cover a SQLite sidecar opened later by path. That
//! window is recorded in SECURITY.md.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, store_err};
use crate::guard::{check_dir_0700, current_euid, read_private};

const STATUS_CAP: u64 = 64 * 1024;
const STALE_MS: u64 = 45_000;
const SQL: &str = "SELECT tool, state, \
CASE WHEN length(payload) > 16384 THEN NULL ELSE payload END, \
created_at_ms, length(payload) \
FROM signals \
WHERE created_at_ms >= ?1 AND created_at_ms <= ?2 \
ORDER BY created_at_ms DESC \
LIMIT 5001";

pub struct RawRow {
    pub tool: String,
    pub state: String,
    pub payload: Option<String>,
    pub created_at_ms: i64,
    pub payload_len: i64,
}

pub struct QueueLoad {
    pub rows: Vec<RawRow>,
    pub truncated: bool,
    pub queue_problem: Option<&'static str>,
    pub status: StatusView,
}

#[derive(Serialize)]
pub struct StatusView {
    pub read: String,
    pub stale: bool,
    pub host: Option<String>,
    pub state: Option<String>,
    pub mode: Option<String>,
    pub problem: Option<String>,
    pub pending: Option<i64>,
    pub accepted: Option<i64>,
    pub dropped: Option<i64>,
    pub rejected: Option<i64>,
    pub retried: Option<i64>,
    pub peer_unreadable: Option<i64>,
    pub evicted: Option<i64>,
    pub ack_errors: Option<i64>,
    pub store_errors: Option<i64>,
    pub last_frame_ms: Option<i64>,
    pub updated_at_ms: Option<i64>,
    pub started_at_ms: Option<i64>,
    pub status_interval_ms: Option<i64>,
    pub heartbeat_ok: Option<bool>,
    pub heartbeat_at_ms: Option<i64>,
    pub heartbeat_http_status: Option<i64>,
    pub heartbeat_problem: Option<String>,
    pub heartbeat_last_ok_ms: Option<i64>,
    pub darkapple: Option<String>,
}

enum DirKind {
    Missing,
    Bad,
    Ok,
}

pub fn load(state_dir: &Path, now: i64, start: i64, end: i64) -> QueueLoad {
    match classify_dir(state_dir) {
        DirKind::Missing => blank("queue_missing", "missing"),
        DirKind::Bad => blank("queue_unreadable", "unreadable"),
        DirKind::Ok => load_ok(state_dir, now, start, end),
    }
}

fn blank(queue_problem: &'static str, read: &'static str) -> QueueLoad {
    QueueLoad {
        rows: Vec::new(),
        truncated: false,
        queue_problem: Some(queue_problem),
        status: empty_status(read),
    }
}

fn load_ok(state_dir: &Path, now: i64, start: i64, end: i64) -> QueueLoad {
    let status = load_status(&state_dir.join("status.json"), now);
    match read_db(&state_dir.join("signals.db"), start, end) {
        Ok(read) => QueueLoad {
            rows: read.rows,
            truncated: read.truncated,
            queue_problem: None,
            status,
        },
        Err(code) => QueueLoad {
            rows: Vec::new(),
            truncated: false,
            queue_problem: Some(code),
            status,
        },
    }
}

fn classify_dir(path: &Path) -> DirKind {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => DirKind::Missing,
        Err(_) => DirKind::Bad,
        Ok(_) => match check_dir_0700(path) {
            Ok(()) => DirKind::Ok,
            Err(_) => DirKind::Bad,
        },
    }
}

struct DbRead {
    rows: Vec<RawRow>,
    truncated: bool,
}

fn read_db(path: &Path, start: i64, end: i64) -> Result<DbRead, &'static str> {
    let conn = open_db(path)?;
    let mut rows = query_rows(&conn, start, end)?;
    let truncated = rows.len() == 5001;
    if truncated {
        rows.pop();
    }
    Ok(DbRead { rows, truncated })
}

fn open_db(path: &Path) -> Result<Connection, &'static str> {
    let euid = current_euid().map_err(|_| "queue_unreadable")?;
    let meta = match fs::symlink_metadata(path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err("queue_missing"),
        Err(_) => return Err("queue_unreadable"),
        Ok(meta) => meta,
    };
    if !db_file_ok(&meta, euid) {
        return Err("queue_unreadable");
    }
    let open_at = path_for_open(path, &meta)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(&open_at, flags).map_err(as_unreadable)?;
    conn.execute_batch("PRAGMA busy_timeout = 200;")
        .map_err(as_unreadable)?;
    conn.execute_batch("PRAGMA query_only = ON;")
        .map_err(as_unreadable)?;
    Ok(conn)
}

fn db_file_ok(meta: &fs::Metadata, euid: u32) -> bool {
    meta.file_type().is_file()
        && !meta.file_type().is_symlink()
        && meta.uid() == euid
        && meta.mode() & 0o7777 == 0o600
}

/// Resolve ancestor symlinks only. The final component stays unresolved so
/// `SQLITE_OPEN_NOFOLLOW` still rejects a symlinked database file.
fn path_for_open(path: &Path, pre: &fs::Metadata) -> Result<PathBuf, &'static str> {
    let name = path.file_name().ok_or("queue_unreadable")?;
    let parent = path.parent().ok_or("queue_unreadable")?;
    if parent.as_os_str().is_empty() {
        return Err("queue_unreadable");
    }
    let parent_real = fs::canonicalize(parent).map_err(|_| "queue_unreadable")?;
    let open_at = parent_real.join(name);
    let again = fs::symlink_metadata(&open_at).map_err(|_| "queue_unreadable")?;
    if again.file_type().is_symlink() || again.dev() != pre.dev() || again.ino() != pre.ino() {
        return Err("queue_unreadable");
    }
    Ok(open_at)
}

fn query_rows(conn: &Connection, start: i64, end: i64) -> Result<Vec<RawRow>, &'static str> {
    let mut stmt = conn.prepare(SQL).map_err(as_unreadable)?;
    let mut rows = stmt
        .query(rusqlite::params![start, end])
        .map_err(as_unreadable)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(as_unreadable)? {
        out.push(map_row(row).map_err(as_unreadable)?);
    }
    Ok(out)
}

fn map_row(row: &rusqlite::Row<'_>) -> Result<RawRow, rusqlite::Error> {
    Ok(RawRow {
        tool: row.get(0)?,
        state: row.get(1)?,
        payload: row.get(2)?,
        created_at_ms: row.get(3)?,
        payload_len: row.get(4)?,
    })
}

fn as_unreadable(err: rusqlite::Error) -> &'static str {
    let _code = match &err {
        rusqlite::Error::SqliteFailure(sqlite, _) => sqlite.extended_code,
        _ => 0,
    };
    match store_err() {
        Error::Io(_) | Error::Usage | Error::Config(_) | Error::Closed(_) => "queue_unreadable",
    }
}

fn load_status(path: &Path, now: i64) -> StatusView {
    match read_private(path, STATUS_CAP) {
        Ok(bytes) => parse_status(&bytes, now),
        Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            empty_status("missing")
        }
        Err(_) => empty_status("unreadable"),
    }
}

pub(crate) fn parse_status(bytes: &[u8], now: i64) -> StatusView {
    if bytes.len() > usize::try_from(STATUS_CAP).unwrap_or(usize::MAX) {
        return empty_status("unreadable");
    }
    let value: Value = match serde_json::from_slice(bytes) {
        Ok(value) => value,
        Err(_) => return empty_status("unreadable"),
    };
    let Some(obj) = value.as_object() else {
        return empty_status("unreadable");
    };
    let Some(required) = required_status(obj) else {
        return empty_status("unreadable");
    };
    finish_status(obj, required, now)
}

struct RequiredStatus {
    host: String,
    state: String,
    mode: String,
    updated_at_ms: i64,
}

fn required_status(obj: &serde_json::Map<String, Value>) -> Option<RequiredStatus> {
    if obj.get("kind").and_then(Value::as_str) != Some("darksignal.status") {
        return None;
    }
    let host = obj.get("host").and_then(Value::as_str)?;
    let state = obj.get("state").and_then(Value::as_str)?;
    let mode = obj.get("mode").and_then(Value::as_str)?;
    let updated_at_ms = obj.get("updated_at_ms").and_then(Value::as_i64)?;
    if !host_ok(host) || !slug_ok(state) || !slug_ok(mode) {
        return None;
    }
    Some(RequiredStatus {
        host: host.to_string(),
        state: state.to_string(),
        mode: mode.to_string(),
        updated_at_ms,
    })
}

fn finish_status(
    obj: &serde_json::Map<String, Value>,
    required: RequiredStatus,
    now: i64,
) -> StatusView {
    let stale = i64::abs_diff(now, required.updated_at_ms) > STALE_MS;
    let read = if stale { "stale" } else { "ok" };
    let beat = obj.get("heartbeat");
    StatusView {
        read: read.to_string(),
        stale,
        host: Some(required.host),
        state: Some(required.state),
        mode: Some(required.mode),
        problem: problem_field(obj.get("problem")),
        pending: json_i64(obj.get("pending")),
        accepted: json_i64(obj.get("accepted")),
        dropped: json_i64(obj.get("dropped")),
        rejected: json_i64(obj.get("rejected")),
        retried: json_i64(obj.get("retried")),
        peer_unreadable: json_i64(obj.get("peer_unreadable")),
        evicted: json_i64(obj.get("evicted")),
        ack_errors: json_i64(obj.get("ack_errors")),
        store_errors: json_i64(obj.get("store_errors")),
        last_frame_ms: json_i64(obj.get("last_frame_ms")),
        updated_at_ms: Some(required.updated_at_ms),
        started_at_ms: json_i64(obj.get("started_at_ms")),
        status_interval_ms: json_i64(obj.get("status_interval_ms")),
        heartbeat_ok: beat
            .and_then(Value::as_object)
            .and_then(|o| json_bool(o.get("ok"))),
        heartbeat_at_ms: beat
            .and_then(Value::as_object)
            .and_then(|o| json_i64(o.get("at_ms"))),
        heartbeat_http_status: beat
            .and_then(Value::as_object)
            .and_then(|o| json_i64(o.get("http_status"))),
        heartbeat_problem: beat
            .and_then(Value::as_object)
            .and_then(|o| problem_field(o.get("problem"))),
        heartbeat_last_ok_ms: beat
            .and_then(Value::as_object)
            .and_then(|o| json_i64(o.get("last_ok_ms"))),
        darkapple: darkapple_status(obj),
    }
}

fn empty_status(read: &str) -> StatusView {
    StatusView {
        read: read.to_string(),
        stale: false,
        host: None,
        state: None,
        mode: None,
        problem: None,
        pending: None,
        accepted: None,
        dropped: None,
        rejected: None,
        retried: None,
        peer_unreadable: None,
        evicted: None,
        ack_errors: None,
        store_errors: None,
        last_frame_ms: None,
        updated_at_ms: None,
        started_at_ms: None,
        status_interval_ms: None,
        heartbeat_ok: None,
        heartbeat_at_ms: None,
        heartbeat_http_status: None,
        heartbeat_problem: None,
        heartbeat_last_ok_ms: None,
        darkapple: None,
    }
}

fn json_i64(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64)
}

fn json_bool(value: Option<&Value>) -> Option<bool> {
    value.and_then(Value::as_bool)
}

fn problem_field(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    if problem_ok(text) {
        Some(text.to_string())
    } else {
        Some("unknown".to_string())
    }
}

fn darkapple_status(obj: &serde_json::Map<String, Value>) -> Option<String> {
    let status = obj
        .get("producers")?
        .as_object()?
        .get("darkapple")?
        .as_object()?
        .get("status")?
        .as_str()?;
    match status {
        "unseen" | "available" | "degraded" | "silent" => Some(status.to_string()),
        _ => None,
    }
}

fn host_ok(host: &str) -> bool {
    let n = host.len();
    (1..=253).contains(&n)
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

fn slug_ok(value: &str) -> bool {
    let n = value.len();
    (1..=32).contains(&n)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

fn problem_ok(value: &str) -> bool {
    let n = value.len();
    (1..=32).contains(&n)
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::write_private_new;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(now: i64) -> String {
        format!(
            "{{\"kind\":\"darksignal.status\",\"host\":\"edge-1\",\"state\":\"running\",\"mode\":\"ship\",\"updated_at_ms\":{now},\"pending\":1,\"dropped\":null,\"heartbeat\":{{\"ok\":true}},\"producers\":{{\"darkapple\":{{\"status\":\"available\"}}}}}}"
        )
    }

    #[test]
    fn parse_status_keeps_null_counters() {
        let now = 1_700_000_000_000_i64;
        let view = parse_status(fixture(now).as_bytes(), now);
        let text = serde_json::to_string(&view).unwrap();
        assert!(text.contains("\"dropped\":null"));
        assert!(text.contains("\"heartbeat_ok\":true"));
        assert!(text.contains("\"stale\":false"));
        assert!(text.contains("\"read\":\"ok\""));
        assert!(text.contains("\"darkapple\":\"available\""));
        let bad = br#"{"kind":"other","host":"edge-1","state":"running","mode":"ship","updated_at_ms":1}"#;
        assert_eq!(parse_status(bad, now).read, "unreadable");
    }

    #[test]
    fn missing_database_keeps_a_good_status() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let now = 1_700_000_000_000_i64;
        write_private_new(&state.join("status.json"), fixture(now).as_bytes()).unwrap();
        let loaded = load(&state, now, now - 1000, now);
        assert_eq!(loaded.queue_problem, Some("queue_missing"));
        assert!(loaded.rows.is_empty());
        let text = serde_json::to_string(&loaded.status).unwrap();
        assert!(text.contains("\"read\":\"ok\""));
        assert!(text.contains("\"host\":\"edge-1\""));
        assert!(text.contains("\"dropped\":null"));
    }

    #[test]
    fn symlinked_database_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let real = state.join("real.db");
        fs::write(&real, b"not-a-database").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&real, state.join("signals.db")).unwrap();
        let now = 1_700_000_000_000_i64;
        let loaded = load(&state, now, now - 1000, now);
        assert_eq!(loaded.queue_problem, Some("queue_unreadable"));
        assert!(loaded.rows.is_empty());
    }

    #[test]
    fn ancestor_symlink_still_reads_the_database_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let db = state.join("signals.db");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
        conn.execute_batch(
            "CREATE TABLE signals (
                id TEXT PRIMARY KEY, dedupe TEXT NOT NULL, tool TEXT NOT NULL,
                state TEXT NOT NULL, created_at_ms INTEGER NOT NULL, payload TEXT NOT NULL);",
        )
        .unwrap();
        let now = 1_700_000_000_000_i64;
        let payload = "{\"tool\":\"afterzero\",\"summary\":\"pack conditions met\"}";
        conn.execute(
            "INSERT INTO signals (id, dedupe, tool, state, created_at_ms, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["row-1", "dedupe-row", "afterzero", "pending", now, payload],
        )
        .unwrap();
        drop(conn);
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
        let loaded = load(&state, now, now - 1000, now);
        assert_eq!(loaded.queue_problem, None);
        assert_eq!(loaded.rows.len(), 1);
        assert_eq!(loaded.rows[0].tool, "afterzero");
        let text = loaded.rows[0].payload.as_deref().unwrap_or("");
        assert!(text.contains("pack conditions met"));
    }
}
