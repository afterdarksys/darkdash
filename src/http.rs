//! Loopback HTTP console.
//!
//! Threats: the listener accepts only 127.0.0.1. The operator token and
//! session ids are compared in constant time. Eight failures lock the
//! listener for 60 seconds. A closed policy returns 503 and does not read
//! the queue. The page never receives join, dedupe, or evidence fields.
//! The optional fleet panel reads darkapi only after the policy resolves,
//! with GETs only (see `fleet`).
//!
//! The accept loop is single-threaded. One stalled client can block the next
//! connection for the five-second read timeout.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::audit::{self, AuditLine, decode_hex32, fingerprint_of_hex};
use crate::auth::{
    AuthState, Clock, SESSION_MS, Sessions, load_token, new_session_id, system_now, tokens_match,
};
use crate::error::Error;
use crate::fetch::{FetchCtx, HttpsSource, PolicyCache, SettingsSource, known, resolve};
use crate::fleet::{self, FleetCache, FleetSource, HttpsFleet};
use crate::guard::clean_abs;
use crate::pin::{LOOPBACK, Pin, load_pin};
use crate::queue;
use crate::snapshot::{self, FoldIn, window_bounds};

const PAGE: &str = include_str!("page.html");
const HEADER_CAP: usize = 8192;
const HEADER_LINES: usize = 33;
const SESSION_CAP: u64 = 256;
const MAX_AGE_SECS: i64 = SESSION_MS / 1000;
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";
const CLEAR_COOKIE: &str = "darkdash_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0";

struct Runtime {
    cache: PolicyCache,
    audited: Mutex<std::collections::HashSet<String>>,
    auth: Mutex<AuthState>,
    sessions: Mutex<Sessions>,
    fleet: FleetCache,
}

struct Ctx<'a> {
    pin: &'a Pin,
    port: u16,
    clock: &'a Clock,
    source: &'a dyn SettingsSource,
    fleet: &'a dyn FleetSource,
    runtime: &'a Runtime,
}

struct Request {
    method: String,
    path: String,
    origin: Option<String>,
    cookie: Option<String>,
    body: Vec<u8>,
}

impl Drop for Request {
    fn drop(&mut self) {
        self.body.zeroize();
        if let Some(cookie) = self.cookie.as_mut() {
            cookie.zeroize();
        }
    }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
    set_cookie: Option<String>,
}

impl Drop for Reply {
    fn drop(&mut self) {
        self.body.zeroize();
        if let Some(cookie) = self.set_cookie.as_mut() {
            cookie.zeroize();
        }
    }
}

struct HeaderBuf {
    bytes: Vec<u8>,
}

impl Drop for HeaderBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct SecretBuf {
    bytes: Vec<u8>,
}

impl SecretBuf {
    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

struct Wipe(String);

impl Drop for Wipe {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct HeaderSlots {
    method: String,
    path: String,
    host: Option<String>,
    origin: Option<String>,
    cookie: Option<String>,
    content_length: Option<u64>,
    saw_type: bool,
}

impl Drop for HeaderSlots {
    fn drop(&mut self) {
        if let Some(cookie) = self.cookie.as_mut() {
            cookie.zeroize();
        }
    }
}

#[derive(Clone, Copy)]
enum Fail {
    Bad,
    TooLarge,
}

pub(crate) fn serve(pin_path: &std::path::Path) -> Result<(), Error> {
    let text = pin_path.to_str().ok_or(Error::Config("path"))?;
    let abs = clean_abs(text)?;
    let pin = load_pin(&abs)?;
    let listener = TcpListener::bind((LOOPBACK, pin.port))?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?.port();
    eprintln!("darkdash: listening {LOOPBACK}:{bound}");
    let source: Arc<dyn SettingsSource> = Arc::new(HttpsSource);
    let fleet: Arc<dyn FleetSource> = Arc::new(HttpsFleet);
    let clock: Clock = Arc::new(system_now as fn() -> Result<i64, ()>);
    let stop = AtomicBool::new(false);
    serve_listener(&listener, &pin, &clock, &source, &fleet, &stop)
}

pub(crate) fn serve_listener(
    listener: &TcpListener,
    pin: &Pin,
    clock: &Clock,
    source: &Arc<dyn SettingsSource>,
    fleet: &Arc<dyn FleetSource>,
    stop: &AtomicBool,
) -> Result<(), Error> {
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let runtime = Runtime {
        cache: PolicyCache::new(),
        audited: Mutex::new(std::collections::HashSet::new()),
        auth: Mutex::new(AuthState::new()),
        sessions: Mutex::new(Sessions::new()),
        fleet: FleetCache::new(),
    };
    let ctx = Ctx {
        pin,
        port,
        clock,
        source: source.as_ref(),
        fleet: fleet.as_ref(),
        runtime: &runtime,
    };
    accept_loop(listener, &ctx, stop)
}

fn accept_loop(listener: &TcpListener, ctx: &Ctx<'_>, stop: &AtomicBool) -> Result<(), Error> {
    loop {
        if stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, peer)) => accept_one(&stream, peer, ctx),
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
                if stop.load(Ordering::SeqCst) {
                    return Ok(());
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err.into()),
        }
    }
}

fn accept_one(stream: &TcpStream, peer: SocketAddr, ctx: &Ctx<'_>) {
    if !peer_ok(peer) || prepare_stream(stream).is_err() {
        return;
    }
    let reply = match read_request(stream, &ctx.pin.host_header(ctx.port)) {
        Ok(request) => dispatch(ctx, &request),
        Err(fail) => fail_reply(fail),
    };
    if let Ok(()) = write_reply(stream, &reply) {}
}

fn peer_ok(peer: SocketAddr) -> bool {
    match peer {
        SocketAddr::V4(addr) => addr.ip().octets() == [127, 0, 0, 1],
        SocketAddr::V6(_) => false,
    }
}

fn prepare_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(())
}

fn read_request(stream: &TcpStream, expected_host: &str) -> Result<Request, Fail> {
    let (headers, mut prefix) = read_headers(stream)?;
    let mut slots = parse_headers(&headers)?;
    drop(headers);
    if slots.host.as_deref() != Some(expected_host) {
        return Err(Fail::Bad);
    }
    let len = plan_body(
        &slots.method,
        &slots.path,
        prefix.len(),
        slots.content_length,
    )?;
    let body = take_body(stream, &mut prefix, len)?;
    Ok(into_request(&mut slots, body))
}

fn read_headers(stream: &TcpStream) -> Result<(HeaderBuf, SecretBuf), Fail> {
    let mut buf = HeaderBuf { bytes: Vec::new() };
    loop {
        if let Some(end) = header_end(&buf.bytes) {
            if end > HEADER_CAP {
                return Err(Fail::Bad);
            }
            let rest = buf.bytes.split_off(end);
            return Ok((buf, SecretBuf { bytes: rest }));
        }
        if buf.bytes.len() > HEADER_CAP {
            return Err(Fail::Bad);
        }
        if !push_chunk(stream, &mut buf.bytes)? {
            return Err(Fail::Bad);
        }
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|win| win == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn push_chunk(mut stream: &TcpStream, buf: &mut Vec<u8>) -> Result<bool, Fail> {
    let mut tmp = [0u8; 1024];
    let read = match stream.read(&mut tmp) {
        Ok(0) => {
            tmp.zeroize();
            return Ok(false);
        }
        Ok(n) => n,
        Err(err) if err.kind() == ErrorKind::Interrupted => {
            tmp.zeroize();
            return Ok(true);
        }
        Err(_) => {
            tmp.zeroize();
            return Err(Fail::Bad);
        }
    };
    buf.extend_from_slice(&tmp[..read]);
    tmp.zeroize();
    Ok(true)
}

fn parse_headers(buf: &HeaderBuf) -> Result<HeaderSlots, Fail> {
    if buf.bytes.contains(&0) {
        return Err(Fail::Bad);
    }
    let text = std::str::from_utf8(&buf.bytes).map_err(|_| Fail::Bad)?;
    let lines = header_lines(text)?;
    let (method, path) = split_request(lines[0])?;
    let mut slots = HeaderSlots {
        method,
        path,
        host: None,
        origin: None,
        cookie: None,
        content_length: None,
        saw_type: false,
    };
    for line in &lines[1..] {
        apply_line(&mut slots, line)?;
    }
    Ok(slots)
}

fn header_lines(text: &str) -> Result<Vec<&str>, Fail> {
    let mut lines: Vec<&str> = text.split("\r\n").collect();
    while lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    if lines.is_empty() || lines.len() > HEADER_LINES {
        return Err(Fail::Bad);
    }
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            return Err(Fail::Bad);
        }
        if index > 0 && !line.contains(':') {
            return Err(Fail::Bad);
        }
    }
    Ok(lines)
}

fn split_request(line: &str) -> Result<(String, String), Fail> {
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(Fail::Bad)?;
    let path = parts.next().ok_or(Fail::Bad)?;
    let version = parts.next().ok_or(Fail::Bad)?;
    if parts.next().is_some() || version != "HTTP/1.1" || !method_ok(method) || !path_ok(path) {
        return Err(Fail::Bad);
    }
    Ok((method.to_string(), path.to_string()))
}

fn method_ok(method: &str) -> bool {
    let n = method.len();
    (1..=16).contains(&n) && method.bytes().all(|b| b.is_ascii_uppercase())
}

fn path_ok(path: &str) -> bool {
    let bytes = path.as_bytes();
    !bytes.is_empty()
        && bytes[0] == b'/'
        && bytes
            .iter()
            .all(|b| *b > 0x20 && *b != 0x7f && *b != b'?' && *b != b'#' && *b != b'\\')
}

fn apply_line(slots: &mut HeaderSlots, line: &str) -> Result<(), Fail> {
    let Some((name, value)) = line.split_once(':') else {
        return Err(Fail::Bad);
    };
    if !name_ok(name) {
        return Err(Fail::Bad);
    }
    store_header(slots, &name.to_ascii_lowercase(), trim_ws(value))
}

fn name_ok(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn trim_ws(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

fn store_header(slots: &mut HeaderSlots, name: &str, value: &str) -> Result<(), Fail> {
    if name == "transfer-encoding" {
        return Err(Fail::Bad);
    }
    match name {
        "host" => fill_slot(&mut slots.host, value),
        "origin" => fill_slot(&mut slots.origin, value),
        "cookie" => fill_slot(&mut slots.cookie, value),
        "content-type" => {
            if slots.saw_type {
                return Err(Fail::Bad);
            }
            slots.saw_type = true;
            Ok(())
        }
        "content-length" => store_length(slots, value),
        _ => Ok(()),
    }
}

fn fill_slot(slot: &mut Option<String>, value: &str) -> Result<(), Fail> {
    if slot.is_some() {
        return Err(Fail::Bad);
    }
    *slot = Some(value.to_string());
    Ok(())
}

fn store_length(slots: &mut HeaderSlots, value: &str) -> Result<(), Fail> {
    if slots.content_length.is_some() {
        return Err(Fail::Bad);
    }
    slots.content_length = Some(parse_length(value)?);
    Ok(())
}

fn parse_length(raw: &str) -> Result<u64, Fail> {
    if raw.is_empty() || raw.len() > 7 || (raw.len() > 1 && raw.starts_with('0')) {
        return Err(Fail::Bad);
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Fail::Bad);
    }
    raw.parse::<u64>().map_err(|_| Fail::Bad)
}

fn plan_body(method: &str, path: &str, prefix: usize, declared: Option<u64>) -> Result<u64, Fail> {
    let len = declared_len(method, prefix, declared)?;
    if rejected_body(method, path, len) {
        return Err(Fail::Bad);
    }
    if len > body_cap(method, path) {
        return Err(Fail::TooLarge);
    }
    Ok(len)
}

fn declared_len(method: &str, prefix: usize, declared: Option<u64>) -> Result<u64, Fail> {
    let prefix = u64::try_from(prefix).map_err(|_| Fail::Bad)?;
    match declared {
        Some(len) if prefix > len => Err(Fail::Bad),
        None if prefix > 0 || method == "POST" => Err(Fail::Bad),
        None => Ok(0),
        Some(len) => Ok(len),
    }
}

fn rejected_body(method: &str, path: &str, len: u64) -> bool {
    len > 0 && (method == "GET" || !routed(method, path) || path == "/logout")
}

fn body_cap(method: &str, path: &str) -> u64 {
    if method == "POST" && path == "/session" {
        SESSION_CAP
    } else {
        0
    }
}

fn routed(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("GET", "/")
            | ("GET", "/healthz")
            | ("GET", "/api/snapshot")
            | ("POST", "/session")
            | ("POST", "/logout")
    )
}

fn take_body(stream: &TcpStream, prefix: &mut SecretBuf, len: u64) -> Result<Vec<u8>, Fail> {
    let need = usize::try_from(len).map_err(|_| Fail::Bad)?;
    let mut got = prefix.take();
    if got.len() > need {
        got.zeroize();
        return Err(Fail::Bad);
    }
    if got.len() == need {
        return Ok(got);
    }
    read_rest(stream, got, need)
}

fn read_rest(mut stream: &TcpStream, mut got: Vec<u8>, need: usize) -> Result<Vec<u8>, Fail> {
    let mut extra = vec![0u8; need - got.len()];
    let result = stream.read_exact(&mut extra);
    if result.is_ok() {
        got.extend_from_slice(&extra);
    }
    extra.zeroize();
    if result.is_err() {
        got.zeroize();
        return Err(Fail::Bad);
    }
    Ok(got)
}

fn into_request(slots: &mut HeaderSlots, body: Vec<u8>) -> Request {
    Request {
        method: std::mem::take(&mut slots.method),
        path: std::mem::take(&mut slots.path),
        origin: slots.origin.take(),
        cookie: slots.cookie.take(),
        body,
    }
}

fn dispatch(ctx: &Ctx<'_>, req: &Request) -> Reply {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => html_reply(),
        ("GET", "/healthz") => json_reply(200, b"{\"ok\":true}"),
        ("POST", "/session") => login(ctx, req),
        ("POST", "/logout") => logout(ctx, req),
        ("GET", "/api/snapshot") => snapshot(ctx, req),
        _ => json_reply(404, b"{\"error\":\"not_found\"}"),
    }
}

fn login(ctx: &Ctx<'_>, req: &Request) -> Reply {
    if !origin_ok(&req.origin, &ctx.pin.origin(ctx.port)) {
        return json_reply(403, b"{\"error\":\"unauthorized\"}");
    }
    let token = match load_token(&ctx.pin.token_file) {
        Ok(text) => Wipe(text),
        Err(_) => return closed_reply("token"),
    };
    let now = match (ctx.clock)() {
        Ok(now) if now >= 0 => now,
        _ => return closed_reply("clock"),
    };
    if !auth_allowed(ctx, now) {
        return json_reply(401, b"{\"error\":\"locked\"}");
    }
    let presented = presented_token(&req.body);
    if !tokens_match(&presented.0, &token.0) {
        drop(presented);
        drop(token);
        return login_failed(ctx, now);
    }
    let fp = match fingerprint_of_hex(&token.0) {
        Ok(fp) => Wipe(fp),
        Err(_) => return closed_reply("closed"),
    };
    drop(presented);
    drop(token);
    if !audit_login_ok(ctx, now, &fp.0) {
        return closed_reply("closed");
    }
    issue_session(ctx, now)
}

fn origin_ok(origin: &Option<String>, expected: &str) -> bool {
    match origin {
        None => true,
        Some(value) => value == expected,
    }
}

fn presented_token(body: &[u8]) -> Wipe {
    let text = match std::str::from_utf8(body) {
        Ok(raw) => raw
            .trim_matches(|ch: char| matches!(ch, ' ' | '\t' | '\r' | '\n'))
            .to_string(),
        Err(_) => String::new(),
    };
    Wipe(text)
}

fn auth_allowed(ctx: &Ctx<'_>, now: i64) -> bool {
    lock_auth(ctx).allowed(now)
}

fn auth_fail(ctx: &Ctx<'_>, now: i64) {
    lock_auth(ctx).fail(now);
}

fn auth_succeed(ctx: &Ctx<'_>) {
    lock_auth(ctx).succeed();
}

fn lock_auth<'a>(ctx: &'a Ctx<'_>) -> std::sync::MutexGuard<'a, AuthState> {
    ctx.runtime
        .auth
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn lock_sessions<'a>(ctx: &'a Ctx<'_>) -> std::sync::MutexGuard<'a, Sessions> {
    ctx.runtime
        .sessions
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn login_failed(ctx: &Ctx<'_>, now: i64) -> Reply {
    let line = AuditLine {
        at_ms: now,
        event: "login_fail",
        token_fp: None,
        actor: None,
        reason: None,
        expires_at_ms: None,
        problem: None,
    };
    if audit::write(&ctx.pin.audit_file, &line).is_err() {
        eprintln!("darkdash: audit");
    }
    auth_fail(ctx, now);
    json_reply(401, b"{\"error\":\"unauthorized\"}")
}

fn audit_login_ok(ctx: &Ctx<'_>, now: i64, fp: &str) -> bool {
    let line = AuditLine {
        at_ms: now,
        event: "login_ok",
        token_fp: Some(fp),
        actor: None,
        reason: None,
        expires_at_ms: None,
        problem: None,
    };
    audit::write(&ctx.pin.audit_file, &line).is_ok()
}

fn issue_session(ctx: &Ctx<'_>, now: i64) -> Reply {
    let mut id = match new_session_id() {
        Ok(id) => id,
        Err(_) => return closed_reply("closed"),
    };
    let mut encoded = hex::encode(id);
    let cookie = format!(
        "darkdash_session={encoded}; HttpOnly; SameSite=Strict; Path=/; Max-Age={MAX_AGE_SECS}"
    );
    encoded.zeroize();
    lock_sessions(ctx).insert(id, now.saturating_add(SESSION_MS));
    id.zeroize();
    auth_succeed(ctx);
    let mut reply = json_reply(200, b"{\"ok\":true}");
    reply.set_cookie = Some(cookie);
    reply
}

fn logout(ctx: &Ctx<'_>, req: &Request) -> Reply {
    let cookie = match session_cookie(&req.cookie) {
        Ok(value) => value,
        Err(fail) => return fail_reply(fail),
    };
    if let Some(value) = cookie.as_deref() {
        revoke_cookie(ctx, value);
    }
    Reply {
        status: 204,
        body: Vec::new(),
        content_type: "application/json",
        set_cookie: Some(CLEAR_COOKIE.to_string()),
    }
}

fn revoke_cookie(ctx: &Ctx<'_>, value: &str) {
    let mut id = [0u8; 32];
    if decode_hex32(value, &mut id) {
        lock_sessions(ctx).revoke(&id);
    }
    id.zeroize();
}

fn snapshot(ctx: &Ctx<'_>, req: &Request) -> Reply {
    let cookie = match session_cookie(&req.cookie) {
        Ok(value) => value,
        Err(fail) => return fail_reply(fail),
    };
    let Some(cookie) = cookie else {
        return json_reply(401, b"{\"error\":\"unauthorized\"}");
    };
    let token = match load_token(&ctx.pin.token_file) {
        Ok(text) => Wipe(text),
        Err(_) => return closed_reply("token"),
    };
    let now = match (ctx.clock)() {
        Ok(now) if now >= 0 => now,
        _ => return closed_reply("clock"),
    };
    if !accept_cookie(ctx, &cookie, &token.0, now) {
        return json_reply(401, b"{\"error\":\"unauthorized\"}");
    }
    drop(token);
    render_snapshot(ctx, now)
}

fn session_cookie(header: &Option<String>) -> Result<Option<String>, Fail> {
    let Some(raw) = header else {
        return Ok(None);
    };
    let mut found: Option<String> = None;
    for part in raw.split(';') {
        let Some((name, value)) = trim_ws(part).split_once('=') else {
            continue;
        };
        if !name.eq_ignore_ascii_case("darkdash_session") {
            continue;
        }
        if found.is_some() {
            if let Some(prev) = found.as_mut() {
                prev.zeroize();
            }
            return Err(Fail::Bad);
        }
        found = Some(value.to_string());
    }
    Ok(found)
}

fn accept_cookie(ctx: &Ctx<'_>, cookie: &str, token: &str, now: i64) -> bool {
    let mut presented = [0u8; 32];
    let mut token_raw = [0u8; 32];
    let decoded = decode_hex32(cookie, &mut presented);
    let token_decoded = decode_hex32(token, &mut token_raw);
    let same = presented.ct_eq(&token_raw);
    let as_token = tokens_match(cookie, token);
    let session_ok = lock_sessions(ctx).matches(&presented, now);
    let ok = Choice::from(u8::from(decoded))
        & Choice::from(u8::from(token_decoded))
        & Choice::from(u8::from(session_ok))
        & !same
        & Choice::from(u8::from(!as_token));
    presented.zeroize();
    token_raw.zeroize();
    bool::from(ok)
}

fn render_snapshot(ctx: &Ctx<'_>, now: i64) -> Reply {
    let fetch = FetchCtx {
        pin: ctx.pin,
        source: ctx.source,
        cache: &ctx.runtime.cache,
        audited: &ctx.runtime.audited,
        audit_path: &ctx.pin.audit_file,
    };
    let active = match resolve(&fetch, now) {
        Ok(active) => active,
        Err(code) => return closed_reply(code),
    };
    let (start, end) = window_bounds(now, active.policy.window_hours);
    let loaded = queue::load(&ctx.pin.state_dir, now, start, end);
    let fleet = ctx
        .pin
        .fleet
        .as_ref()
        .map(|pinned| fleet::current(ctx.fleet, pinned, &ctx.runtime.fleet, now));
    let input = FoldIn {
        rows: &loaded.rows,
        truncated: loaded.truncated,
        policy: &active.policy,
        now,
        queue_problem: loaded.queue_problem,
        status: &loaded.status,
        source: active.source,
        settings_problem: active.settings_problem,
        glass: active.glass.as_ref(),
        fleet: fleet.as_ref(),
    };
    match snapshot::build(&input) {
        Ok(body) => Reply {
            status: 200,
            body,
            content_type: "application/json",
            set_cookie: None,
        },
        Err(()) => closed_reply("closed"),
    }
}

fn html_reply() -> Reply {
    Reply {
        status: 200,
        body: PAGE.as_bytes().to_vec(),
        content_type: "text/html; charset=utf-8",
        set_cookie: None,
    }
}

fn json_reply(status: u16, body: &[u8]) -> Reply {
    Reply {
        status,
        body: body.to_vec(),
        content_type: "application/json",
        set_cookie: None,
    }
}

fn closed_reply(problem: &str) -> Reply {
    let code = known(problem);
    let text = format!("{{\"closed\":true,\"problem\":\"{code}\"}}");
    json_reply(503, text.as_bytes())
}

fn fail_reply(fail: Fail) -> Reply {
    match fail {
        Fail::Bad => json_reply(400, b"{\"error\":\"bad_request\"}"),
        Fail::TooLarge => json_reply(413, b"{\"error\":\"too_large\"}"),
    }
}

fn phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Content Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn encode_reply(reply: &Reply) -> Vec<u8> {
    let status = reply.status;
    let phrase = phrase(status);
    let ctype = reply.content_type;
    let len = reply.body.len();
    let mut cookie_line = match &reply.set_cookie {
        Some(value) => format!("Set-Cookie: {value}\r\n"),
        None => String::new(),
    };
    let head = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: {ctype}\r\nContent-Length: {len}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {CSP}\r\n{cookie_line}\r\n"
    );
    cookie_line.zeroize();
    let mut out = head.into_bytes();
    out.extend_from_slice(&reply.body);
    out
}

fn write_reply(mut stream: &TcpStream, reply: &Reply) -> std::io::Result<()> {
    let mut encoded = encode_reply(reply);
    let result = stream.write_all(&encoded).and_then(|()| stream.flush());
    encoded.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::write_token;
    use crate::fetch::ScriptedSource;
    use crate::fleet::{ScriptedFleet, fixtures};
    use crate::guard::write_private_new;
    use crate::pin::parse_pin;
    use crate::policy::{parse_policy, public_from_secret, sign_break_glass};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::atomic::AtomicI64;

    const NOW: i64 = 1_700_000_000_000;

    struct Lab {
        _root: tempfile::TempDir,
        pin: Pin,
        source: Arc<ScriptedSource>,
        fleet: Arc<ScriptedFleet>,
        clock: Arc<AtomicI64>,
        token: String,
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            self.token.zeroize();
        }
    }

    struct StopGuard<'a> {
        stop: &'a AtomicBool,
    }

    impl Drop for StopGuard<'_> {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    fn secret(byte: u8) -> [u8; 32] {
        let mut raw = [byte; 32];
        raw[0] = byte.wrapping_add(3);
        raw
    }

    fn policy_text(now: i64) -> String {
        format!(
            "schema=darkdash.policy.v1\nissued_at_ms={now}\nexpires_at_ms={expires}\nrefresh_seconds=30\nwindow_hours=24\nsilence_seconds=90\nsite=Lab One\ntools=afterzero,nocved\n",
            expires = now + 3_600_000
        )
    }

    fn pin_for(dir: &Path, server: &[u8; 32], glass: &[u8; 32], fleet: bool) -> Pin {
        let server_hex = hex::encode(public_from_secret(server).unwrap());
        let glass_hex = hex::encode(public_from_secret(glass).unwrap());
        let fleet_fields = if fleet {
            format!(
                ",\"fleet_url\":\"https://api.darkapi.example\",\"fleet_key_file\":\"{}\"",
                dir.join("fleet.key").display()
            )
        } else {
            String::new()
        };
        let text = format!(
            "{{\"schema\":\"darkdash.pin.v1\",\"settings_url\":\"https://darkapi.example/v1/darkdash/settings\",\"server_pubkey\":\"{server_hex}\",\"break_glass_pubkey\":\"{glass_hex}\",\"break_glass_file\":\"{}\",\"state_dir\":\"{}\",\"token_file\":\"{}\",\"audit_file\":\"{}\",\"bind\":\"127.0.0.1:9\"{fleet_fields}}}",
            dir.join("glass").display(),
            dir.join("state").display(),
            dir.join("token").display(),
            dir.join("audit").display()
        );
        parse_pin(&text).unwrap()
    }

    fn status_json(now: i64) -> String {
        format!(
            "{{\"kind\":\"darksignal.status\",\"host\":\"edge-1\",\"state\":\"running\",\"mode\":\"ship\",\"updated_at_ms\":{now},\"pending\":1,\"dropped\":null,\"heartbeat\":{{\"ok\":true}},\"producers\":{{\"darkapple\":{{\"status\":\"available\"}}}}}}"
        )
    }

    fn plant_db(path: &Path, now: i64, summary: &str) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
        conn.execute_batch(
            "CREATE TABLE signals (
                id TEXT PRIMARY KEY, dedupe TEXT NOT NULL UNIQUE, tool TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending', 'sent', 'rejected')),
                created_at_ms INTEGER NOT NULL, payload TEXT NOT NULL,
                class_rank INTEGER NOT NULL DEFAULT 2, sev_rank INTEGER NOT NULL DEFAULT 4);",
        )
        .unwrap();
        let payload = format!(
            "{{\"tool\":\"afterzero\",\"class\":\"vuln\",\"severity\":\"high\",\"priority\":\"p2\",\"rule\":\"afterzero.reachable\",\"summary\":\"{summary}\",\"join\":\"JOIN-SECRET-VALUE\",\"dedupe\":\"DEDUPE-SECRET-77\"}}"
        );
        conn.execute(
            "INSERT INTO signals (id, dedupe, tool, state, created_at_ms, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params!["row-1", "dedupe-row", "afterzero", "pending", now, payload],
        )
        .unwrap();
        drop(conn);
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn lab(summary: &str, down: bool) -> Lab {
        lab_with(summary, down, false)
    }

    fn lab_with(summary: &str, down: bool, fleet: bool) -> Lab {
        let root = tempfile::tempdir().unwrap();
        let pin = pin_for(root.path(), &secret(1), &secret(2), fleet);
        fs::create_dir(&pin.state_dir).unwrap();
        fs::set_permissions(&pin.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
        write_private_new(
            &pin.state_dir.join("status.json"),
            status_json(NOW).as_bytes(),
        )
        .unwrap();
        plant_db(&pin.state_dir.join("signals.db"), NOW, summary);
        write_token(&pin.token_file).unwrap();
        let mut raw = fs::read(&pin.token_file).unwrap();
        assert_eq!(raw.len(), 65);
        let token = String::from_utf8(raw[..64].to_vec()).unwrap();
        raw.zeroize();
        let policy = parse_policy(&policy_text(NOW)).unwrap();
        let source = if down {
            Arc::new(ScriptedSource::new(Err("settings_unreachable")))
        } else {
            Arc::new(ScriptedSource::new(Ok(policy)))
        };
        Lab {
            _root: root,
            pin,
            source,
            fleet: Arc::new(ScriptedFleet::new(Ok(fixtures::good()))),
            clock: Arc::new(AtomicI64::new(NOW)),
            token,
        }
    }

    fn serve_for<T>(lab: &Lab, body: impl FnOnce(u16) -> T) -> T {
        let listener = TcpListener::bind((LOOPBACK, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let ticks = Arc::clone(&lab.clock);
        let clock: Clock = Arc::new(move || Ok(ticks.load(Ordering::SeqCst)));
        let owned = Arc::clone(&lab.source);
        let source: Arc<dyn SettingsSource> = owned;
        let owned_fleet = Arc::clone(&lab.fleet);
        let fleet: Arc<dyn FleetSource> = owned_fleet;
        let stop = AtomicBool::new(false);
        thread::scope(|scope| {
            let guard = StopGuard { stop: &stop };
            let handle = scope
                .spawn(|| serve_listener(&listener, &lab.pin, &clock, &source, &fleet, &stop));
            let value = body(port);
            drop(guard);
            assert!(matches!(handle.join(), Ok(Ok(()))));
            value
        })
    }

    fn exchange(port: u16, request: &str) -> String {
        let mut last = String::new();
        for _ in 0..100 {
            match TcpStream::connect((LOOPBACK, port)) {
                Ok(mut stream) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream.write_all(request.as_bytes()).unwrap();
                    let mut out = String::new();
                    match stream.read_to_string(&mut out) {
                        Ok(_) => return out,
                        Err(_) => last = out,
                    }
                }
                Err(_) => thread::sleep(Duration::from_millis(10)),
            }
        }
        last
    }

    fn body_after(raw: &str) -> &str {
        raw.split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .unwrap_or("")
    }

    fn host_line(port: u16) -> String {
        format!("Host: {LOOPBACK}:{port}\r\n")
    }

    fn post_session(port: u16, token: &str, origin: Option<&str>) -> String {
        let origin_line = match origin {
            Some(value) => format!("Origin: {value}\r\n"),
            None => String::new(),
        };
        format!(
            "POST /session HTTP/1.1\r\n{host}{origin_line}Content-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{token}",
            host = host_line(port),
            len = token.len()
        )
    }

    fn session_pair(raw: &str) -> String {
        raw.lines()
            .find_map(|line| line.strip_prefix("Set-Cookie: "))
            .and_then(|rest| rest.split(';').next())
            .unwrap_or("")
            .to_string()
    }

    fn authed_get(port: u16, path: &str, cookie: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\n{host}Cookie: {cookie}\r\nConnection: close\r\n\r\n",
            host = host_line(port)
        )
    }

    fn assert_security(raw: &str) {
        assert!(raw.contains("Cache-Control: no-store\r\n"));
        assert!(raw.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(raw.contains("Referrer-Policy: no-referrer\r\n"));
        assert!(raw.contains(CSP));
        assert!(raw.contains("Connection: close\r\n"));
    }

    #[test]
    fn page_source_stays_static() {
        let page = include_str!("page.html");
        for banned in [
            "innerHTML",
            "document.write",
            "eval(",
            "setTimeout(\"",
            "setTimeout('",
            "insertAdjacentHTML",
        ] {
            assert!(!page.contains(banned));
        }
        assert!(page.contains(
            "Afterzero counts are pack conditions met, not confirmation of exploitation."
        ));
        assert!(page.contains("nocved is the sensor; nocve-store is the forwarder."));
        assert!(page.contains("darksignal is the local bus, not a counted producer."));
        assert!(page.contains("function componentState"));
        assert!(page.contains("\"dashed\""));
        assert!(page.contains("\"partial\""));
        assert!(page.contains("\"shown\""));
        assert!(page.contains("method=\"post\""));
        assert!(page.contains("#d24a3a"));
        assert!(page.contains("#e0a100"));
        assert!(page.contains("#7d9a62"));
    }

    #[test]
    fn shell_and_healthz_are_open() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            let health = exchange(
                port,
                &format!(
                    "GET /healthz HTTP/1.1\r\n{host}Connection: close\r\n\r\n",
                    host = host_line(port)
                ),
            );
            assert!(health.starts_with("HTTP/1.1 200 "));
            assert!(health.contains("Content-Type: application/json\r\n"));
            assert_eq!(body_after(&health), "{\"ok\":true}");
            assert_security(&health);
            let page = exchange(
                port,
                &format!(
                    "GET / HTTP/1.1\r\n{host}Connection: close\r\n\r\n",
                    host = host_line(port)
                ),
            );
            assert!(page.contains("Content-Type: text/html; charset=utf-8\r\n"));
            let html = body_after(&page);
            assert!(html.contains(
                "Afterzero counts are pack conditions met, not confirmation of exploitation."
            ));
            assert!(html.contains("nocved is the sensor; nocve-store is the forwarder."));
            assert!(html.contains("darksignal is the local bus, not a counted producer."));
        });
    }

    #[test]
    fn login_snapshot_hides_join_and_token() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            let raw = exchange(port, &post_session(port, &lab.token, None));
            assert!(raw.starts_with("HTTP/1.1 200 "));
            assert_eq!(body_after(&raw), "{\"ok\":true}");
            assert!(raw.contains("Max-Age=28800"));
            assert_security(&raw);
            let cookie = session_pair(&raw);
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(snap.starts_with("HTTP/1.1 200 "));
            let body = body_after(&snap);
            assert!(body.contains("pack conditions met"));
            assert!(body.contains("edge-1"));
            assert!(!body.contains("JOIN-SECRET-VALUE"));
            assert!(!body.contains("DEDUPE-SECRET-77"));
            let leaked = body.contains(&lab.token);
            assert!(!leaked);
        });
    }

    #[test]
    fn fleet_panel_is_off_without_a_pinned_fleet() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            let raw = exchange(port, &post_session(port, &lab.token, None));
            let cookie = session_pair(&raw);
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(body_after(&snap).contains("\"fleet\":null"));
        });
        assert_eq!(lab.fleet.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn fleet_panel_is_projected_into_the_snapshot() {
        let lab = lab_with("pack conditions met", false, true);
        serve_for(&lab, |port| {
            let raw = exchange(port, &post_session(port, &lab.token, None));
            let cookie = session_pair(&raw);
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(snap.starts_with("HTTP/1.1 200 "));
            let body = body_after(&snap);
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(value["fleet"]["state"], "shown");
            assert_eq!(value["fleet"]["hosts"][1]["host"], "ns2");
            assert_eq!(value["fleet"]["signals"][0]["rule"], "chain.rollback");
            for secret in ["JOIN-FLEET-SECRET", "DEDUPE-FLEET-SECRET", "ITEMHASHSECRET"] {
                assert!(!body.contains(secret));
            }
            let again = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(again.starts_with("HTTP/1.1 200 "));
        });
        assert_eq!(lab.fleet.calls.load(Ordering::SeqCst), 1, "cached within 30 s");
    }

    #[test]
    fn closed_policy_does_not_call_the_fleet() {
        let lab = lab_with("pack conditions met", true, true);
        serve_for(&lab, |port| {
            let raw = exchange(port, &post_session(port, &lab.token, None));
            let cookie = session_pair(&raw);
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(snap.starts_with("HTTP/1.1 503 "));
        });
        assert_eq!(lab.fleet.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn unknown_paths_are_not_found() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            for path in ["/nope", "/healthz/", "/api/snapshot/"] {
                let raw = exchange(
                    port,
                    &format!(
                        "GET {path} HTTP/1.1\r\n{host}Connection: close\r\n\r\n",
                        host = host_line(port)
                    ),
                );
                assert!(raw.starts_with("HTTP/1.1 404 "));
                assert_eq!(body_after(&raw), "{\"error\":\"not_found\"}");
            }
        });
    }

    #[test]
    fn absent_cookie_does_not_read_a_locked_token() {
        let lab = lab("pack conditions met", false);
        fs::set_permissions(&lab.pin.token_file, fs::Permissions::from_mode(0o000)).unwrap();
        serve_for(&lab, |port| {
            let raw = exchange(
                port,
                &format!(
                    "GET /api/snapshot HTTP/1.1\r\n{host}Connection: close\r\n\r\n",
                    host = host_line(port)
                ),
            );
            assert!(raw.starts_with("HTTP/1.1 401 "));
            assert_eq!(body_after(&raw), "{\"error\":\"unauthorized\"}");
            assert!(!raw.contains("\"problem\":\"token\""));
        });
        fs::set_permissions(&lab.pin.token_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn eight_failures_lock_the_ninth_guess() {
        let lab = lab("pack conditions met", false);
        let wrong = "cd".repeat(32);
        serve_for(&lab, |port| {
            for _ in 0..8 {
                let raw = exchange(port, &post_session(port, &wrong, None));
                assert!(raw.starts_with("HTTP/1.1 401 "));
                assert_eq!(body_after(&raw), "{\"error\":\"unauthorized\"}");
            }
            let locked = exchange(port, &post_session(port, &lab.token, None));
            assert!(locked.starts_with("HTTP/1.1 401 "));
            assert_eq!(body_after(&locked), "{\"error\":\"locked\"}");
            assert!(!locked.contains("Set-Cookie: darkdash_session="));
            lab.clock.store(NOW + 61_000, Ordering::SeqCst);
            let again = exchange(port, &post_session(port, &lab.token, None));
            assert!(again.starts_with("HTTP/1.1 200 "));
            assert_eq!(body_after(&again), "{\"ok\":true}");
        });
    }

    #[test]
    fn bad_origin_does_not_increment_lockout() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            for _ in 0..8 {
                let raw = exchange(
                    port,
                    &post_session(port, &lab.token, Some("http://evil.example")),
                );
                assert!(raw.starts_with("HTTP/1.1 403 "));
                assert_eq!(body_after(&raw), "{\"error\":\"unauthorized\"}");
                assert!(!raw.contains("Set-Cookie"));
            }
            let raw = exchange(port, &post_session(port, &lab.token, None));
            assert!(raw.starts_with("HTTP/1.1 200 "));
            assert_eq!(body_after(&raw), "{\"ok\":true}");
        });
    }

    #[test]
    fn logout_revokes_the_session() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            let bare = exchange(
                port,
                &format!(
                    "POST /logout HTTP/1.1\r\n{host}Content-Length: 0\r\nConnection: close\r\n\r\n",
                    host = host_line(port)
                ),
            );
            assert!(bare.starts_with("HTTP/1.1 204 "));
            assert!(bare.contains("Content-Length: 0\r\n"));
            assert!(bare.contains("Max-Age=0"));
            assert_security(&bare);
            assert!(body_after(&bare).is_empty());
            let raw = exchange(port, &post_session(port, &lab.token, None));
            let cookie = session_pair(&raw);
            let gone = exchange(
                port,
                &format!(
                    "POST /logout HTTP/1.1\r\n{host}Cookie: {cookie}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    host = host_line(port)
                ),
            );
            assert!(gone.starts_with("HTTP/1.1 204 "));
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(snap.starts_with("HTTP/1.1 401 "));
            assert_eq!(body_after(&snap), "{\"error\":\"unauthorized\"}");
        });
    }

    #[test]
    fn bad_framing_is_rejected_before_the_body() {
        let lab = lab("pack conditions met", false);
        serve_for(&lab, |port| {
            let host = host_line(port);
            let dup = exchange(
                port,
                &format!(
                    "GET /api/snapshot HTTP/1.1\r\n{host}Cookie: darkdash_session=aa\r\nCookie: darkdash_session=bb\r\nConnection: close\r\n\r\n"
                ),
            );
            assert!(dup.starts_with("HTTP/1.1 400 "));
            let two = exchange(
                port,
                &format!(
                    "GET /api/snapshot HTTP/1.1\r\n{host}Cookie: darkdash_session=aa; darkdash_session=bb\r\nConnection: close\r\n\r\n"
                ),
            );
            assert!(two.starts_with("HTTP/1.1 400 "));
            let padded = exchange(
                port,
                &format!(
                    "GET /healthz HTTP/1.1\r\n{host}Content-Length: 01\r\nConnection: close\r\n\r\n"
                ),
            );
            assert!(padded.starts_with("HTTP/1.1 400 "));
            assert_eq!(body_after(&padded), "{\"error\":\"bad_request\"}");
            let huge = exchange(
                port,
                &format!(
                    "POST /session HTTP/1.1\r\n{host}Content-Length: 257\r\nConnection: close\r\n\r\n"
                ),
            );
            assert!(huge.starts_with("HTTP/1.1 413 "));
            assert_eq!(body_after(&huge), "{\"error\":\"too_large\"}");
            let post = exchange(
                port,
                &format!(
                    "POST / HTTP/1.1\r\n{host}Content-Length: 1\r\nConnection: close\r\n\r\nx"
                ),
            );
            assert!(post.starts_with("HTTP/1.1 400 "));
            assert_eq!(body_after(&post), "{\"error\":\"bad_request\"}");
            assert!(!post.contains("not_found"));
            let wrong = exchange(
                port,
                "GET /healthz HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
            );
            assert!(wrong.starts_with("HTTP/1.1 400 "));
            let typed = exchange(
                port,
                &format!(
                    "POST /session HTTP/1.1\r\n{host}Content-Type: text/plain\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ),
            );
            assert!(typed.starts_with("HTTP/1.1 400 "));
            assert_eq!(body_after(&typed), "{\"error\":\"bad_request\"}");
        });
    }

    #[test]
    fn invalid_glass_closes_without_the_queue() {
        let lab = lab("UNIQUE-DB-SUMMARY-91", false);
        write_private_new(&lab.pin.break_glass_file, b"not-a-valid-envelope").unwrap();
        serve_for(&lab, |port| {
            let health = exchange(
                port,
                &format!(
                    "GET /healthz HTTP/1.1\r\n{host}Connection: close\r\n\r\n",
                    host = host_line(port)
                ),
            );
            assert_eq!(body_after(&health), "{\"ok\":true}");
            let raw = exchange(port, &post_session(port, &lab.token, None));
            let cookie = session_pair(&raw);
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(snap.starts_with("HTTP/1.1 503 "));
            let body = body_after(&snap);
            assert_eq!(
                body,
                "{\"closed\":true,\"problem\":\"break_glass_invalid\"}"
            );
            assert!(!body.contains("UNIQUE-DB-SUMMARY-91"));
            assert_eq!(lab.source.calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn break_glass_serves_when_the_server_is_down() {
        let lab = lab("pack conditions met", true);
        let glass_key = secret(2);
        let body =
            sign_break_glass(&glass_key, &policy_text(NOW), "server down", "ops", NOW).unwrap();
        let identity = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["signature"]
            .as_str()
            .unwrap()
            .to_string();
        write_private_new(&lab.pin.break_glass_file, &body).unwrap();
        serve_for(&lab, |port| {
            let raw = exchange(port, &post_session(port, &lab.token, None));
            let cookie = session_pair(&raw);
            let snap = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(snap.starts_with("HTTP/1.1 200 "));
            let view = body_after(&snap);
            assert!(view.contains("\"policy_source\":\"break_glass\""));
            assert!(view.contains("\"settings_problem\":\"settings_unreachable\""));
            assert!(view.contains("server down"));
            assert!(view.contains("\"actor\":\"ops\""));
            let leaked = view.contains(&identity);
            assert!(!leaked);
            let again = exchange(port, &authed_get(port, "/api/snapshot", &cookie));
            assert!(again.starts_with("HTTP/1.1 200 "));
            assert_eq!(lab.source.calls.load(Ordering::SeqCst), 1);
            let audit = fs::read_to_string(&lab.pin.audit_file).unwrap();
            assert_eq!(audit.matches("\"event\":\"break_glass\"").count(), 1);
            let audit_leaked = audit.contains(&identity);
            assert!(!audit_leaked);
        });
    }

    #[test]
    fn non_utf8_pin_path_is_config() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(&[0xff]));
        let err = serve(path).unwrap_err();
        assert_eq!(err.to_string(), "config: path");
    }
}
