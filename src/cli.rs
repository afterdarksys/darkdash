//! Operator commands. No flags are read from the environment.
//!
//! Threats: key bytes stay in a zeroizing buffer and are never printed.
//! A value that starts with `--` is usage, so a missing path cannot be
//! read as another flag. Sign rejects a label with a leading space before
//! it writes an envelope.

use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::auth::{self, system_now};
use crate::error::Error;
use crate::guard::{read_private, write_private_new};
use crate::http;
use crate::policy::{generate_secret, public_from_secret, sign_break_glass, sign_settings};

#[derive(Debug)]
pub enum SignKind {
    Settings,
    BreakGlass,
}

#[derive(Debug)]
pub enum Command {
    Serve {
        pin: PathBuf,
    },
    Token {
        out: PathBuf,
    },
    Keygen {
        out: PathBuf,
    },
    Sign {
        key: PathBuf,
        policy: PathBuf,
        kind: SignKind,
        reason: Option<String>,
        actor: Option<String>,
        out: PathBuf,
    },
}

#[derive(Default)]
struct Slots {
    pin: Option<String>,
    out: Option<String>,
    key: Option<String>,
    policy: Option<String>,
    kind: Option<String>,
    reason: Option<String>,
    actor: Option<String>,
}

struct SecretKey([u8; 32]);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

struct Wipe(String);

impl Drop for Wipe {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

enum OutKind {
    Token,
    Keygen,
}

pub fn parse_args(args: &[OsString]) -> Result<Command, Error> {
    let mut text = Vec::with_capacity(args.len());
    for arg in args {
        match arg.to_str() {
            Some(value) => text.push(value),
            None => return Err(Error::Usage),
        }
    }
    parse_text(&text)
}

fn parse_text(args: &[&str]) -> Result<Command, Error> {
    if args.is_empty() || args.contains(&"--") {
        return Err(Error::Usage);
    }
    let mut slots = Slots::default();
    let mut index = 1;
    while index < args.len() {
        let flag = args[index];
        let value = args.get(index + 1).copied().ok_or(Error::Usage)?;
        if value.starts_with("--") {
            return Err(Error::Usage);
        }
        assign(&mut slots, flag, value)?;
        index = index.saturating_add(2);
    }
    finish(args[0], slots)
}

fn assign(slots: &mut Slots, flag: &str, value: &str) -> Result<(), Error> {
    if let Some(slot) = path_slot(slots, flag) {
        return fill(slot, value);
    }
    let Some(slot) = text_slot(slots, flag) else {
        return Err(Error::Usage);
    };
    fill(slot, value)
}

fn fill(slot: &mut Option<String>, value: &str) -> Result<(), Error> {
    if slot.is_some() {
        return Err(Error::Usage);
    }
    *slot = Some(value.to_string());
    Ok(())
}

fn path_slot<'a>(slots: &'a mut Slots, flag: &str) -> Option<&'a mut Option<String>> {
    match flag {
        "--pin" => Some(&mut slots.pin),
        "--out" => Some(&mut slots.out),
        "--key" => Some(&mut slots.key),
        "--policy" => Some(&mut slots.policy),
        _ => None,
    }
}

fn text_slot<'a>(slots: &'a mut Slots, flag: &str) -> Option<&'a mut Option<String>> {
    match flag {
        "--kind" => Some(&mut slots.kind),
        "--reason" => Some(&mut slots.reason),
        "--actor" => Some(&mut slots.actor),
        _ => None,
    }
}

fn finish(cmd: &str, slots: Slots) -> Result<Command, Error> {
    match cmd {
        "serve" => finish_serve(slots),
        "token" => finish_out(slots, OutKind::Token),
        "keygen" => finish_out(slots, OutKind::Keygen),
        "sign" => finish_sign(slots),
        _ => Err(Error::Usage),
    }
}

fn finish_serve(slots: Slots) -> Result<Command, Error> {
    if extra_serve(&slots) {
        return Err(Error::Usage);
    }
    let pin = slots.pin.ok_or(Error::Usage)?;
    Ok(Command::Serve {
        pin: PathBuf::from(pin),
    })
}

fn extra_serve(slots: &Slots) -> bool {
    slots.out.is_some()
        || slots.key.is_some()
        || slots.policy.is_some()
        || slots.kind.is_some()
        || slots.reason.is_some()
        || slots.actor.is_some()
}

fn finish_out(slots: Slots, which: OutKind) -> Result<Command, Error> {
    if slots.pin.is_some()
        || slots.key.is_some()
        || slots.policy.is_some()
        || slots.kind.is_some()
        || slots.reason.is_some()
        || slots.actor.is_some()
    {
        return Err(Error::Usage);
    }
    let out = slots.out.ok_or(Error::Usage)?;
    match which {
        OutKind::Token => Ok(Command::Token {
            out: PathBuf::from(out),
        }),
        OutKind::Keygen => Ok(Command::Keygen {
            out: PathBuf::from(out),
        }),
    }
}

fn finish_sign(slots: Slots) -> Result<Command, Error> {
    if slots.pin.is_some() {
        return Err(Error::Usage);
    }
    let key = slots.key.ok_or(Error::Usage)?;
    let policy = slots.policy.ok_or(Error::Usage)?;
    let out = slots.out.ok_or(Error::Usage)?;
    let kind = match slots.kind.as_deref() {
        Some("settings") => SignKind::Settings,
        Some("break-glass") => SignKind::BreakGlass,
        _ => return Err(Error::Usage),
    };
    match kind {
        SignKind::Settings if slots.reason.is_some() || slots.actor.is_some() => {
            return Err(Error::Usage);
        }
        SignKind::BreakGlass if slots.reason.is_none() || slots.actor.is_none() => {
            return Err(Error::Usage);
        }
        SignKind::Settings | SignKind::BreakGlass => {}
    }
    Ok(Command::Sign {
        key: PathBuf::from(key),
        policy: PathBuf::from(policy),
        kind,
        reason: slots.reason,
        actor: slots.actor,
        out: PathBuf::from(out),
    })
}

pub fn run(cmd: Command) -> Result<(), Error> {
    match cmd {
        Command::Serve { pin } => http::serve(&pin),
        Command::Token { out } => auth::write_token(&out),
        Command::Keygen { out } => keygen(&out),
        Command::Sign {
            key,
            policy,
            kind,
            reason,
            actor,
            out,
        } => sign_to(
            &key,
            &policy,
            &kind,
            reason.as_deref(),
            actor.as_deref(),
            &out,
        ),
    }
}

fn keygen(out: &Path) -> Result<(), Error> {
    let public = keygen_to(out)?;
    writeln!(io::stdout(), "{public}")?;
    eprintln!("darkdash: wrote key");
    Ok(())
}

fn keygen_to(out: &Path) -> Result<String, Error> {
    let secret = SecretKey(generate_secret()?);
    let public = public_from_secret(&secret.0)?;
    write_private_new(out, &secret.0)?;
    Ok(hex::encode(public))
}

fn sign_to(
    key: &Path,
    policy: &Path,
    kind: &SignKind,
    reason: Option<&str>,
    actor: Option<&str>,
    out: &Path,
) -> Result<(), Error> {
    let secret = read_key(key)?;
    let text = read_policy(policy)?;
    let now = system_now().map_err(|_| Error::Closed("clock"))?;
    let bytes = signed(&secret, &text.0, kind, reason, actor, now)?;
    write_private_new(out, &bytes)?;
    wrote(kind);
    Ok(())
}

fn signed(
    secret: &SecretKey,
    text: &str,
    kind: &SignKind,
    reason: Option<&str>,
    actor: Option<&str>,
    now: i64,
) -> Result<Vec<u8>, Error> {
    match kind {
        SignKind::Settings => sign_settings(&secret.0, text, now),
        SignKind::BreakGlass => sign_break_glass(
            &secret.0,
            text,
            reason.ok_or(Error::Usage)?,
            actor.ok_or(Error::Usage)?,
            now,
        ),
    }
}

fn wrote(kind: &SignKind) {
    match kind {
        SignKind::Settings => eprintln!("darkdash: wrote settings"),
        SignKind::BreakGlass => eprintln!("darkdash: wrote break-glass"),
    }
}

fn read_key(path: &Path) -> Result<SecretKey, Error> {
    let mut bytes = read_private(path, 33)?;
    let decoded = decode_key(&bytes);
    bytes.zeroize();
    decoded.map(SecretKey)
}

fn decode_key(bytes: &[u8]) -> Result<[u8; 32], Error> {
    if bytes.len() != 32 {
        return Err(Error::Config("key"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    if bool::from(key.ct_eq(&[0u8; 32])) {
        key.zeroize();
        return Err(Error::Config("key"));
    }
    Ok(key)
}

fn read_policy(path: &Path) -> Result<Wipe, Error> {
    let mut bytes = read_private(path, 4097)?;
    if bytes.len() > 4096 {
        bytes.zeroize();
        return Err(Error::Config("policy"));
    }
    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text.to_string(),
        Err(_) => {
            bytes.zeroize();
            return Err(Error::Config("policy"));
        }
    };
    bytes.zeroize();
    Ok(Wipe(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{verify_break_glass, verify_settings};
    use std::os::unix::ffi::OsStringExt;

    fn err_text<T>(result: Result<T, Error>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(err) => err.to_string(),
        }
    }

    fn owned(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn assert_usage(args: &[&str]) {
        let err = parse_args(&owned(args)).unwrap_err();
        let text = err.to_string();
        assert_eq!(text, "usage");
        assert!(!text.contains("secret"));
    }

    #[test]
    fn usage_shapes() {
        assert_usage(&[]);
        assert_usage(&["serve"]);
        assert_usage(&["serve", "--pin"]);
        assert_usage(&["serve", "--pin", "--secret"]);
        assert_usage(&["serve", "--pin", "/tmp/a", "--pin", "/tmp/b"]);
        assert_usage(&["serve", "--pin", "/tmp/a", "--out", "/tmp/b"]);
        assert_usage(&["serve", "--"]);
        assert_usage(&["token"]);
        assert_usage(&["token", "--out", "/tmp/a", "--pin", "/tmp/b"]);
        assert_usage(&["nope", "--out", "/tmp/a"]);
        assert_usage(&[
            "sign", "--key", "/tmp/k", "--policy", "/tmp/p", "--kind", "settings",
        ]);
        assert_usage(&[
            "sign", "--key", "/tmp/k", "--policy", "/tmp/p", "--kind", "settings", "--reason",
            "because", "--out", "/tmp/o",
        ]);
        assert_usage(&[
            "sign",
            "--key",
            "/tmp/k",
            "--policy",
            "/tmp/p",
            "--kind",
            "break-glass",
            "--out",
            "/tmp/o",
        ]);
    }

    #[test]
    fn parses_serve_and_break_glass() {
        let serve = parse_args(&owned(&["serve", "--pin", "/var/lib/darkdash/pin.json"])).unwrap();
        assert!(matches!(serve, Command::Serve { .. }));
        let token = parse_args(&owned(&["token", "--out", "/tmp/t"])).unwrap();
        assert!(matches!(token, Command::Token { .. }));
        let keygen = parse_args(&owned(&["keygen", "--out", "/tmp/k"])).unwrap();
        assert!(matches!(keygen, Command::Keygen { .. }));
        let sign = parse_args(&owned(&[
            "sign",
            "--key",
            "/k",
            "--policy",
            "/p",
            "--kind",
            "break-glass",
            "--reason",
            "settings server down",
            "--actor",
            "ops",
            "--out",
            "/o",
        ]))
        .unwrap();
        assert!(matches!(
            sign,
            Command::Sign {
                kind: SignKind::BreakGlass,
                ..
            }
        ));
    }

    #[test]
    fn non_utf8_arg_is_usage() {
        let arg = OsString::from_vec(vec![0xff]);
        let err = parse_args(&[arg]).unwrap_err();
        assert_eq!(err.to_string(), "usage");
    }

    #[test]
    fn serve_rejects_a_relative_pin_without_binding() {
        let err = http::serve(Path::new("relative")).unwrap_err();
        let text = err.to_string();
        assert_eq!(text, "config: path");
        assert!(!text.contains("relative"));
    }

    #[test]
    fn serve_rejects_a_bad_pin_before_bind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pin");
        write_private_new(&path, b"not-json").unwrap();
        let err = http::serve(&path).unwrap_err();
        assert_eq!(err.to_string(), "config: pin");
    }

    #[test]
    fn keygen_writes_a_secret_and_returns_the_public_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        let public = keygen_to(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 32);
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        let expect = hex::encode(public_from_secret(&raw).unwrap());
        raw.zeroize();
        assert_eq!(public, expect);
    }

    #[test]
    fn token_file_is_hex_and_a_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        auth::write_token(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[64], b'\n');
        assert!(
            bytes[..64]
                .iter()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    fn policy_text(now: i64) -> String {
        format!(
            "schema=darkdash.policy.v1\nissued_at_ms={now}\nexpires_at_ms={expires}\nrefresh_seconds=30\nwindow_hours=24\nsilence_seconds=90\nsite=Lab One\ntools=afterzero,nocved\n",
            expires = now + 3_600_000
        )
    }

    #[test]
    fn sign_roundtrip_and_closed_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key");
        let policy = dir.path().join("policy");
        let settings = dir.path().join("settings");
        let glass = dir.path().join("glass");
        let public = keygen_to(&key).unwrap();
        let now = system_now().unwrap();
        write_private_new(&policy, policy_text(now).as_bytes()).unwrap();
        sign_to(&key, &policy, &SignKind::Settings, None, None, &settings).unwrap();
        sign_to(
            &key,
            &policy,
            &SignKind::BreakGlass,
            Some("settings server down"),
            Some("ops"),
            &glass,
        )
        .unwrap();
        let mut pub_bytes = [0u8; 32];
        hex::decode_to_slice(&public, &mut pub_bytes).unwrap();
        let signed_settings = read_private(&settings, 16 * 1024).unwrap();
        let opened = verify_settings(&signed_settings, &pub_bytes, system_now().unwrap()).unwrap();
        assert_eq!(opened.site, "Lab One");
        let signed_glass = read_private(&glass, 16 * 1024).unwrap();
        let broke = verify_break_glass(&signed_glass, &pub_bytes, system_now().unwrap()).unwrap();
        assert_eq!(broke.actor, "ops");
        let label = sign_to(
            &key,
            &policy,
            &SignKind::BreakGlass,
            Some(" SECRETREASON"),
            Some("ops"),
            &dir.path().join("nope"),
        )
        .unwrap_err();
        let text = label.to_string();
        assert_eq!(text, "config: label");
        assert!(!text.contains("SECRET"));
        write_private_new(&dir.path().join("z33"), &[1u8; 33]).unwrap();
        assert_eq!(err_text(read_key(&dir.path().join("z33"))), "config: key");
        write_private_new(&dir.path().join("z34"), &[1u8; 34]).unwrap();
        assert_eq!(err_text(read_key(&dir.path().join("z34"))), "config: mode");
        write_private_new(&dir.path().join("zero"), &[0u8; 32]).unwrap();
        assert_eq!(err_text(read_key(&dir.path().join("zero"))), "config: key");
        write_private_new(&dir.path().join("p4097"), &vec![b'a'; 4097]).unwrap();
        assert_eq!(
            err_text(read_policy(&dir.path().join("p4097"))),
            "config: policy"
        );
        write_private_new(&dir.path().join("p4098"), &vec![b'a'; 4098]).unwrap();
        assert_eq!(
            err_text(read_policy(&dir.path().join("p4098"))),
            "config: mode"
        );
    }
}
