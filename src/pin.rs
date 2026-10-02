//! Local pin. The server cannot change the bind address, the state
//! directory, the keys, the settings URL, or the fleet URL and key file.
//!
//! Threats: a relative path, a non-loopback bind, an HTTP settings URL, a
//! weak or all-zero public key, or two identical signing keys must not open
//! the console. Unknown JSON fields fail closed. The pin file itself is
//! mode 0600, owned by this euid, and not a symlink. The fleet panel is
//! optional: `fleet_url` and `fleet_key_file` are both present or both absent,
//! the URL is HTTPS with no path, and the key file sits apart from every
//! other pinned path.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Error;
use crate::guard::{clean_abs, is_inside, read_private};
use crate::policy::{parse_pubkey, pubkeys_differ};

const MAX_PIN: u64 = 8192;
pub const LOOPBACK: &str = "127.0.0.1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinFile {
    schema: String,
    settings_url: String,
    server_pubkey: String,
    break_glass_pubkey: String,
    break_glass_file: String,
    state_dir: String,
    token_file: String,
    audit_file: String,
    bind: String,
    #[serde(default)]
    fleet_url: Option<String>,
    #[serde(default)]
    fleet_key_file: Option<String>,
}

/// darkapi read-only reporting source for the fleet panel.
pub struct Fleet {
    pub url: String,
    pub key_file: PathBuf,
}

pub struct Pin {
    pub settings_url: String,
    pub server_pubkey: [u8; 32],
    pub break_glass_pubkey: [u8; 32],
    pub break_glass_file: PathBuf,
    pub state_dir: PathBuf,
    pub token_file: PathBuf,
    pub audit_file: PathBuf,
    pub port: u16,
    pub fleet: Option<Fleet>,
}

impl Pin {
    pub fn origin(&self, port: u16) -> String {
        format!("http://{LOOPBACK}:{port}")
    }

    pub fn host_header(&self, port: u16) -> String {
        format!("{LOOPBACK}:{port}")
    }
}

pub fn load_pin(path: &Path) -> Result<Pin, Error> {
    let bytes = read_private(path, MAX_PIN)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Config("pin"))?;
    parse_pin(text)
}

pub fn parse_pin(text: &str) -> Result<Pin, Error> {
    if text.len() > usize::try_from(MAX_PIN).unwrap_or(8192) {
        return Err(Error::Config("pin"));
    }
    let file: PinFile = serde_json::from_str(text).map_err(|_| Error::Config("pin"))?;
    if file.schema != "darkdash.pin.v1" {
        return Err(Error::Config("pin"));
    }
    validate_url(&file.settings_url)?;
    let server = parse_pubkey(&file.server_pubkey)?;
    let glass = parse_pubkey(&file.break_glass_pubkey)?;
    if !pubkeys_differ(&server, &glass) {
        return Err(Error::Config("pubkey"));
    }
    let break_glass_file = clean_abs(&file.break_glass_file)?;
    let state_dir = clean_abs(&file.state_dir)?;
    let token_file = clean_abs(&file.token_file)?;
    let audit_file = clean_abs(&file.audit_file)?;
    let port = parse_bind(&file.bind)?;
    if crowded(&break_glass_file, &state_dir)
        || crowded(&token_file, &state_dir)
        || crowded(&audit_file, &state_dir)
        || crowded(&break_glass_file, &token_file)
        || crowded(&break_glass_file, &audit_file)
        || crowded(&token_file, &audit_file)
    {
        return Err(Error::Config("path"));
    }
    let fleet = parse_fleet(
        file.fleet_url,
        file.fleet_key_file,
        &[&break_glass_file, &state_dir, &token_file, &audit_file],
    )?;
    Ok(Pin {
        settings_url: file.settings_url,
        server_pubkey: server,
        break_glass_pubkey: glass,
        break_glass_file,
        state_dir,
        token_file,
        audit_file,
        port,
        fleet,
    })
}

fn parse_fleet(
    url: Option<String>,
    key_file: Option<String>,
    others: &[&Path],
) -> Result<Option<Fleet>, Error> {
    let (url, key_file) = match (url, key_file) {
        (None, None) => return Ok(None),
        (Some(url), Some(key_file)) => (url, key_file),
        _ => return Err(Error::Config("fleet")),
    };
    validate_url(&url)?;
    let origin = url.strip_prefix("https://").ok_or(Error::Config("fleet"))?;
    if origin.contains('/') {
        return Err(Error::Config("fleet"));
    }
    let key_file = clean_abs(&key_file)?;
    if others.iter().any(|other| crowded(&key_file, other)) {
        return Err(Error::Config("path"));
    }
    Ok(Some(Fleet { url, key_file }))
}

fn crowded(left: &Path, right: &Path) -> bool {
    left == right || is_inside(left, right) || is_inside(right, left)
}

fn parse_bind(bind: &str) -> Result<u16, Error> {
    let rest = bind
        .strip_prefix("127.0.0.1:")
        .ok_or(Error::Config("bind"))?;
    parse_port(rest).map_err(|_| Error::Config("bind"))
}

fn parse_port(raw: &str) -> Result<u16, ()> {
    if raw.is_empty() || raw.len() > 5 || (raw.len() > 1 && raw.starts_with('0')) {
        return Err(());
    }
    if !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    let port: u16 = raw.parse().map_err(|_| ())?;
    if port == 0 {
        return Err(());
    }
    Ok(port)
}

fn validate_url(url: &str) -> Result<(), Error> {
    if url.len() > 2048 || url.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(Error::Config("url"));
    }
    if url.contains('@') || url.contains('?') || url.contains('#') || url.contains('\\') {
        return Err(Error::Config("url"));
    }
    if url.ends_with('/') {
        return Err(Error::Config("url"));
    }
    let rest = url.strip_prefix("https://").ok_or(Error::Config("url"))?;
    if rest.is_empty() || rest.contains('[') || rest.contains(']') {
        return Err(Error::Config("url"));
    }
    let (hostport, path) = match rest.split_once('/') {
        Some((host, path)) => (host, Some(path)),
        None => (rest, None),
    };
    let (host, port) = split_host(hostport)?;
    host_ok(host)?;
    if let Some(raw) = port {
        parse_port(raw).map_err(|_| Error::Config("url"))?;
    }
    if let Some(path) = path {
        path_ok(path)?;
    }
    Ok(())
}

fn split_host(hostport: &str) -> Result<(&str, Option<&str>), Error> {
    if let Some((host, port)) = hostport.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok((host, Some(port)));
    }
    Ok((hostport, None))
}

fn host_ok(host: &str) -> Result<(), Error> {
    if host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains("..")
    {
        return Err(Error::Config("url"));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(Error::Config("url"));
    }
    Ok(())
}

fn path_ok(path: &str) -> Result<(), Error> {
    if path.is_empty() {
        return Err(Error::Config("url"));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(Error::Config("url"));
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err(Error::Config("url"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::public_from_secret;

    fn pubkey(byte: u8) -> String {
        let mut secret = [byte; 32];
        secret[0] = byte.wrapping_add(9);
        hex::encode(public_from_secret(&secret).unwrap())
    }

    fn document(url: &str, server: &str, glass: &str, bind: &str) -> String {
        with_paths(
            url,
            server,
            glass,
            bind,
            "/var/lib/darksignal",
            "/var/lib/darkdash/token",
        )
    }

    fn with_paths(
        url: &str,
        server: &str,
        glass: &str,
        bind: &str,
        state: &str,
        token: &str,
    ) -> String {
        let glass_path = "/var/lib/darkdash/break-glass.json";
        let audit = "/var/lib/darkdash/audit";
        format!(
            r#"{{"schema":"darkdash.pin.v1","settings_url":"{url}","server_pubkey":"{server}","break_glass_pubkey":"{glass}","break_glass_file":"{glass_path}","state_dir":"{state}","token_file":"{token}","audit_file":"{audit}","bind":"{bind}"}}"#
        )
    }

    fn good() -> String {
        document(
            "https://darkapi.example/v1/darkdash/settings",
            &pubkey(1),
            &pubkey(2),
            "127.0.0.1:9",
        )
    }

    #[test]
    fn accepts_https_and_a_loopback_bind() {
        let pin = parse_pin(&good()).unwrap();
        assert_eq!(pin.port, 9);
        assert!(pin.settings_url.starts_with("https://"));
        let with_port = document(
            "https://darkapi.example:443/v1/darkdash/settings",
            &pubkey(1),
            &pubkey(2),
            "127.0.0.1:443",
        );
        assert!(parse_pin(&with_port).is_ok());
    }

    #[test]
    fn rejects_bad_pin_material() {
        let server = pubkey(1);
        let http = document(
            "http://darkapi.example/v1/darkdash/settings",
            &server,
            &pubkey(2),
            "127.0.0.1:9",
        );
        assert!(parse_pin(&http).is_err());
        let wide = document(
            "https://darkapi.example/v1/darkdash/settings",
            &server,
            &pubkey(2),
            "0.0.0.0:9",
        );
        assert!(parse_pin(&wide).is_err());
        let same = document(
            "https://darkapi.example/v1/darkdash/settings",
            &server,
            &server,
            "127.0.0.1:9",
        );
        assert!(parse_pin(&same).is_err());
        let relative = with_paths(
            "https://darkapi.example/v1/darkdash/settings",
            &server,
            &pubkey(2),
            "127.0.0.1:9",
            "relative",
            "/var/lib/darkdash/token",
        );
        assert!(parse_pin(&relative).is_err());
        let mut extra: serde_json::Value = serde_json::from_str(&good()).unwrap();
        extra["extra"] = serde_json::json!(1);
        assert!(parse_pin(&extra.to_string()).is_err());
        let small = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        let weak = document(
            "https://darkapi.example/v1/darkdash/settings",
            small,
            &pubkey(2),
            "127.0.0.1:9",
        );
        assert!(parse_pin(&weak).is_err());
        let zeros = "0".repeat(64);
        let zeroed = document(
            "https://darkapi.example/v1/darkdash/settings",
            &zeros,
            &pubkey(2),
            "127.0.0.1:9",
        );
        assert!(parse_pin(&zeroed).is_err());
        let inside = with_paths(
            "https://darkapi.example/v1/darkdash/settings",
            &server,
            &pubkey(2),
            "127.0.0.1:9",
            "/var/lib/darksignal",
            "/var/lib/darksignal/token",
        );
        assert!(parse_pin(&inside).is_err());
    }

    fn with_fleet(fields: &str) -> String {
        let base = good();
        format!("{},{fields}}}", &base[..base.len() - 1])
    }

    #[test]
    fn fleet_is_optional_and_pinned() {
        assert!(parse_pin(&good()).unwrap().fleet.is_none());
        let pin = parse_pin(&with_fleet(
            r#""fleet_url":"https://api.darkapi.example","fleet_key_file":"/var/lib/darkdash/fleet.key""#,
        ))
        .unwrap();
        let fleet = pin.fleet.unwrap();
        assert_eq!(fleet.url, "https://api.darkapi.example");
        assert_eq!(fleet.key_file, PathBuf::from("/var/lib/darkdash/fleet.key"));
    }

    #[test]
    fn rejects_bad_fleet_material() {
        let key = r#""fleet_key_file":"/var/lib/darkdash/fleet.key""#;
        for url in [
            "http://api.darkapi.example",
            "https://api.darkapi.example/v1",
            "https://api.darkapi.example/",
            "https://user@api.darkapi.example",
            "https://api.darkapi.example?x=1",
        ] {
            let text = with_fleet(&format!(r#""fleet_url":"{url}",{key}"#));
            assert!(parse_pin(&text).is_err(), "{url}");
        }
        let url_only = with_fleet(r#""fleet_url":"https://api.darkapi.example""#);
        assert!(parse_pin(&url_only).is_err());
        assert!(parse_pin(&with_fleet(key)).is_err());
        for path in [
            "relative.key",
            "/var/lib/darkdash/token",
            "/var/lib/darksignal/fleet.key",
            "/var/lib/darkdash/audit",
        ] {
            let text = with_fleet(&format!(
                r#""fleet_url":"https://api.darkapi.example","fleet_key_file":"{path}""#
            ));
            assert!(parse_pin(&text).is_err(), "{path}");
        }
    }
}
