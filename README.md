# darkdash

Loopback operator console for the local darksignal queue. It shows counts, a time series, and recent rows for the tools named in a signed server policy. A local break-glass file can replace that policy when the settings server is down.

The console does not ship frames or open a producer socket. It holds an API key only for the optional fleet panel, read from a pinned file (see Fleet). darksignal is the local bus, not a counted producer. nocved is the sensor; nocve-store is the forwarder. Afterzero counts are pack conditions met, not confirmation of exploitation.

## Layout

Create the parent directories yourself, mode 0700. The token file, the audit file, and the break-glass file sit outside `state_dir`. No path may contain another.

## Keys and token

```
darkdash keygen --out /var/lib/darkdash/server.key
darkdash keygen --out /var/lib/darkdash/glass.key
darkdash token --out /var/lib/darkdash/token
```

The token is written to the file and is not printed. Each key file is mode 0600. The public key is printed once. The two public keys must differ.

## Policy

A policy is eight lines:

```
schema=darkdash.policy.v1
issued_at_ms=1700000000000
expires_at_ms=1700003600000
refresh_seconds=30
window_hours=24
silence_seconds=90
site=Lab One
tools=afterzero,cveguard,darkapple,nocved
```

`tools` is a sorted unique subset of `aftercve`, `afterseal`, `afterzero`, `cveguard`, `darkapple`, `nocve-store`, and `nocved`. Server settings last at most seven days. Break-glass lasts at most four hours.

Sign settings with the server key:

```
darkdash sign --key /var/lib/darkdash/server.key --policy /var/lib/darkdash/policy.txt --kind settings --out /var/lib/darkdash/settings.json
```

The settings server returns that envelope from the pin's `settings_url`.

Break-glass uses the other key, a reason, and an actor:

```
darkdash sign --key /var/lib/darkdash/glass.key --policy /var/lib/darkdash/policy.txt --kind break-glass --reason "settings server down" --actor ops --out /var/lib/darkdash/break-glass.json
```

An absent break-glass file uses the server policy. A present valid file overrides the server. A present invalid file keeps the console closed.

## Pin

`darkdash.pin.v1` names the settings URL, both public keys, the break-glass path, `state_dir`, the token path, the audit path, and `bind`. `bind` is `127.0.0.1` and a port. The server cannot change those fields. `state_dir` is the darksignal state directory (mode 0700) that holds `signals.db` and `status.json`.

## Fleet

The pin may add a read-only fleet panel from darkapi's reporting routes. Both fields are present or both are absent:

```
"fleet_url": "https://api.darkapi.io",
"fleet_key_file": "/var/lib/darkdash/fleet.key"
```

`fleet_url` is an HTTPS origin with no path. The key file holds one darkapi user key whose permissions are only `report:read` (darkapi confines such a key to `/v1/reports` and `/v1/sensor-keys`). The file is mode 0600, owned by this user, and outside `state_dir` and every other pinned path. darkdash sends it as `X-API-Key` on three GETs per refresh (`/v1/reports/hosts`, open `/v1/reports/signals`, `/v1/reports/rejections`), at most once every 30 seconds. The panel never acknowledges a signal or mints a key; do that in darkapi.

The panel is `shown`, `partial` when rows failed the field checks, or `dashed` with a problem: `fleet_key` (the file failed its checks), `fleet_key_rejected` (401 or 403), `fleet_limited` (429), `fleet_unreachable`, or `fleet_rejected` (another status or a body that did not parse).

## Serve

```
darkdash serve --pin /var/lib/darkdash/pin.json
```

Open `http://127.0.0.1:<port>/` on this host. Read the token from the token file.

## Components

Each snapshot names `bus` and `queue` as `shown`, `partial`, or `dashed`. The page draws numbers for `shown` and `partial`. A missing or unknown state is dashed, so a failed check is not drawn as a quiet zero.

The queue is `dashed` when `signals.db` fails its checks. That response carries no tool cards, series, or recent rows. A verified empty tool stays a real zero. A truncated read, or a row that failed the field checks, stays `partial` and is labeled.

The bus is `shown` only when `status.json` parsed as `ok` or `stale`. Any other read is `dashed`. A stale status stays visible.
