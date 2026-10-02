# darkdash

Loopback operator console for the local darksignal queue. It shows counts, a time series, and recent rows for the tools named in a signed server policy. A local break-glass file can replace that policy when the settings server is down.

The console does not ship frames, store an API key, or open a producer socket. darksignal is the local bus, not a counted producer. nocved is the sensor; nocve-store is the forwarder. Afterzero counts are pack conditions met, not confirmation of exploitation.

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

## Serve

```
darkdash serve --pin /var/lib/darkdash/pin.json
```

Open `http://127.0.0.1:<port>/` on this host. Read the token from the token file.

## Components

Each snapshot names `bus` and `queue` as `shown`, `partial`, or `dashed`. The page draws numbers for `shown` and `partial`. A missing or unknown state is dashed, so a failed check is not drawn as a quiet zero.

The queue is `dashed` when `signals.db` fails its checks. That response carries no tool cards, series, or recent rows. A verified empty tool stays a real zero. A truncated read, or a row that failed the field checks, stays `partial` and is labeled.

The bus is `shown` only when `status.json` parsed as `ok` or `stale`. Any other read is `dashed`. A stale status stays visible.
