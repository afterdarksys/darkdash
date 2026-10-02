# Design

darkdash is a loopback operator console. It reads the local darksignal queue and renders counts, a time series, and recent rows for the tools named in a signed server policy. A local break-glass file, signed by a different key and limited to four hours, can replace that policy when the settings server is down. The console does not ship frames or open a producer socket.

The pin may name a darkapi origin and a report-only key file for a read-only fleet panel. After the policy resolves, the snapshot adds that panel: the host grid, open signals, and rejected reports from `/v1/reports/*`. A refresh runs at most once every 30 seconds, failures included, and each GET times out after 5 seconds, so a refresh can hold the single-threaded listener for up to 15 seconds. A failed refresh dashes the panel; it does not draw zeros. Without the pin fields the snapshot carries `"fleet": null` and darkapi is never called.

The accept loop is single-threaded. One stalled client can block the next connection for the five-second read timeout.

Each snapshot names two components, `bus` and `queue`, as `shown`, `partial`, or `dashed`. The page draws numbers only for `shown` and `partial`. A missing or unknown state is dashed. The queue is dashed when `signals.db` fails its checks, and that response carries no tool cards, series, or recent rows. The bus is dashed unless `status.json` parsed. A stale status stays visible with that mark. A truncated read, or a row that failed the field checks, stays `partial` and is labeled.
