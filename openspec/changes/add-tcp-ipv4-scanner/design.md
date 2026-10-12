# IPv4 TCP Scanner Design

## Context

The repository currently has an OTP application root and an escript shell. The
scanner will be a reusable dependency with the same core serving Erlang consumers
and CLI users. All network tests use loopback and temporary listener sockets.

## Goals / Non-Goals

Support TCP connect over IPv4, normalized selections, bounded work, cancellation,
status and two result consumption modes. Keep runtime dependencies within OTP 27.
No privileged probes, ping prerequisites, UDP, IPv6, hostname resolution, service
fingerprinting, OS detection, persistent scan storage or browser interface in v1.

## Decisions

### Input contract

`Targets` accepts a UTF-8 binary expression or a nonempty list of IPv4 tuples and
binary expressions. A binary is a comma-separated selection of dotted-decimal
addresses, full-address inclusive ranges (`192.0.2.1-192.0.2.10`) or CIDR
(`192.0.2.0/24`). Whitespace around tokens is ignored; empty tokens are rejected.
IPv4 octets are decimal integers in 0..255. CIDR normalizes host bits to the subnet;
all addresses in the subnet are included, including its first and last addresses.

`Ports` accepts a UTF-8 binary expression or a nonempty list of integers and
`{range, First, Last}` tuples. Binary expressions contain comma-separated integers
or inclusive ranges. Ports are 1..65535; zero, descending ranges, malformed input,
non-IPv4 addresses and invalid CIDR prefixes are errors. Selections are deduplicated.
The application limit `max_hosts` defaults to 65536 unique hosts; larger selections
return `too_many_hosts` before any network work. Determine cardinality using
normalized intervals before expanding addresses. Port selections are bounded by
the port space. Never materialize the host × port Cartesian product.

### Public Erlang API

All functions require the OTP application to be running; otherwise return
`{error, not_started}`. Scan references are opaque Erlang references local to the VM.

```erlang
trawler:start_scan(Targets, Ports, Options) -> {ok, ScanRef} | {error, Reason}.
trawler:scan(Targets, Ports, Options) -> {ok, [Result]} | {error, Reason}.
trawler:status(ScanRef) -> {ok, Status} | {error, not_found}.
trawler:cancel(ScanRef) -> ok | {error, not_found | already_finished}.
```

`Options` is a map: `timeout_ms` (positive integer, default 1000), `concurrency`
(positive integer, default 64, at most the application's global limit),
`deadline_ms` (positive integer or `infinity`, default `infinity`), and `recipient`
(local pid, default caller, asynchronous API only). Reject unknown or invalid
options with `{error, {invalid_options, Details}}`; return analogous tagged input
errors for invalid targets/ports. Validate the complete request before probing.

The async API sends these messages to the recipient:

```erlang
{trawler, ScanRef, {result, Result}}
{trawler, ScanRef, {done, Summary}}
{trawler, ScanRef, {cancelled, Summary}}
{trawler, ScanRef, {error, Reason, Summary}}
```

`Result` is a map with `ip` (IPv4 tuple), `port`, `state`
(`open | closed | timeout | unreachable | error`), and `elapsed_ms`. Include
`reason` for unreachable/error outcomes. Async results follow completion order.
Exactly one terminal event is emitted, after all in-flight workers release their
resources, with no later result events. `Summary` contains total/completed counts,
counts by outcome and elapsed milliseconds; unattempted probes are not outcomes.

`Status` contains `state` (`queued | running | completed | cancelled | failed`),
total/completed counts and counts by outcome. Retain terminal status for 60 seconds,
then return `not_found`. Async mode retains counters, not a full result list.

The synchronous wrapper receives its own scan messages in a dedicated collector
process so unrelated caller messages remain untouched. It returns collected results
sorted by numerical IP and port. A deadline cancels outstanding work and returns
`{error, deadline_exceeded}`. Do not return partial lists as successful scans.

### Supervision and resource ownership

Extend `trawler_sup` with a bounded probe scheduler and a dynamic scan supervisor.
Each scan coordinator monitors its caller and recipient. Caller or recipient death
cancels remaining work; repeated cancellation of a cancelled scan is harmless.
An active explicit cancellation is idempotent (`ok`); completed/failed scans return
`already_finished`. Caller death also cleans up the synchronous collector and scan.

The application-wide `max_concurrency` defaults to 256. Apply both this limit and
the per-scan limit across concurrent scans; dispatch at most one pending item per
scan in round-robin order. Derive pending jobs lazily from normalized selections.
Temporary monitored workers own their sockets, use `gen_tcp:connect` with binary,
passive IPv4 sockets and a finite timeout, and close successful connections
immediately. Release scheduler slots on every worker exit. Cancel/timeout paths
terminate remaining workers, cancel timers and drain owned monitor notifications.
Use monotonic time. Scan processes are temporary children so crashes cannot restart
network work silently. Infrastructure failures produce one error terminal event.

### Observations

Successful connect means `open`; `econnrefused` means `closed`; TCP timeout means
`timeout`; `enetunreach` and `ehostunreach` mean `unreachable`; other socket errors
mean `error` with the original reason. An IP with no open ports is not labelled
offline. Do not label a timeout `filtered`, because connect alone cannot prove it.

### CLI contract

```text
trawler scan --targets '192.0.2.1,192.0.2.10-192.0.2.20,198.51.100.0/30' \
  --ports '22,80,443,8000-8010' [--json] [--timeout 1000] [--concurrency 64]
```

Targets and ports are required. CLI arguments map directly to the API; no scanning
logic lives in the CLI. Text output is an IP/port/state table plus a summary. JSON
output is one object containing `results` and `summary`, with dotted-decimal IPs
and string states encoded using OTP 27's `json` module. Both formats include all
observed states. Exit 0 means completed, even if no ports were open; exit 2 means
invalid arguments; exit 1 means an operational failure. Diagnostics go to stderr,
JSON data to stdout. Standard Ctrl-C stops the standalone VM and closes its sockets.

## Risks / Trade-offs

TCP-connect scanning cannot establish host absence or distinguish every firewall
condition. Global limits and lazy dispatch bound async work; synchronous and JSON
collection retain results proportional to the number of probes. Consumers doing
large scans should use the async stream. Closed-port tests must reserve ports and
avoid timing assumptions; timeout classification needs deterministic injected
probe results rather than relying on an external firewall.

## Migration Plan

Add the library API and CLI command in this change. Preserve help/version output
and standard application startup. Run the entire check suite, review the diff and
only then archive the change to promote these requirements to current specs.
