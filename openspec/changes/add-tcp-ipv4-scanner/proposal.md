# IPv4 TCP Scanning

## Why

The foundation can start as an Erlang dependency and run a CLI, but cannot perform
network scans. Consumers need a reusable TCP scanner that accepts host and port
ranges without shelling out to nmap or requiring privileged sockets.

## What Changes

- Add input normalization for IPv4 addresses, lists, inclusive ranges and CIDR,
  and for individual TCP ports, lists and inclusive ranges.
- Add bounded, supervised TCP-connect probing with streamed observations,
  synchronous collection, status and cancellation.
- Add a public Erlang API and a `scan` CLI command with text and JSON output.
- Extend lifecycle and loopback integration tests to cover resource cleanup.

## Capabilities

### New Capabilities

- `target-selection`: Validate and normalize address/port selections without duplicate probes.
- `tcp-scanning`: Execute bounded TCP probes and report observed outcomes.
- `scan-api`: Expose asynchronous and synchronous Erlang contracts and scan lifecycle controls.
- `scan-cli`: Translate command-line selections into the shared API and format results.

### Modified Capabilities

- `project-foundation`: Replace the foundation's scan-argument rejection with the implemented scan command.

## Impact

New library modules and supervised scan processes extend the existing OTP tree.
`trawler_cli` becomes an adapter to the public API. Runtime dependencies remain
kernel and stdlib; OTP 27 provides TCP networking and JSON encoding.
IPv6, UDP, ICMP/ARP, OS detection, service fingerprinting, web UI and exact nmap
argument compatibility are excluded. This prepared change has not been applied.
