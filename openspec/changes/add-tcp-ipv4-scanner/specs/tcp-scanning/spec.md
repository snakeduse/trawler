# TCP Scanning

## Purpose

Observe IPv4 TCP connection outcomes with bounded resource use and report the
limits of those observations without claiming unsupported host classifications.

## ADDED Requirements

### Requirement: Observed connection outcomes
The scanner SHALL report `open` for a successful connect, `closed` for connection
refusal, `timeout` for an expired connect, `unreachable` for network/host unreachable,
and `error` with a reason for other socket failures. Each result SHALL identify its
address and port and contain a nonnegative elapsed duration.

#### Scenario: An open loopback port
- **WHEN** a TCP listener accepts connections on the selected loopback port
- **THEN** the result is `open` and the scanner closes its connection

#### Scenario: A refused connection
- **WHEN** the TCP connection is refused
- **THEN** the result is `closed`

#### Scenario: No response before timeout
- **WHEN** the finite connection timeout expires
- **THEN** the result is `timeout`
- **AND** the result does not assert that the host is absent or the port is filtered

### Requirement: Bounded work across scans
Active connections SHALL obey both the per-scan and application-wide limits.
Scheduling SHALL not materialize the full host/port Cartesian product and SHALL
allow competing scans to make progress while capacity is available.

#### Scenario: Concurrent scans
- **WHEN** multiple scans have pending probes
- **THEN** active connections never exceed the global limit or any per-scan limit
- **AND** each pending scan can receive available capacity

### Requirement: Cleanup on every terminal path
Connections and reserved capacity SHALL be released after success, failure,
cancellation, deadline expiry or scan owner/recipient death.

#### Scenario: Cancellation during active probing
- **WHEN** an active scan is cancelled
- **THEN** its remaining work stops and in-flight sockets are closed
- **AND** other scans can use its released capacity
