# Target Selection

## Purpose

Define predictable IPv4 host and TCP port selections that callers can compose,
validate and deduplicate before starting network operations.

## ADDED Requirements

### Requirement: IPv4 selections
The scanner SHALL accept single IPv4 addresses, lists, inclusive full-address
ranges and CIDR selections through the documented Erlang and CLI input forms.
It SHALL normalize CIDR host bits, include all addresses in the subnet and probe
each selected address/port pair at most once.

#### Scenario: Mixed overlapping targets
- **WHEN** a caller combines individual addresses, ranges and overlapping CIDR blocks
- **THEN** each unique selected IPv4 address is represented exactly once

#### Scenario: CIDR boundaries
- **WHEN** a caller selects `192.0.2.5/30`
- **THEN** addresses `192.0.2.4` through `192.0.2.7` are included
- **AND** `/32` selects exactly one address

### Requirement: Port selections
The scanner SHALL accept individual TCP ports, lists and inclusive ranges in
1..65535, deduplicating overlaps and rejecting zero or invalid range bounds.

#### Scenario: Mixed port inputs
- **WHEN** a caller selects `22,80,80-82`
- **THEN** selected ports are exactly 22, 80, 81 and 82

### Requirement: Validation before probing
Malformed, empty, descending, non-IPv4 or excessive host selections SHALL produce
an input error before any connection is attempted. Large selections SHALL be
checked against the configured maximum host count before address expansion.

#### Scenario: Invalid selection
- **WHEN** an input contains an invalid octet, CIDR prefix, empty token or reversed range
- **THEN** the request is rejected and no TCP connections are attempted

#### Scenario: Excessive host count
- **WHEN** a normalized selection exceeds the configured `max_hosts`
- **THEN** the request returns `too_many_hosts` without expanding the full address space
