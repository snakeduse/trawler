# Scan API

## Purpose

Expose the same reusable scanning capability to Erlang consumers through
asynchronous events, synchronous collection, progress inspection and cancellation.

## ADDED Requirements

### Requirement: Asynchronous scan lifecycle
The public API SHALL provide `start_scan/3`, returning a scan reference or a tagged
error, and SHALL stream result events to the selected local recipient process.
Each scan SHALL produce exactly one terminal event after resource cleanup and
SHALL emit no later results.

#### Scenario: An asynchronous scan completes
- **WHEN** a valid scan starts and all probes finish
- **THEN** the recipient receives result events and one done event with counters
- **AND** asynchronous storage retains counters rather than a complete result list

#### Scenario: The application is not started
- **WHEN** a caller invokes the scanning API while trawler is stopped
- **THEN** it receives `{error, not_started}`

### Requirement: Synchronous scan collection
The API SHALL provide `scan/3`, collecting the same observations and returning
results sorted by numeric IPv4 address and port. It SHALL leave unrelated caller
messages untouched and SHALL return an error rather than successful partial data
when its deadline expires.

#### Scenario: Both APIs observe the same listener
- **WHEN** equivalent requests use synchronous and asynchronous APIs
- **THEN** they report equivalent address/port outcomes
- **AND** unrelated messages remain available in the synchronous caller's mailbox

### Requirement: Status and cancellation
The API SHALL provide `status/1` and `cancel/1`, expose state and counters, allow
idempotent cancellation of active/cancelled scans, and return documented errors
for unknown references or already completed scans. Terminal status SHALL remain
available for 60 seconds before expiry.

#### Scenario: Progress is inspected
- **WHEN** a caller requests status during execution
- **THEN** state and total/completed counters reflect the scan's progress

#### Scenario: An unknown reference is used
- **WHEN** status or cancellation receives an unknown or expired scan reference
- **THEN** it returns `{error, not_found}`

#### Scenario: Scan ownership ends
- **WHEN** the caller or recipient exits during execution
- **THEN** the scan stops and releases its resources
