# Scan CLI

## Purpose

Allow command-line users to select hosts and ports and consume text or JSON
results through the same scanning core used by embedded Erlang applications.

## ADDED Requirements

### Requirement: Shared-core scan command
The CLI SHALL provide `trawler scan` with required `--targets` and `--ports`
arguments, optional timeout/concurrency controls and `--json` output selection.
It SHALL use the public Erlang API and the same validation and outcome semantics.

#### Scenario: A CLI scan matches library behaviour
- **WHEN** equivalent target, port and option selections are passed to CLI and library
- **THEN** both expose equivalent connection observations

### Requirement: Result formatting
Text output SHALL show IP, port and state plus summary counters. JSON output SHALL
be a single valid object containing `results` and `summary`, with dotted-decimal
IP strings and string states. Diagnostics SHALL be written to stderr.

#### Scenario: JSON output is requested
- **WHEN** the user runs a completed scan with `--json`
- **THEN** stdout parses as a single JSON object with all observed results and summary
- **AND** stdout contains no progress or diagnostic text

### Requirement: Completion and error exit statuses
The CLI SHALL exit 0 for completed scans regardless of whether an open port was
found, 2 for invalid arguments and 1 for operational failures.

#### Scenario: No ports are open
- **WHEN** a scan completes with closed ports only
- **THEN** its exit status is 0

#### Scenario: Arguments are invalid
- **WHEN** required arguments are missing or selections are invalid
- **THEN** the CLI exits 2 with a diagnostic and does not start a scan
