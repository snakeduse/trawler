# Project Foundation

## Purpose

Provide a buildable OTP 27 application and CLI foundation with reproducible tools,
isolated Hermes configuration and a validated specification-driven development workflow.

## Requirements

### Requirement: Embeddable application lifecycle
Trawler SHALL start and stop as a standard OTP application using kernel and stdlib,
and SHALL expose a supervised application root without requiring development tools.

#### Scenario: An Erlang consumer starts the dependency
- **WHEN** a consumer calls `application:ensure_all_started(trawler)`
- **THEN** the application starts and `trawler_sup` is registered
- **AND** stopping trawler terminates its supervision tree

### Requirement: Foundation CLI
The escript SHALL provide help and its application version, and SHALL return a
nonzero exit code for unsupported arguments without claiming a scan took place.

#### Scenario: Help is requested
- **WHEN** the user runs `trawler --help`
- **THEN** usage is printed and the process exits with code 0

#### Scenario: Version is requested
- **WHEN** the user runs `trawler --version`
- **THEN** the application version is printed and the process exits with code 0

#### Scenario: Unsupported arguments are supplied
- **WHEN** an unknown command or unsupported option is passed to the foundation CLI
- **THEN** the process exits with code 2 and prints a diagnostic to stderr

### Requirement: Reproducible development workflow
Project wrappers SHALL use OTP 27 and globally installed OpenSpec 1.14.1 under
Node 24.15.0. The required check command SHALL compile, run EUnit and Common Test,
run Xref and Dialyzer, and strictly validate current specs and pending changes.

#### Scenario: Required checks run
- **WHEN** a developer runs `make check` with the pinned tools installed
- **THEN** each required verification runs and a failure yields a nonzero exit code

### Requirement: Project-isolated model orchestration
The project Hermes launcher SHALL select Pro as the main model and Flash as the
implementation model, isolate state under the ignored runtime directory, and load
project OpenSpec skills without modifying the default Hermes profile.

#### Scenario: A development request enters the automatic workflow
- **WHEN** the user requests a behaviour change
- **THEN** Pro prepares and validates the OpenSpec artifacts before delegating to Flash
- **AND** a separate Flash command is not required

#### Scenario: Only project preparation is requested
- **WHEN** the user requests only a scaffold or specifications
- **THEN** future implementation tasks remain unchecked and are not applied automatically

#### Scenario: Existing credentials are reused
- **WHEN** a DeepSeek key is available in the process environment, runtime env file or user Hermes env file
- **THEN** only that credential is provided to the launched project process
- **AND** its value is neither printed nor added to tracked configuration
