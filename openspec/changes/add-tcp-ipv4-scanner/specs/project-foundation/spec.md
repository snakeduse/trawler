# Project Foundation Delta

## MODIFIED Requirements

### Requirement: Foundation CLI
The escript SHALL provide help and its application version, support the scan
command through the public scanning API, and return a nonzero exit code for
unsupported or invalid arguments.

#### Scenario: Help is requested
- **WHEN** the user runs `trawler --help`
- **THEN** usage including scanning options is printed and the process exits with code 0

#### Scenario: Version is requested
- **WHEN** the user runs `trawler --version`
- **THEN** the application version is printed and the process exits with code 0

#### Scenario: A valid scan is requested
- **WHEN** valid arguments are passed to the scan command
- **THEN** the shared scanning API is invoked and its observations are formatted

#### Scenario: Unsupported arguments are supplied
- **WHEN** an unknown command or invalid option is supplied
- **THEN** the process exits with code 2 and prints a diagnostic to stderr
