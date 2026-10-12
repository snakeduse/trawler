# Trawler agent instructions

## Purpose and current state

Trawler is an embeddable Erlang/OTP 27 application with a separate escript CLI.
The repository currently implements the application lifecycle and CLI help/version.
The scanner is specified in the pending `add-tcp-ipv4-scanner` OpenSpec change.
Do not claim that scanning works until that change is implemented and verified.
User-facing discussion and the README are in Russian; code and OpenSpec artifacts
use English. Preserve the Apache-2.0 license.

## Development commands

- `make build` — strict compilation.
- `make cli` — create `_build/default/bin/trawler`.
- `make test` — EUnit and Common Test, including escript checks.
- `make xref`, `make dialyzer` — static checks.
- `make specs` — strict validation of all changes and current specs.
- `make consumer` — build and run a separate temporary OTP consumer.
- `make check` — all required checks.
- `make docs`, `make shell` — EDoc and an OTP shell.
- `./scripts/openspec ...` — global OpenSpec 1.14.1 under Node 24.15.0.
- `./scripts/hermes chat` — project-isolated Hermes session.

Wrappers activate OTP 27 and the pinned Node installation. Erlang is installed
through Kerl at `$HOME/erlang/27.3.4.18` on this machine; use `TRAWLER_OTP_ROOT`
for another location. The library build must not require Node, OpenSpec or Hermes.

## Erlang/OTP conventions

Use OTP behaviours and supervised processes; document public types with `-spec`.
Keep CLI parsing, printing and VM termination in `trawler_cli`, outside the library.
Keep runtime dependencies minimal; use OTP 27's standard library where suitable.
Never create atoms from user input. Parse and validate all target/port input before
network activity. Use monotonic time for durations and deadlines.
Bound concurrent connections across scans, generate probe work lazily, and clean
up sockets, monitors and timers on completion, failure, cancellation or owner exit.
A TCP timeout does not establish that a host is absent. Do not overstate discovery
or firewall classification. Tests use loopback fixtures, not external networks.

## Automatic OpenSpec workflow and model roles

The project launcher selects `deepseek-v4-pro` as the primary Hermes agent and
`deepseek-flash` for `delegate_task` children, both through provider `deepseek`.
Pro owns requirements, proposal/design/spec/tasks, task assignment and final review.
Flash implements bounded code and test tasks. A child does not delegate further.

The user's explicit standing policy is a continuous plan-to-implementation cycle
for development requests. OpenSpec's generated `openspec-propose` skill is a
planning-only workflow and tells agents to wait for a new apply request. For the
automatic cycle, generate artifacts using the CLI (`new change`, `status`,
`instructions`) and continue to delegation under the original development request.
Do not introduce that skill's extra approval stage. An explicit request to run
`openspec-propose` or prepare specifications alone remains planning-only.

For a user request to develop or change behaviour:

1. Read the applicable current specs and relevant code. Discover active changes
   with `./scripts/openspec list`; use the workflow skills appropriate to the scope.
2. Pro creates or updates decision-complete OpenSpec artifacts, respecting the
   user's scope. Validate them with `make specs` before implementation.
3. Pro automatically delegates implementation to Flash; no separate command or
   routine approval is needed. Pass the workspace, change name, exact tasks,
   interfaces, constraints and acceptance checks in the child's context. Fresh
   children do not have the parent conversation.
4. Run at most one child at a time in the shared checkout. Wait for its result;
   inspect the diff and independently run the relevant checks. Return concrete
   corrections to Flash instead of silently changing its model.
5. Mark only verified tasks complete. After all work and `make check` pass, archive
   the completed change using OpenSpec's archive workflow, updating current specs.
   Report what changed, validation and any remaining limitations.

For requests limited to planning, documentation or project preparation, complete
that scope and leave future implementation tasks unchecked. Do not apply a pending
scanner change merely because it exists. Ask only about material ambiguity or a
genuinely required permission; do not add a separate Flash approval stage.

## Configuration and secrets

`.hermes/config.yaml` is the versioned source of truth. The launcher materializes
it under `.hermes/runtime/`, the ignored `HERMES_HOME`, and connects the project
OpenSpec skills using `skills.external_dirs`. Edit the source config, not the
generated runtime copy. Sessions, memory, logs and checkpoints are local state.
Use `DEEPSEEK_API_KEY` from the process environment, the ignored runtime `.env`,
or the existing user Hermes `.env`. Never print or commit credentials, copy all
user configuration, or enable an alternative model as a silent fallback.

Do not commit, push or publish artifacts unless the user requests it.
