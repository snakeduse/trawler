## 1. Selection normalization

- [ ] 1.1 Implement documented target/port input contracts, validation and deduplication with public types.
- [ ] 1.2 Add EUnit cases for individual/list/range/CIDR inputs, boundaries, host-bit normalization, overlap, empty/malformed/descending selections and excessive host counts.

## 2. Supervised TCP execution

- [ ] 2.1 Add the bounded global scheduler, lazy job generation and temporary scan/worker supervision.
- [ ] 2.2 Implement finite-timeout connect probing and the documented observation classification.
- [ ] 2.3 Verify per-scan/global limits and cleanup on success, worker failure, cancellation, deadline and owner/recipient death.

## 3. Public Erlang API

- [ ] 3.1 Implement start_scan/3, status/1 and cancel/1, recipient events, exactly one terminal event and terminal status expiry.
- [ ] 3.2 Implement scan/3 with an isolated synchronous collector and deterministic result order.
- [ ] 3.3 Add loopback Common Test scenarios for open/closed ports, concurrent scans, cancellation, lifecycle failures and consumer integration; inject timeout outcomes deterministically.

## 4. CLI adapter

- [ ] 4.1 Add scan arguments, API delegation, text/JSON output and documented exit statuses.
- [ ] 4.2 Test CLI parity with the library, JSON validity, diagnostics, invalid inputs and preserved help/version behavior.

## 5. Review and completion

- [ ] 5.1 Update README and EDoc with working examples and resource/result limitations.
- [ ] 5.2 Pro reviews the diff and independently runs make check and an external Erlang-consumer smoke test.
- [ ] 5.3 Confirm that the implementation satisfies every delta scenario and is ready for promotion.

After all tasks are verified, archive the change using the OpenSpec workflow and
validate the promoted current specs.
