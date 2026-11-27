# Native transfer verifier

Build with `cmake -S ledger -B build/ledger`, `cmake --build build/ledger`, and `ctest --test-dir build/ledger`. The library uses OpenSSL 3.5 or later and libsodium. `demos-ledger-verify --version` returns `demos-ledger-verify/1`. With no arguments the executable reads one binary request to end-of-file and writes a 193-byte reply on success. Exit 1 means the input or transfer was rejected. Exit 2 indicates an invocation or I/O failure. Each process handles one transfer.

All integers use big-endian byte order. The following fields precede the exact native signed transfer bytes, which must be 5,505 bytes for ML-DSA-65 or 16,516 bytes for SLH-DSA-SHA2-192s.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DLV1` |
| 4 | 32 | Ledger ID from trusted node configuration |
| 36 | 1 | Permitted input suites, bitmask 1–3 |
| 37 | 1 | Permitted output suites, bitmask 1–3 |
| 38 | 8 | Proposed inclusion height |
| 46 | 64 | Input ID from stored unspent unit |
| 110 | 8 | Stored input weight |
| 118 | 1 | Stored input signature suite |
| 119 | 64 | Stored input owner commitment |
| 183 | variable | Complete signed transfer |

The reply carries the 64-byte move ID, 64-byte new unit ID, one-byte recipient suite and 64-byte recipient commitment in that order. The original unit weight carries forward. The executable verifies the input with `demos_ledger_apply_transfer_id` and emits no state on refusal. The caller authenticates the input state, chooses the height, enforces lifetime commitment uniqueness and commits the spend and log entry atomically. Unit IDs, commitments and native move IDs are 64 bytes.

`demos-ledger-fixture` is generated only for test builds. It emits JSON containing newly signed synthetic transfers and their public commitments, including competing spends at the maximum denomination. The ephemeral signing keys stay in that process.
