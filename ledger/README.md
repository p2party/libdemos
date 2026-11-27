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

## Offline receipt log

`demos-ledger-log` reads receipt move IDs in ascending ledger height. Height 1 is index 0. Genesis contributes zero leaves. The leaf digest is `SHA512(0x00 || move_id)`, where `move_id` is the 64-byte binary native identifier. The digest of an internal node is `SHA512(0x01 || left || right)`. The empty root is SHA-512 of zero bytes. For an uneven tree, split at the largest power of two strictly smaller than its size. The existing voting Merkle functions have their own encoding. [RFC 9162 tree and proof construction](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1) · [C API](../include/demos_ledger_log.h)

IDs, roots and proof nodes use `0x` followed by 128 lowercase hex digits. On stdin and stdout each record ends with one LF. An empty file encodes zero records. Sizes and zero-based indices on the command line use unsigned 64-bit lowercase hex quantities such as `0x0` or `0x10`, with no leading zeroes. Inclusion and consistency proofs contain only the required sibling or subtree hashes in RFC order, beginning at the lowest level. The position and sizes determine orientation.

For an export containing three receipts, these commands calculate the root and create proofs for the third receipt and the prefix of length two.

```sh
build/ledger/demos-ledger-log root < receipt-ids.txt
build/ledger/demos-ledger-log inclusion 0x2 < receipt-ids.txt > third.proof
build/ledger/demos-ledger-log consistency 0x2 < receipt-ids.txt > extension.proof
```

Supply the expected move ID and the authenticated roots at heights two and three in the variables below. The verifier can run offline with only the proof and these public inputs.

```sh
build/ledger/demos-ledger-log verify-inclusion 0x3 0x2 "$MOVE_ID" "$ROOT_AT_3" < third.proof
build/ledger/demos-ledger-log verify-consistency 0x2 0x3 "$ROOT_AT_2" "$ROOT_AT_3" < extension.proof
```

Successful verification prints `ok`. Exit 1 rejects invalid input or a failed proof. Exit 2 reports an invocation, allocation or I/O failure. The local CLI accepts up to 1,048,576 receipts for proof generation. The C API uses an in-memory array and logarithmic stack space. Proof verification accepts any unsigned 64-bit size with up to 65 hashes. For equal sizes, consistency requires equal roots and an empty proof. For a zero-length prefix, the verifier checks the empty root and an empty proof. Every authenticated history contains that prefix.

A checkpoint authenticates a root and size for a particular chain and genesis. Inclusion establishes the position of the identified move. Consistency establishes that the earlier history is a prefix of the later one. Transfer validity requires replay of the ledger rules. Current spendability requires a trusted state or a state proof.

CTest runs C proof and boundary checks. With Python 3 installed at configure time it also compares the CLI with an independent SHA-512 implementation, including a 65-node proof for a tree of size `0xffffffffffffffff`. To fuzz generated proofs, configure the sanitizer build below, then run

```sh
cmake --build build/fuzz --target ledger_log_fuzz
build/fuzz/ledger_log_fuzz -max_len=256 -max_total_time=30
```

## Fuzz the transfer verifier

Use Clang with libFuzzer and its sanitizer runtimes, CMake, Python 3.9 or later, OpenSSL 3.5 or later and libsodium. From the repository root, run

```sh
cmake -S ledger -B build/fuzz -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=RelWithDebInfo -DDEMOS_LEDGER_FUZZ=ON
cmake --build build/fuzz --parallel --target ledger_transfer_fuzz demos-ledger-fixture demos-ledger-verify ledger_transfer_test
build/fuzz/ledger_transfer_test
build/fuzz/demos-ledger-fixture | python3 ledger/fuzz/seed_corpus.py build/fuzz/corpus build/fuzz/demos-ledger-verify
build/fuzz/ledger_transfer_fuzz -max_len=16646 -max_total_time=45 build/fuzz/corpus
```

The fixture generates a signed spend for each suite with ephemeral local keys. LibFuzzer mutates the public input state and signed bytes, including their lengths. On rejection the input unit must stay intact. On acceptance its weight must be conserved, its owner and ID must change, and the same transfer must fail against the new state. ASan and UBSan instrument the verifier and harness. OpenSSL and libsodium use their installed builds.

The fuzzer is opt-in and runs locally. Keep the generated corpus for longer runs and adjust `-max_total_time` for the time available. The executable works offline after the build dependencies are installed.
