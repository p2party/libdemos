# Release changes

## November 27, 2026

- The native transfer verifier reports an unavailable signature provider as a local failure (exit 2). Validators can retry the original request when the provider recovers. An invalid signature still returns exit 1. [Verifier contract](ledger/README.md)

- Fixed signature verification for a voting commitment proof. A proof now has to authenticate the current commitment. The original voting API uses Ed25519. [Fix](https://github.com/ondemos/libdemos/commit/e116d43)
- Added a separate native transfer format with independently selectable ML-DSA-65 and SLH-DSA-SHA2-192s ownership. Per-ledger masks select the permitted spend and receive suites. The exact encodings are 5,505 and 16,516 bytes respectively. The signed body binds the recipient and network to the spend. [C API](include/demos_ledger.h) · [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) · [SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- Exposed the verifier as a bounded executable that checks one transfer at a time. It returns the authenticated move ID and output unit. The node must establish ordering, reject reused commitments and commit state atomically. A retry of an identical signed message can refer to its original receipt. [Verifier wire format](ledger/README.md) · [Testnet guide](https://github.com/p2party/p2party-js/blob/master/docs/testnet-1.md)
- Restored Linux CI for the four existing native suites. A second job tests the ledger and packages a static amd64 executable with the crypto libraries used to build it. The initial testnet verifier has SHA-256 `f8f06cf56f5409a7c6071eaa7131f93b729431f4bbf72091e7a2bacdc306027b`. [Native CI](https://github.com/ondemos/libdemos/actions/runs/45985760412) · [Verifier build](https://github.com/ondemos/libdemos/actions/runs/45985760486)
- Confirmed both transfer suites on the public testnet. Ethers submitted the ML-DSA-65 spend at height 2, and viem submitted the SLH-DSA-SHA2-192s spend at height 3. Retrying each signed transfer recovered the same receipt. [Public verification instructions](https://github.com/p2party/p2party-js/blob/master/docs/testnet-1.md)
- Added opt-in local native transfer fuzzing under AddressSanitizer and UndefinedBehaviorSanitizer. [Run the fuzzer](ledger/README.md#fuzz-the-transfer-verifier)

## Roadmap

Testnet 1 uses one validating node, fixed genesis issuance and whole-unit transfers. Public testing covers cross-suite transfers, receipt recovery and double spends. Further work includes independently operated validators and proof-of-stake ordering, suite retirement and key recovery, denomination splitting and joining, and review before a monetary network is proposed. The separate voting-ledger design also requires delegation and reclaim rules. [Testnet roadmap](https://github.com/p2party/p2party-js/blob/master/docs/testnet-1.md)
