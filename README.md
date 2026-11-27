# @ondemos/libdemos

This repository provides cryptographic tools for digital democracies.

Other than the compilation as a static or shared lib, it also compiles for WASM and use in the browser. 

The code has not undergone any external security audits yet. Use at your own risk.

## Native P2Party testnet transfers

The optional C17 ledger library verifies native transfers for P2Party Testnet 1. Its genesis permits ML-DSA-65 and the stateless hash-based SLH-DSA-SHA2-192s. A separate genesis can also authorize ML-DSA-87 and SLH-DSA-SHAKE-256s. A transfer signs the network ID, input unit, weight, expiry and full recipient commitment. The node atomically consumes that input and records a receipt. Existing voting and secret-sharing APIs retain their original formats.

Build the ledger module with CMake, OpenSSL 3.5 or newer and libsodium. The Linux packaging job runs the native transfer tests and publishes a statically linked verifier with its SHA-256 and source revision. The public development network uses valueless test units. Its first grant funded one unit that the native verifier accepted with ML-DSA-65 at height 2 and SLH-DSA-SHA2-192s at height 3. [Verifier format and build instructions](ledger/README.md) · [Testnet access and grants](https://github.com/p2party/p2party-js/blob/master/docs/testnet-1.md) · [Release changes and roadmap](CHANGELOG.md)

The development branch also includes an offline SHA-512 receipt log. Given a trusted checkpoint, a client can verify that a move appears at a specific position or that a newer receipt history extends an earlier one. The C API and command-line tool use the tree shape and proofs from RFC 9162. [Receipt log format and examples](ledger/README.md#offline-receipt-log)

## Introduction

This library relies heavily on Ed25519 public-secret key pairs and their related operations, which are provided by [libsodium](https://github.com/jedisct1/libsodium), which is a battle-tested project.

In the  [src](src) folder, there are the functions that enable private liquid democracy according to [this paper](https://arxiv.org/pdf/2302.14421). There is an example in the __tests__ folder.

It also has [Shamir secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) functionality, where a user can split and restore a secret through the Shamir threshold sharing scheme. 

The library also has mnemonic generation, validation and Ed25519 key pair from mnemonic functionality that was inspired by [bip39](https://github.com/bitcoinjs/bip39) but instead of Blake2b we use Argon2 and instead of SHA256 we use SHA512, both of which can be found in libsodium.

Finally, you can calculate [Merkle roots](https://en.wikipedia.org/wiki/Merkle_tree), proofs and validate proofs from trees. 

## Files

The [chacha20poly1305](src/chacha20poly1305) directory contains symmetric and asymmetric key encryption functions. The 
schema is AEAD and the IETF implementation. The Ed25519 keys are converted to x25519 for key agreement.

The [merkle](src/merkle) directory contains a Merkle root getter function, a Merkle
proof artifacts getter, a root from proof getter and a proof verification function.

The [shamir](src/shamir) directory contains a Shamir secret split and restoration of a Uint8Array secret.
Under the hood it uses the libsodium randombytes method to generate random coefficients for the polynomial.

The [utils](src/utils) directory contains helper methods such as cryptographic random slicing of arrays etc.

## Getting Started

To get started you need to have CMake, LLVM/Clang and [emsdk](https://github.com/emscripten-core/emsdk) installed on your machine and in your path.
You also need to clone this repository and [libsodium](https://github.com/jedisct1/libsodium) as a submodule in order to be able to compile the library

```
git clone https://github.com/p2party/libdemos.git
cd libdemos
git submodule update --init --recursive
source ./build.sh
```

Linux CI runs four native test executables covering commitments, Shamir sharing, cryptography and Merkle proofs. The ledger module also has its own transfer and command-line tests. [Native tests](__tests__) · [Ledger tests](ledger/transfer_test.c)

A local coverage-guided fuzz test compiles the transfer verifier with AddressSanitizer and UndefinedBehaviorSanitizer and exercises both signature suites. [Run the fuzzer](ledger/README.md#fuzz-the-transfer-verifier)

## License

The source code is licensed under the terms of the Affero General Public License version 3.0 (see [LICENSE](LICENSE)).

## Copyright

Copyright (C) 2024 Deliberative Technologies P.C.
