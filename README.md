# @ondemos/libdemos

This repository provides cryptographic tools for digital democracies.

This repository builds the native C voting library as a shared or static library. The TypeScript binding maintains the browser and Node WebAssembly build. [WebAssembly bindings](https://github.com/p2party/libdemos-ts)

The code has not undergone any external security audits yet. Use at your own risk.

## Native P2Party testnet transfers

The optional C17 ledger library verifies native transfers for P2Party Testnet 1. Owners can choose ML-DSA-65 or the stateless hash-based SLH-DSA-SHA2-192s. A transfer signs the network ID, input unit, weight, expiry and full recipient commitment. The node atomically consumes that input and records a receipt. Existing voting and secret-sharing APIs retain their original formats.

Build the ledger module with CMake, OpenSSL 3.5 or newer and libsodium. The Linux packaging job tests both suites and publishes a statically linked verifier with its SHA-256 and source revision. The public development network uses valueless test units. Its first grant funded one unit that the native verifier accepted with ML-DSA-65 at height 2 and SLH-DSA-SHA2-192s at height 3. [Verifier format and build instructions](ledger/README.md) · [Testnet access and grants](https://github.com/p2party/p2party-js/blob/master/docs/testnet-1.md) · [Release changes and roadmap](CHANGELOG.md)

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

## Using a native release

Version 0.2.8 provides shared and static libraries for Linux x86-64, macOS Intel, macOS Apple Silicon and Windows x86-64 with MinGW. Each archive includes the C header, the required libsodium headers, licenses and the exact source revisions in `BUILDINFO.txt`. The Windows archive also contains a DLL import library. [Release assets and SHA-256 checksums](https://github.com/p2party/libdemos/releases/tag/v0.2.8)

Download the archive for your platform and `SHA256SUMS` from the same release. On macOS or Linux, compare the archive's digest with the line for that filename. For example, on Linux run

```sh
sha256sum libdemos-0.2.8-linux-x86_64.tar.gz
tar -xzf libdemos-0.2.8-linux-x86_64.tar.gz
cc -std=c11 -Ilibdemos-0.2.8-linux-x86_64/include consumer.c \
  libdemos-0.2.8-linux-x86_64/lib/libdemos_static.a -lm -o consumer
./consumer
```

On macOS, `shasum -a 256` prints the digest. On Windows, use `Get-FileHash -Algorithm SHA256`. When statically linking with MinGW, compile the consumer with `-DDEMOS_PUBLIC=`. For dynamic linking on Windows, link to `libdemos.dll.a` and place `libdemos.dll` beside the executable or in its DLL search path. The consumer source calls SHA-512, generates a signing key, verifies a signature and rejects a changed signature. [Consumer example](scripts/native-consumer.c)

## Building from source

A recursive checkout includes the pinned libsodium source. To build and run the native C tests on macOS or Linux, install CMake 3.28.1 or later and a C toolchain, then run

```sh
git clone --recurse-submodules https://github.com/p2party/libdemos.git
cd libdemos
./build.sh
```

The release build also requires Ninja and Python 3.12 or later. From a clean checkout, run `python3 scripts/build-native-package.py dist`. Verify both packaged libraries from a separate consumer directory with `python3 scripts/check-native-package.py dist/*.tar.gz`. To check a downloaded release archive, pass `--checksums SHA256SUMS` to that same command. MinGW builds use GCC and G++. [Release workflow](.github/workflows/release.yml)

The four native suites cover commitments, Shamir sharing, cryptography and Merkle proofs. The optional ledger module has a separate verifier, release workflow and tests. [Native tests](__tests__) · [Ledger tests](ledger/transfer_test.c)

A local coverage-guided fuzz test compiles the transfer verifier with AddressSanitizer and UndefinedBehaviorSanitizer and exercises both signature suites. [Run the fuzzer](ledger/README.md#fuzz-the-transfer-verifier)

## License

The source code is licensed under the terms of the Affero General Public License version 3.0 (see [LICENSE](LICENSE)).

## Copyright

Copyright (C) 2024 Deliberative Technologies P.C.
