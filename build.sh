#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
cmake -S . -B build
cmake --build build --parallel --target demos demos_static commit_test shamir_test crypto_test merkle_test
for suite in commit shamir crypto merkle; do
  "./build/__tests__/${suite}_test"
done
