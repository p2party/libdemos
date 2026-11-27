#!/usr/bin/env bash
# Build an amd64 Linux verifier whose crypto implementation travels with it.
set -euo pipefail
out=${1:?usage: ledger/build-linux-verifier.sh OUTPUT_DIRECTORY}
src=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$out"
out=$(cd "$out" && pwd)
test "$(uname -s)/$(uname -m)" = Linux/x86_64
pkg-config --atleast-version=3.5 libcrypto
export OPENSSL_CONF=/dev/null
export OPENSSL_MODULES=/nonexistent
flags=(-std=c17 -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3 -fPIE -static-pie -Wl,-z,relro,-z,now "-I$src/../include")
read -r -a libraries <<< "$(pkg-config --static --libs libcrypto libsodium)"
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
cc "${flags[@]}" "$src/transfer.c" "$src/transfer_test.c" "${libraries[@]}" -o "$build/tests"
"$build/tests"
cc "${flags[@]}" "$src/transfer.c" "$src/verify_cli.c" "${libraries[@]}" -o "$build/demos-ledger-verify"
strip --strip-unneeded "$build/demos-ledger-verify"
readelf -lW "$build/demos-ledger-verify" > "$build/program-headers"
readelf -dW "$build/demos-ledger-verify" > "$build/dynamic"
if grep -q INTERP "$build/program-headers" || grep -q NEEDED "$build/dynamic"; then
  echo 'The verifier requires a runtime loader or shared library' >&2
  exit 1
fi
test "$("$build/demos-ledger-verify" --version)" = demos-ledger-verify/1
if "$build/demos-ledger-verify" </dev/null; then exit 1; fi
install -m 0755 "$build/demos-ledger-verify" "$out/demos-ledger-verify"
(
  cd "$out"
  sha256sum demos-ledger-verify > SHA256SUMS
  sha256sum -c SHA256SUMS
)
{
  git -C "$src" rev-parse HEAD
  dpkg-query -W libssl-dev libsodium-dev libc6-dev gcc
} > "$out/build.txt"
