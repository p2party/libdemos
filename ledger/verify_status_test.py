"""Exercise the packaged verifier with a valid transfer under two OpenSSL configurations."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main(verifier, generator):
    fixture = json.loads(subprocess.check_output([generator], timeout=30))
    def value(name):
        return bytes.fromhex(fixture[name].removeprefix("0x"))

    prefix = b"DLV1" + value("chainId") + bytes([3, 3]) + (1).to_bytes(8, "big")
    request = (prefix + value("inputId") + (8).to_bytes(8, "big")
               + bytes([1]) + value("commitment") + value("first"))
    with tempfile.TemporaryDirectory() as directory:
        config = Path(directory) / "openssl.cnf"
        config.write_text("openssl_conf=init\n[init]\nproviders=providers\n"
                          "[providers]\nnull=empty\n[empty]\nactivate=1\n")
        def check(payload, expected, size, env=None):
            result = subprocess.run([verifier], input=payload, capture_output=True,
                                    env=env, timeout=5)
            if result.returncode != expected or len(result.stdout) != size:
                raise AssertionError(f"expected status {expected} and {size} reply bytes, "
                                     f"got {result.returncode} and {len(result.stdout)}")

        check(request, 0, 193)
        check(request, 2, 0, {**os.environ, "OPENSSL_CONF": str(config)})
        check(request[:-1] + bytes([request[-1] ^ 1]), 1, 0)


if __name__ == "__main__":
    main(*sys.argv[1:])
