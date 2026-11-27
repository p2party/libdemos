"""Verify two synthetic spends and save their input states and signed bytes."""

import json
import subprocess
import sys
from pathlib import Path


def seed_corpus(directory, verifier, fixture):
    def decode(field):
        return bytes.fromhex(fixture[field].removeprefix("0x"))

    directory.mkdir(parents=True, exist_ok=True)
    # Versioned verifier request with both suite masks, height 1 and weight 8.
    prefix = b"DLV1" + decode("chainId") + bytes([3, 3]) + (1).to_bytes(8, "big")
    unit_id = decode("inputId")
    owner = decode("commitment")
    suite = 1
    for name, field in [("ml-dsa", "first"), ("slh-dsa", "second")]:
        wire = decode(field)
        request = prefix + unit_id + (8).to_bytes(8, "big") + bytes([suite]) + owner + wire
        result = subprocess.run([verifier], input=request, stdout=subprocess.PIPE, check=True)
        reply = result.stdout
        if len(reply) != 193:
            raise ValueError("unexpected verifier reply size")
        (directory / name).write_bytes(unit_id + owner + bytes([suite]) + wire)
        unit_id, suite, owner = reply[64:128], reply[128], reply[129:]


if __name__ == "__main__":
    seed_corpus(Path(sys.argv[1]), sys.argv[2], json.load(sys.stdin))
