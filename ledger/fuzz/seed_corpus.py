"""Verify two synthetic spends and save their input states and signed bytes."""

import json
import subprocess
import sys
from pathlib import Path


def seed_corpus(directory, verifier, fixture):
    def decode(field):
        return bytes.fromhex(fixture[field].removeprefix("0x"))

    directory.mkdir(parents=True, exist_ok=True)
    unit_id = decode("inputId")
    owner = decode("commitment")
    suite = decode("first")[114]
    names = {1: "ml-dsa", 2: "slh-dsa", 3: "ml-dsa-87", 4: "slh-dsa-shake-256s"}
    for field in ["first", "second"]:
        wire = decode(field)
        # Verify each transition with only its two required permission bits.
        masks = bytes([1 << (suite - 1), 1 << (wire[115] - 1)])
        prefix = b"DLV1" + decode("chainId") + masks + (1).to_bytes(8, "big")
        request = prefix + unit_id + (8).to_bytes(8, "big") + bytes([suite]) + owner + wire
        result = subprocess.run([verifier], input=request, stdout=subprocess.PIPE, check=True)
        reply = result.stdout
        if len(reply) != 193:
            raise ValueError("unexpected verifier reply size")
        (directory / names[suite]).write_bytes(unit_id + owner + bytes([suite]) + wire)
        unit_id, suite, owner = reply[64:128], reply[128], reply[129:]


if __name__ == "__main__":
    seed_corpus(Path(sys.argv[1]), sys.argv[2], json.load(sys.stdin))
