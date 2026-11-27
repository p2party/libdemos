"""Reference state tree, adversarial encodings and signed native transfers."""
from hashlib import sha512
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest

CLI, VERIFY, FIXTURE, LOG = sys.argv[1:5]
del sys.argv[1:5]
NAMES = ("spent", "move", "owner")


def tag(name, value):
    return sha512(bytes([len(name)]) + name.encode("ascii") + value).digest()


def parent(a, b):
    return tag("smt/node", a + b)


EMPTY = [tag("smt/empty", b"")]
for _ in range(512):
    EMPTY.append(parent(EMPTY[-1], EMPTY[-1]))


def hexid(v):
    return "0x" + v.hex()


def identifier(kind, value):
    return tag("smt/" + kind, value)


def run(exe, args, data=b"", ok=True):
    p = subprocess.run([exe, *args], input=data, capture_output=True, check=False)
    if (p.returncode == 0) != ok:
        raise AssertionError((args, p.returncode, p.stdout[:32], p.stderr[:256]))
    return p.stdout


def entries(claims):
    return "".join(f"{kind} {hexid(v)}\n" for kind, v in claims).encode("ascii")


def native_root(claims):
    return bytes.fromhex(run(CLI, ["root", "-"], entries(claims)).decode().strip()[2:])


def layers(claims):
    level = {}
    for kind, v in claims:
        key = identifier(kind, v)
        level[int.from_bytes(key, "big")] = tag("smt/leaf", key)
    result = [level]
    for i in range(512):
        empty = EMPTY[i]
        level = {p: parent(level.get(p * 2, empty), level.get(p * 2 + 1, empty))
                 for p in {c // 2 for c in level}}
        result.append(level)
    return result


def proof_for(levels, kind, v):
    index = int.from_bytes(identifier(kind, v), "big")
    present = index in levels[0]
    bitmap = bytearray(64)
    siblings = []
    for level in range(512):
        sibling = levels[level].get(index ^ 1)
        if sibling is not None:
            depth = 511 - level
            bitmap[depth // 8] |= 128 >> (depth % 8)
            siblings.append(sibling)
        index >>= 1
    return b"DSS1" + bytes([1 + NAMES.index(kind), present]) + v + bitmap + b"".join(reversed(siblings))


class StateTree(unittest.TestCase):
    def test_reference_shapes_and_input_order(self):
        claims = [(name, sha512(f"record {i}".encode()).digest())
                  for i in range(8) for name in NAMES]
        for size in (0, 1, 2, 3, 6, 13, 24):
            sample = claims[:size]
            levels = layers(sample)
            root = levels[-1].get(0, EMPTY[-1])
            self.assertEqual(native_root(sample), root)
            self.assertEqual(native_root(sample[::-1]), root)
            for k, v in (claims[0], claims[2], claims[4], claims[-1], ("spent", bytes(64))):
                args = [k, hexid(v)]
                proof = run(CLI, ["prove", "-", *args], entries(sample))
                self.assertEqual(proof, proof_for(levels, k, v))
                member = (k, v) in sample
                expected = "present" if member else "absent"
                self.assertEqual(run(CLI, ["verify", hexid(root), *args, expected, "-"], proof), b"ok\n")
                if not member:
                    nxt = run(CLI, ["insert-root", hexid(root), *args, "-"], proof)
                    self.assertEqual(nxt.decode().strip(), hexid(native_root([*sample, (k, v)])))

    def test_strict_formats(self):
        value = bytes(range(64))
        line = entries([("owner", value)])
        for bad in (line * 2, line[:-1], line[:-1] + b"\r\n", b"\n",
                    line.replace(b"owner", b"Owner"), line.replace(b" 0x", b"  0x"),
                    line.replace(b"01", b"0F"), line + b"x\0\n"):
            run(CLI, ["root", "-"], bad, False)
        query = ("spent", value)
        sample = [("owner", value)]
        root = hexid(native_root(sample))
        proof = run(CLI, ["prove", "-", query[0], hexid(value)], line)
        check = ["verify", root, query[0], hexid(value), "absent", "-"]
        for i in (0, 4, 5, 6, 69, 70, len(proof) - 1):
            altered = bytearray(proof)
            altered[i] ^= 1
            run(CLI, check, altered, False)
        for bad in (proof[:-1], proof + b"x", proof + bytes(64), b""):
            run(CLI, check, bad, False)
        run(CLI, ["verify", root, "move", hexid(value), "absent", "-"], proof, False)
        run(CLI, ["verify", root, "spent", hexid(value), "present", "-"], proof, False)
        run(CLI, ["verify", hexid(EMPTY[-1]), *check[2:]], proof, False)
        # A redundant explicit default hash reconstructs the same root but is invalid.
        blank = bytearray(proof_for(layers([]), *query))
        blank[70] = 128
        run(CLI, ["verify", hexid(EMPTY[-1]), *check[2:]], blank + EMPTY[511], False)

    def test_full_width_path(self):
        # Synthetic trusted root exercises depth 511 and every bitmap byte.
        v = b"v" * 64
        key = identifier("move", v)
        idx = int.from_bytes(key, "big")
        siblings = [sha512(i.to_bytes(2, "big")).digest() for i in range(512)]
        value, inserted = EMPTY[0], tag("smt/leaf", key)
        for i, s in enumerate(reversed(siblings)):
            if (idx >> i) & 1:
                value, inserted = parent(s, value), parent(s, inserted)
            else:
                value, inserted = parent(value, s), parent(inserted, s)
        p = b"DSS1\x02\x00" + v + b"\xff" * 64 + b"".join(siblings)
        q = ["move", hexid(v)]
        self.assertEqual(run(CLI, ["verify", hexid(value), *q, "absent", "-"], p), b"ok\n")
        self.assertEqual(run(CLI, ["insert-root", hexid(value), *q, "-"], p).decode().strip(), hexid(inserted))
        run(CLI, ["verify", hexid(value), *q, "absent", "-"], p + b"x", False)

    def test_real_native_transfers_and_owner_commitments(self):
        v = json.loads(run(FIXTURE, []))
        raw = lambda key: bytes.fromhex(v[key][2:])
        unit = raw("inputId")
        owner = raw("commitment")
        claims = [("owner", owner)]
        moves = []
        for height, field in enumerate(("first", "second"), 1):
            wire = raw(field)
            prefix = (b"DLV1" + raw("chainId") + b"\x03\x03" + height.to_bytes(8, "big")
                      + unit + wire[98:106] + wire[114:115] + owner)
            verified = run(VERIFY, [], prefix + wire)
            if height == 1:
                with tempfile.TemporaryDirectory() as d:
                    # Disable the local signature provider for a known-valid
                    # spend, while keeping the wire and ledger inputs identical.
                    cfg = Path(d, "openssl.cnf")
                    cfg.write_text("openssl_conf=init\n[init]\nproviders=providers\n"
                                   "[providers]\nnull=empty\n[empty]\nactivate=1\n")
                    failure = subprocess.run([VERIFY], input=prefix + wire, capture_output=True,
                                             env={**os.environ, "OPENSSL_CONF": str(cfg)})
                    self.assertEqual((failure.returncode, failure.stdout), (2, b""))
                invalid = bytearray(wire)
                invalid[-1] ^= 1
                rejected = subprocess.run([VERIFY], input=prefix + invalid, capture_output=True)
                self.assertEqual((rejected.returncode, rejected.stdout), (1, b""))
            move, output, recipient = verified[:64], verified[64:128], verified[129:]
            self.assertEqual(len(verified), 193)
            self.assertEqual(move, tag("move/id", wire))
            self.assertEqual(output, tag("unit/id", move + bytes(4)))
            self.assertEqual(recipient, wire[116:180])
            current = native_root(claims)
            for kind, key in (("spent", unit), ("move", move), ("owner", recipient)):
                proof = run(CLI, ["prove", "-", kind, hexid(key)], entries(claims))
                next_root = run(CLI, ["insert-root", hexid(current), kind, hexid(key), "-"], proof)
                claims.append((kind, key))
                current = bytes.fromhex(next_root.decode().strip()[2:])
                self.assertEqual(current, native_root(claims))
            unit, owner = output, recipient
            moves.append(move)
        records = "".join(hexid(m) + "\n" for m in moves).encode()
        root = run(LOG, ["root"], records).strip().decode()
        path = run(LOG, ["inclusion", "0x1"], records)
        self.assertEqual(run(LOG, ["verify-inclusion", "0x2", "0x1", hexid(moves[1]), root], path), b"ok\n")
        proof = run(CLI, ["prove", "-", "spent", hexid(unit)], entries(claims))
        self.assertEqual(run(CLI, ["verify", hexid(current), "spent", hexid(unit), "absent", "-"], proof), b"ok\n")
        self.assertEqual(current, layers(claims)[-1][0])
        previous_root = native_root(claims[:-3])
        run(CLI, ["verify", hexid(previous_root), "spent", hexid(unit), "absent", "-"], proof, False)


if __name__ == "__main__":
    unittest.main()
