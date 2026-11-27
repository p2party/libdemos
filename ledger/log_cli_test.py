"""Independent SHA-512 vectors and wire checks for the offline receipt log."""
from functools import lru_cache
from hashlib import sha512
import subprocess
import sys
import unittest

BINARY = sys.argv.pop(1)
IDS = [i.to_bytes(64, "big") for i in range(65)]
EMPTY = sha512(b"").digest()


def leaf(value):
    return sha512(b"\x00" + value).digest()


def parent(left, right):
    return sha512(b"\x01" + left + right).digest()


def root(values):
    # Fold by layers, promoting an unpaired child without hashing it.
    nodes = list(map(leaf, values))
    while len(nodes) > 1:
        nodes = [parent(nodes[i], nodes[i + 1]) if i + 1 < len(nodes) else nodes[i]
                 for i in range(0, len(nodes), 2)]
    return nodes[0] if nodes else EMPTY


def hexhash(value):
    return "0x" + value.hex()


def records(values):
    return b"".join((hexhash(value) + "\n").encode("ascii") for value in values)


def split(n):
    return 1 << ((n - 1).bit_length() - 1)


def inclusion_ranges(start, size, index):
    if size == 1:
        return []
    k = split(size)
    if index < k:
        return inclusion_ranges(start, k, index) + [(start + k, size - k)]
    return inclusion_ranges(start + k, size - k, index - k) + [(start, k)]


def consistency_ranges(start, size, old, prefix_is_known=True):
    if size == old or old == 0:
        return [] if prefix_is_known else [(start, size)]
    k = split(size)
    if old <= k:
        return consistency_ranges(start, k, old, prefix_is_known) + [(start + k, size - k)]
    return consistency_ranges(start + k, size - k, old - k, False) + [(start, k)]


def prove(ranges):
    return records(root(IDS[start:start + size]) for start, size in ranges)


@lru_cache(maxsize=None)
def repeated_root(n):
    # Compute the root for n identical IDs without materializing the log.
    if n == 1:
        return leaf(IDS[0])
    k = split(n)
    return parent(repeated_root(k), repeated_root(n - k))


class LogTest(unittest.TestCase):
    def cli(self, *args, data=b"", expect=0):
        result = subprocess.run([BINARY, *args], input=data, capture_output=True, check=False)
        self.assertEqual(result.returncode, expect, (args, result.stderr))
        if expect:
            self.assertEqual(result.stdout, b"")
        return result.stdout

    def test_hashes_and_proof_siblings(self):
        self.assertEqual(root(IDS[:7]).hex(),
                         "834349c00831067ecf203f1aa0c485e91f2afae19e9bb74f89e49f4d649d6f87e"
                         "e923075cb7b86973f47f907a1273d1c1f46e371787cf08cdb2921377fc4bf4f")
        for n in (0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 31, 32, 33, 64, 65):
            data, checkpoint = records(IDS[:n]), root(IDS[:n])
            self.assertEqual(self.cli("root", data=data), records([checkpoint]))
            indices = range(n) if n <= 9 else (0, n // 2, n - 1)
            for i in indices:
                path = prove(inclusion_ranges(0, n, i))
                self.assertEqual(self.cli("inclusion", hex(i), data=data), path)
                self.assertEqual(self.cli("verify-inclusion", hex(n), hex(i), hexhash(IDS[i]),
                                          hexhash(checkpoint), data=path), b"ok\n")
            prefixes = range(n + 1) if n <= 9 else (0, 1, n // 2, n - 1, n)
            for old in prefixes:
                path = prove(consistency_ranges(0, n, old))
                self.assertEqual(self.cli("consistency", hex(old), data=data), path)
                self.assertEqual(self.cli("verify-consistency", hex(old), hex(n),
                                          hexhash(root(IDS[:old])), hexhash(checkpoint),
                                          data=path), b"ok\n")

    def test_full_width_sizes(self):
        n = (1 << 64) - 1
        checkpoint = hexhash(repeated_root(n))
        for index in (0, 3, 1 << 63, n - 1):
            path = records(repeated_root(length) for _, length in inclusion_ranges(0, n, index))
            self.assertEqual(self.cli("verify-inclusion", hex(n), hex(index), hexhash(IDS[0]),
                                      checkpoint, data=path), b"ok\n")
        old = 3
        path = records(repeated_root(length) for _, length in consistency_ranges(0, n, old))
        self.assertEqual(len(path.splitlines()), 65)
        args = ("verify-consistency", hex(old), hex(n), hexhash(repeated_root(old)), checkpoint)
        self.assertEqual(self.cli(*args, data=path), b"ok\n")
        self.cli(*args, data=path + records([EMPTY]), expect=1)

    def test_framing_and_wrong_proofs(self):
        line = records([IDS[0]])
        for malformed in (b"\n", line[:-1], line[:-1] + b"\r\n", line + b"*", b" " + line,
                          line.replace(b"0x", b"0X"), b"0xA" + line[3:], b"0x\0" + line[3:]):
            self.cli("root", data=malformed, expect=1)
        for invalid in ("1", "0x", "0x01", "0X1", "0xF", "0x10000000000000000", "-1"):
            self.cli("inclusion", invalid, data=line, expect=1)
        self.cli("inclusion", "0x1", data=line, expect=1)
        self.cli("consistency", "0x2", data=line, expect=1)
        self.cli("inclusion", "0x0", expect=1)
        args = ("verify-inclusion", "0x7", "0x4", hexhash(IDS[4]), hexhash(root(IDS[:7])))
        proof = prove(inclusion_ranges(0, 7, 4))
        self.cli(*args, data=b"".join(reversed(proof.splitlines(keepends=True))), expect=1)
        self.cli(*args, data=proof[:-131], expect=1)
        self.cli(*args, data=proof + line, expect=1)
        self.cli(*args, data=proof[:-1], expect=1)
        self.cli("verify-inclusion", "0x1", "0x0", hexhash(IDS[0]), "0x", expect=1)
        self.cli("verify-inclusion", "0x1", "0x0", hexhash(IDS[0]), hexhash(leaf(IDS[0])),
                 data=line, expect=1)
        self.cli("verify-consistency", "0x0", "0x1", hexhash(IDS[0]), hexhash(leaf(IDS[0])),
                 expect=1)
        self.cli("verify-consistency", "0x1", "0x1", hexhash(leaf(IDS[0])), hexhash(EMPTY),
                 expect=1)
        self.cli("root", "extra", expect=2)


if __name__ == "__main__":
    unittest.main()
