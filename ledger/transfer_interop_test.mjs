import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";

const [verifier, fixtureBinary] = process.argv.slice(2);
const fixture = JSON.parse(execFileSync(fixtureBinary, ["--extended-suites"], { encoding: "utf8" }));
const bytes = (hex) => Buffer.from(hex.slice(2), "hex");
const hash = (value) => createHash("sha512").update(value).digest();
const tagged = (tag, value) => hash(Buffer.concat([Buffer.from([tag.length]), Buffer.from(tag), value]));
const u64 = (n) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(n);
  return out;
};
const chain = bytes(fixture.chainId);
let unitId = bytes(fixture.inputId);
let commitment = bytes(fixture.commitment);

// Fixed DER SubjectPublicKeyInfo prefixes for the standardized algorithm OIDs.
// The ledger itself carries just the raw public key.
for (const [field, suite, recipient, algorithm, keyBytes, sigBytes, spki] of [
  ["first", 3, 4, "ml-dsa-87", 2592, 4627, "30820a32300b060960864801650304031303820a2100"],
  ["second", 4, 1, "slh-dsa-shake-256s", 64, 29792, "3050300b060960864801650304031e034100"],
]) {
  const wire = bytes(fixture[field]);
  const header = Buffer.from(spki, "hex");
  const body = wire.subarray(0, 244 + keyBytes);
  const raw = body.subarray(244);
  assert.equal(wire.length, body.length + sigBytes);
  assert.deepEqual(body.subarray(2, 34), chain);
  assert.deepEqual(body.subarray(34, 98), unitId);
  assert.deepEqual([...body.subarray(114, 116)], [suite, recipient]);
  const nonceHash = body.subarray(180, 244);
  const owner = (pub) => tagged("unit/owner", Buffer.concat([Buffer.from([suite]), nonceHash, hash(pub)]));
  assert.deepEqual(owner(raw), commitment);
  const publicKey = createPublicKey({ key: Buffer.concat([header, raw]), format: "der", type: "spki" });
  assert.equal(publicKey.asymmetricKeyType, algorithm);
  assert(verify(null, tagged("move/body", body), publicKey, wire.subarray(body.length)));

  const spendMask = 1 << (suite - 1);
  const receiveMask = 1 << (recipient - 1);
  const request = (ownerCommitment, message, spend = spendMask, receive = receiveMask) =>
    Buffer.concat([Buffer.from("DLV1"), chain, Buffer.from([spend, receive]), u64(1n),
      unitId, u64(8n), Buffer.from([suite]), ownerCommitment, message]);
  const expectedReply = (message) => {
    const move = tagged("move/id", message);
    return Buffer.concat([move, tagged("unit/id", Buffer.concat([move, Buffer.alloc(4)])), body.subarray(115, 180)]);
  };
  for (const rejected of [
    request(commitment, wire, 3, 3), request(commitment, wire, 0, receiveMask),
    request(commitment, wire, spendMask, receiveMask | 16), request(commitment, wire.subarray(0, -1)),
    request(commitment, Buffer.concat([wire, Buffer.alloc(1)])),
  ]) {
    const result = spawnSync(verifier, { input: rejected });
    assert.equal(result.status, 1);
    assert.equal(result.stdout.length, 0);
  }

  // A separate Node key opens a synthetic input and signs the same transition.
  // Derive its commitment and both output IDs independently of libdemos.
  const nodeKey = generateKeyPairSync(algorithm);
  const der = nodeKey.publicKey.export({ format: "der", type: "spki" });
  assert.deepEqual(der.subarray(0, header.length), header);
  const nodeRaw = der.subarray(header.length);
  assert.equal(nodeRaw.length, keyBytes);
  const nodeBody = Buffer.concat([body.subarray(0, 244), nodeRaw]);
  const nodeWire = Buffer.concat([nodeBody, sign(null, tagged("move/body", nodeBody), nodeKey.privateKey)]);
  assert.deepEqual(execFileSync(verifier, { input: request(owner(nodeRaw), nodeWire) }), expectedReply(nodeWire));

  const reply = execFileSync(verifier, { input: request(commitment, wire) });
  assert.deepEqual(reply, expectedReply(wire));
  unitId = reply.subarray(64, 128);
  commitment = reply.subarray(129);
}
