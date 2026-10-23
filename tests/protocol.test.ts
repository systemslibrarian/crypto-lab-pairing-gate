import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BLS_POP_PROOF_DST,
  BLS_SIGNATURE_DST,
  MAX_MESSAGE_BYTES,
  OperationEpoch,
  encodeBoundedMessage,
  hashProofPublicKey,
  hashSignatureMessage,
  parseSignerCount,
} from '../src/protocol.ts';

test('uses distinct July 2026 CFRG draft domains for signatures and proofs of possession', () => {
  assert.equal(BLS_SIGNATURE_DST, 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_');
  assert.equal(BLS_POP_PROOF_DST, 'BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_');
  assert.notEqual(BLS_SIGNATURE_DST, BLS_POP_PROOF_DST);
  const suite = { hash: (_message: Uint8Array, domain: string) => domain };
  assert.equal(hashSignatureMessage(suite, new Uint8Array()), BLS_SIGNATURE_DST);
  assert.equal(hashProofPublicKey(suite, new Uint8Array()), BLS_POP_PROOF_DST);
});

test('accepts only the advertised signer-count range', () => {
  assert.equal(parseSignerCount('2'), 2);
  assert.equal(parseSignerCount('100'), 100);
  for (const value of ['0', '1', '101', '-2', '2.5', '2x', '', ' 2 ', '9007199254740993']) {
    assert.throws(() => parseSignerCount(value), /whole number from 2 to 100/);
  }
});

test('bounds messages by encoded bytes rather than JavaScript characters', () => {
  assert.equal(encodeBoundedMessage('x'.repeat(MAX_MESSAGE_BYTES)).length, MAX_MESSAGE_BYTES);
  assert.throws(
    () => encodeBoundedMessage('é'.repeat(MAX_MESSAGE_BYTES)),
    new RegExp(`at most ${MAX_MESSAGE_BYTES} UTF-8 bytes`),
  );
});

test('only the newest operation epoch retains authority', () => {
  const epoch = new OperationEpoch();
  const first = epoch.begin();
  assert.equal(epoch.isCurrent(first), true);
  const second = epoch.begin();
  assert.equal(epoch.isCurrent(first), false);
  assert.equal(epoch.isCurrent(second), true);
  epoch.retire();
  assert.equal(epoch.isCurrent(second), false);
});
