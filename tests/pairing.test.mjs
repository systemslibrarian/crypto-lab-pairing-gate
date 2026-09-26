import assert from 'node:assert/strict';
import test from 'node:test';
import { bls12_381 } from '@noble/curves/bls12-381.js';

// RFC 9380 Appendix J.9.1, BLS12381G1_XMD:SHA-256_SSWU_RO_, empty message.
// The RFC's test DST differs from the BLS signature suite's default DST. Pass
// it explicitly: a default-domain hash is not this published known-answer point.
// https://www.rfc-editor.org/rfc/rfc9380.html#appendix-J.9.1
const rfcDst = 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_';
const rfcX = '052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1';
const rfcY = '08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265';

const point = bls12_381.G1.hashToCurve(new Uint8Array(), { DST: rfcDst });
const generator = bls12_381.G2.Point.BASE;
const gt = bls12_381.fields.Fp12;

test('RFC 9380 J.9.1 hash-to-curve point matches both published coordinates', () => {
  const { x, y } = point.toAffine();
  assert.equal(x.toString(16).padStart(96, '0'), rfcX);
  assert.equal(y.toString(16).padStart(96, '0'), rfcY);
  assert.equal(point.isTorsionFree(), true);
});

test('the published G1 point satisfies the nontrivial pairing identity', () => {
  const base = bls12_381.pairing(point, generator);
  const left = bls12_381.pairing(point.multiply(3n), generator.multiply(5n));
  const right = gt.pow(base, 15n);
  assert.equal(gt.eql(left, right), true);
  assert.equal(gt.eql(base, gt.ONE), false);

  // The page's verification equation for a signature sk·H and key sk·G2.
  const sk = 7n;
  assert.equal(
    gt.eql(bls12_381.pairing(point.multiply(sk), generator),
      bls12_381.pairing(point, generator.multiply(sk))),
    true,
  );
  assert.equal(gt.eql(bls12_381.pairing(point.multiply(sk + 1n), generator),
    bls12_381.pairing(point, generator.multiply(sk))), false);
});
