# crypto-lab-pairing-gate

## What It Is

crypto-lab-pairing-gate implements BLS signatures and signature aggregation over BLS12-381, a pairing-friendly elliptic curve designed by Sean Bowe for Zcash and adopted by Ethereum 2.0. A bilinear pairing `e: G1 × G2 → GT` is a map satisfying `e(aP, bQ) = e(P, Q)^(ab)`, enabling verification of n aggregated signatures with only two pairing operations regardless of n. BLS signature unforgeability (EUF-CMA) is proven under the computational co-Diffie-Hellman assumption (co-CDH) in the random-oracle model. Note that the *decisional* Diffie-Hellman problem is **easy** in the source groups G1/G2 — given `(P, aP, bP, cP)` one simply checks `e(aP, bP) = e(P, cP)` — which is precisely the gap-Diffie-Hellman structure that pairings provide. BLS12-381 offers approximately 128-bit classical security and **no** post-quantum security: like every elliptic-curve and pairing-based scheme, it is broken outright by Shor's algorithm on a sufficiently large quantum computer.

## When to Use It

- Use BLS signatures when you need to aggregate many signatures on the same message into one — consensus protocols, threshold schemes, and multi-party attestations.
- Use BLS12-381 specifically when your application requires pairing-based ZK-SNARK verification (Groth16) alongside signature operations.
- Do not use BLS when signature verification speed is critical for a single signer — Ed25519 is significantly faster for individual signatures.
- Do not use naive BLS aggregation without Proof of Possession or equivalent rogue key protection — the rogue key attack allows an attacker to forge aggregate signatures.
- Do not use BLS for post-quantum security — BLS12-381 has no post-quantum security. Shor's algorithm recovers the private key from any public key in polynomial time on a cryptographically relevant quantum computer (CRQC).
- Do NOT use this implementation in production — it is a browser teaching demo; use a vetted BLS library (e.g. blst) for real deployments.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-pairing-gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/)**

Generate BLS keypairs, sign messages, and verify signatures using real BLS12-381 arithmetic via `@noble/curves`. The sign/verify section lets you generate a keypair, sign an arbitrary message, verify the pairing equation, and tamper with the signature to observe verification failure. The aggregation visualizer has a signer-count slider (2–100), generates all keypairs and signatures, then animates them collapsing into a single 48-byte aggregate signature verified with two pairings.

## What Can Go Wrong

- **Rogue key attack:** without Proof of Possession, an attacker who registers a maliciously computed public key can forge an aggregate signature that passes verification using only their own private key.
- **Subgroup membership checks:** points presented as G1 or G2 elements must be checked for subgroup membership before use — skipping this check can allow small-subgroup attacks.
- **Signing the same message across different contexts:** BLS aggregation assumes all signers sign the same message; mixing messages requires per-message pairing checks, losing the O(1) verification benefit.
- **Implementation bugs in hash-to-curve:** RFC 9380 specifies the hash-to-curve procedure; non-compliant implementations produce points that may not match across libraries.
- **Post-quantum exposure:** BLS12-381 has no quantum resistance. Once a CRQC exists, any deployed key becomes forgeable and previously recorded signatures lose non-repudiation; migrating to a post-quantum signature scheme is the only mitigation.

## Real-World Usage

- **Ethereum 2.0 beacon chain:** aggregates validator attestations using BLS12-381 with Proof of Possession, enabling ~450,000 validators to attest per slot with a manageable verification cost.
- **Zcash Sapling:** BLS12-381 was designed for Zcash's Groth16 zk-SNARK verifier, where pairing equations check proof validity.
- **Internet Computer (DFINITY):** uses BLS threshold signatures for chain-key cryptography, enabling deterministic randomness beacons and cross-subnet message authentication.
- **Filecoin:** aggregates miner message signatures using BLS to reduce on-chain transaction size.
- **Ethereum EIP-2537:** adds BLS12-381 precompiles to the EVM, enabling smart contracts to verify BLS signatures and pairings on-chain.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-pairing-gate
cd crypto-lab-pairing-gate
npm install
npm run dev
```

## Related Demos

- [crypto-lab-ibe-gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/) — Boneh-Franklin identity-based encryption over the same BLS12-381 pairing.
- [crypto-lab-frost-threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — threshold signatures (FROST over Ed25519).
- [crypto-lab-ed25519-forge](https://systemslibrarian.github.io/crypto-lab-ed25519-forge/) — Ed25519 EdDSA, the fast single-signer alternative to BLS.
- [crypto-lab-zk-proof-lab](https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/) — Groth16 and Schnorr ZK proofs.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
