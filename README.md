[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)
[![Deploy to GitHub Pages](https://github.com/systemslibrarian/crypto-lab-pairing-gate/actions/workflows/pages.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-pairing-gate/actions/workflows/pages.yml)

# crypto-lab-pairing-gate

## 1. What It Is

crypto-lab-pairing-gate implements BLS signatures and signature aggregation over BLS12-381, a pairing-friendly elliptic curve designed by Sean Bowe for Zcash and adopted by Ethereum 2.0. A bilinear pairing `e: G1 × G2 → GT` is a map satisfying `e(aP, bQ) = e(P, Q)^(ab)`, enabling verification of n aggregated signatures with only two pairing operations regardless of n. The security model is based on the hardness of the elliptic curve discrete logarithm problem and the decisional Diffie-Hellman problem in the pairing target group GT, with approximately 128-bit classical and 64-bit post-quantum security.

## 2. When to Use It

- Use BLS signatures when you need to aggregate many signatures on the same message into one — consensus protocols, threshold schemes, and multi-party attestations.
- Use BLS12-381 specifically when your application requires pairing-based ZK-SNARK verification (Groth16) alongside signature operations.
- Do not use BLS when signature verification speed is critical for a single signer — Ed25519 is significantly faster for individual signatures.
- Do not use naive BLS aggregation without Proof of Possession or equivalent rogue key protection — the rogue key attack allows an attacker to forge aggregate signatures.
- Do not use BLS for post-quantum security — BLS12-381 provides approximately 64-bit quantum security, which falls below the 128-bit post-quantum threshold.

## 3. Live Demo

[https://systemslibrarian.github.io/crypto-lab-pairing-gate/](https://systemslibrarian.github.io/crypto-lab-pairing-gate/)

Generate BLS keypairs, sign messages, and verify signatures using real BLS12-381 arithmetic via `@noble/curves`. The sign/verify section lets you generate a keypair, sign an arbitrary message, verify the pairing equation, and tamper with the signature to observe verification failure. The aggregation visualizer has a signer-count slider (2–100), generates all keypairs and signatures, then animates them collapsing into a single 48-byte aggregate signature verified with two pairings.

## 4. What Can Go Wrong

- **Rogue key attack:** without Proof of Possession, an attacker who registers a maliciously computed public key can forge an aggregate signature that passes verification using only their own private key.
- **Subgroup membership checks:** points presented as G1 or G2 elements must be checked for subgroup membership before use — skipping this check can allow small-subgroup attacks.
- **Signing the same message across different contexts:** BLS aggregation assumes all signers sign the same message; mixing messages requires per-message pairing checks, losing the O(1) verification benefit.
- **Implementation bugs in hash-to-curve:** RFC 9380 specifies the hash-to-curve procedure; non-compliant implementations produce points that may not match across libraries.
- **Post-quantum exposure:** BLS12-381 provides ~64-bit quantum security. Harvest-now-decrypt-later attacks are relevant for long-term secrets.

## 5. Real-World Usage

- **Ethereum 2.0 beacon chain:** aggregates validator attestations using BLS12-381 with Proof of Possession, enabling ~450,000 validators to attest per slot with a manageable verification cost.
- **Zcash Sapling:** BLS12-381 was designed for Zcash's Groth16 zk-SNARK verifier, where pairing equations check proof validity.
- **Internet Computer (DFINITY):** uses BLS threshold signatures for chain-key cryptography, enabling deterministic randomness beacons and cross-subnet message authentication.
- **Filecoin:** aggregates miner message signatures using BLS to reduce on-chain transaction size.
- **Ethereum EIP-2537:** adds BLS12-381 precompiles to the EVM, enabling smart contracts to verify BLS signatures and pairings on-chain.

## Cross-links

- [Hybrid Wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — X25519 + ML-KEM key exchange
- [ZK Proof Lab](https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/) — Groth16 and Schnorr ZK proofs
- [Curve Lens](https://systemslibrarian.github.io/crypto-lab-curve-lens/) — elliptic curve point arithmetic
- [FROST Threshold](https://systemslibrarian.github.io/crypto-lab-frost-threshold/) — threshold signatures
- [crypto-lab home](https://systemslibrarian.github.io/crypto-lab/)

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*