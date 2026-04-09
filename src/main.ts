import './style.css';
import { bls12_381 } from '@noble/curves/bls12-381.js';

// ============================================================
// Helpers
// ============================================================
const $ = (sel: string) => document.querySelector(sel)!;
const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const truncHex = (hex: string, bytes = 32): string =>
  hex.length > bytes * 2 ? hex.slice(0, bytes * 2) + '…' : hex;

// BLS shortSignatures: G1 signatures (48 bytes), G2 public keys (96 bytes)
const bls = bls12_381.shortSignatures;

// ============================================================
// Theme toggle
// ============================================================
function currentTheme(): string {
  return document.documentElement.getAttribute('data-theme') ?? 'dark';
}

function setTheme(t: string) {
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('theme', t);
  const btn = document.getElementById('theme-toggle');
  if (btn) {
    btn.textContent = t === 'dark' ? '🌙' : '☀️';
    btn.setAttribute('aria-label', `Switch to ${t === 'dark' ? 'light' : 'dark'} theme`);
  }
}

// ============================================================
// Render HTML
// ============================================================
document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<header>
  <button id="theme-toggle" class="theme-toggle" aria-label="Switch theme">🌙</button>
  <h1>Pairing Gate</h1>
  <p class="subtitle">BLS12-381 Signatures &amp; Aggregation</p>
  <a class="portfolio-link" href="https://systemslibrarian.github.io/crypto-lab/">← crypto-lab portfolio</a>
</header>

<!-- ======== Section A: What is a pairing? ======== -->
<section class="demo-section" id="section-a">
  <h2>A — What Is a Pairing?</h2>

  <h3>A1 — The Three Groups</h3>
  <p>BLS12-381 defines three algebraic groups used in pairing-based cryptography:</p>
  <div class="group-boxes">
    <div class="group-box g1">
      <div class="group-label">G₁</div>
      <div class="group-detail">Points on E(𝔽<sub>p</sub>)<br>48-byte compressed<br>Fast operations</div>
    </div>
    <div class="group-box g2">
      <div class="group-label">G₂</div>
      <div class="group-detail">Points on E(𝔽<sub>p²</sub>)<br>96-byte compressed<br>Slower operations</div>
    </div>
    <div class="group-box gt">
      <div class="group-label">G<sub>T</sub></div>
      <div class="group-detail">Target group in 𝔽<sub>p¹²</sub><br>576 bytes<br>Pairing output</div>
    </div>
  </div>
  <div class="note">BLS12-381 was designed by Sean Bowe (Zcash) to achieve ~128-bit classical security with efficient pairings.</div>

  <h3>A2 — The Pairing Operation</h3>
  <p>A pairing <code>e : G₁ × G₂ → G<sub>T</sub></code> is a bilinear map with three key properties:</p>
  <div class="math-block">
    <strong>Bilinearity:</strong> e(<span class="g1">aP</span>, <span class="g2">bQ</span>) = e(<span class="g1">P</span>, <span class="g2">Q</span>)<sup>ab</sup>
  </div>
  <div class="math-block">
    <strong>Non-degeneracy:</strong> e(<span class="g1">P</span>, <span class="g2">Q</span>) ≠ 1 &nbsp; for generators P, Q
  </div>
  <div class="math-block">
    <strong>Efficiency:</strong> Computable in polynomial time (Ate pairing on BLS12-381)
  </div>
  <p>Bilinearity is powerful because it lets you move scalar multiplication between arguments. This algebraic property is the foundation of signature aggregation: <code>e(sk·H, G₂) = e(H, sk·G₂)</code>.</p>

  <h3>A3 — Why BLS12-381 Specifically?</h3>
  <p>Curve parameters:</p>
  <table>
    <tr><th>Parameter</th><th>Value</th></tr>
    <tr><td>Embedding degree</td><td>k = 12 (required for efficient pairings)</td></tr>
    <tr><td>Field size</td><td>381 bits</td></tr>
    <tr><td>Scalar field</td><td>~255 bits (r ≈ 2²⁵⁴, matches Ed25519 scalar size)</td></tr>
    <tr><td>Classical security</td><td>~128 bits</td></tr>
    <tr><td>Quantum security</td><td>~64 bits</td></tr>
  </table>
  <p>BLS12-381 was chosen for Zcash Sapling (2018) and later adopted by Ethereum 2.0 (2020). The "12" in BLS12-381 is the embedding degree; the "381" is the field size in bits.</p>
</section>

<!-- ======== Section B: BLS Signature Scheme ======== -->
<section class="demo-section" id="section-b">
  <h2>B — BLS Signature Scheme</h2>

  <h3>B1 — The Three Algorithms</h3>
  <p><strong>Key generation:</strong> Private key sk ∈ ℤ<sub>r</sub> (random scalar). Public key <span style="color:var(--g2-color)">PK = sk · G₂</span> (G₂ point, 96 bytes).</p>
  <p><strong>Signing:</strong> Hash message to G₁: <span style="color:var(--g1-color)">H = hash_to_curve(message)</span>. Signature: <span style="color:var(--g1-color)">σ = sk · H</span> (G₁ point, 48 bytes).</p>
  <p><strong>Verification:</strong> Check pairing equation:</p>
  <div class="math-block">
    e(<span class="g1">σ</span>, <span class="g2">G₂</span>) = e(<span class="g1">H</span>, <span class="g2">PK</span>)
  </div>
  <p>This works because: <code>e(sk·H, G₂) = e(H, G₂)^sk = e(H, sk·G₂) = e(H, PK)</code></p>

  <h3>B2 — Live Sign / Verify</h3>
  <div class="field-group">
    <label for="b-msg">Message</label>
    <input type="text" id="b-msg" value="Ethereum validator attestation: slot 9841203">
  </div>
  <div class="controls">
    <button id="b-keygen">Generate Keypair</button>
    <button id="b-sign" disabled>Sign</button>
    <button id="b-verify" disabled>Verify</button>
    <button id="b-tamper" class="danger" disabled>Flip One Bit</button>
  </div>
  <div id="b-output"></div>
</section>

<!-- ======== Section C: Signature Aggregation ======== -->
<section class="demo-section" id="section-c">
  <h2>C — Signature Aggregation</h2>

  <h3>C1 — The Aggregation Property</h3>
  <p>Because pairings are bilinear, BLS signatures from different signers on the same message can be combined:</p>
  <div class="math-block">
    <span class="g1">σ<sub>agg</sub></span> = σ₁ + σ₂ + … + σ<sub>n</sub> &nbsp;(point addition in <span class="g1">G₁</span>)
  </div>
  <div class="math-block">
    <span class="g2">PK<sub>agg</sub></span> = PK₁ + PK₂ + … + PK<sub>n</sub> &nbsp;(point addition in <span class="g2">G₂</span>)
  </div>
  <div class="math-block">
    <strong>Verify aggregate:</strong> e(<span class="g1">σ<sub>agg</sub></span>, <span class="g2">G₂</span>) = e(<span class="g1">H(msg)</span>, <span class="g2">PK<sub>agg</sub></span>)
  </div>
  <table>
    <tr><th>Approach</th><th>Pairings required</th><th>Verification cost</th></tr>
    <tr><td>Verify n signatures individually</td><td>2n</td><td>O(n)</td></tr>
    <tr><td>Aggregate then verify</td><td>2</td><td>O(1)</td></tr>
  </table>

  <h3>C2 — Live Aggregation Demo</h3>
  <div class="field-group">
    <label for="c-count">Signers: <span id="c-count-display">10</span></label>
    <input type="range" id="c-count" min="2" max="100" value="10">
  </div>
  <div class="field-group">
    <label for="c-msg">Message</label>
    <input type="text" id="c-msg" value="Block 21847293: propose and attest">
  </div>
  <div class="controls">
    <button id="c-keygen">Generate All Keypairs</button>
    <button id="c-sign" disabled>Sign All</button>
    <button id="c-aggregate" disabled>Aggregate &amp; Verify</button>
  </div>
  <div id="c-grid" class="signer-grid"></div>
  <div id="c-output"></div>
</section>

<!-- ======== Section D: Rogue Key Attack ======== -->
<section class="demo-section" id="section-d">
  <h2>D — Rogue Key Attack &amp; Defenses</h2>

  <h3>D1 — The Rogue Key Attack</h3>
  <p>Naive BLS aggregation is vulnerable if an attacker can choose their public key <em>after</em> seeing other participants' keys.</p>
  <p><strong>Attack scenario:</strong></p>
  <div class="attack-visual">
    <div class="key-card">
      <div class="key-card-title">Honest signer</div>
      <p>PK₁ = sk₁ · G₂</p>
      <p style="color:var(--text-muted);font-size:0.8rem">(Registers key honestly)</p>
    </div>
    <div class="key-card malicious">
      <div class="key-card-title">⚠ Attacker</div>
      <p>PK₂ = sk₂ · G₂ − PK₁</p>
      <p style="color:var(--text-muted);font-size:0.8rem">(Maliciously chosen to cancel PK₁)</p>
    </div>
  </div>
  <p>Aggregate key: PK<sub>agg</sub> = PK₁ + PK₂ = sk₂ · G₂. The attacker signs alone with sk₂ and the aggregate signature verifies — forging a signature that appears to be from both signers.</p>

  <h3>D2 — Defenses</h3>
  <div class="defense-list">
    <div class="defense-item">
      <h4>1. Proof of Possession (PoP) — used by Ethereum</h4>
      <p>Each signer registers a signature of their own public key, proving knowledge of the private key before the public key is accepted. Requires one extra signature per signer during registration — not during signing.</p>
    </div>
    <div class="defense-item">
      <h4>2. Message Augmentation</h4>
      <p>Each signer includes their public key in the signed message: sign <code>PK_i ‖ message</code> instead of <code>message</code>. Aggregation still works but requires one pairing per signer during verification (loses the O(1) verification benefit).</p>
    </div>
    <div class="defense-item">
      <h4>3. Hash-to-scalar Rogue Key Prevention</h4>
      <p>Multiply each signer's contribution by a hash of all public keys: <code>t_i = H(i, PK₁,…,PK_n)</code>. Aggregate: <code>σ_agg = Σ t_i · σ_i</code>, <code>PK_agg = Σ t_i · PK_i</code>. Prevents the attack but requires knowing all public keys before aggregating.</p>
    </div>
  </div>

  <h3>D3 — What Ethereum Does</h3>
  <p>Ethereum 2.0 uses Proof of Possession. Validators register a PoP signature (signing their own public key) when depositing 32 ETH. The beacon chain verifies PoP before accepting any validator's key into the active set. After that, aggregation proceeds with the O(1) verification property intact.</p>
</section>

<!-- ======== Section E: Where Pairings Appear ======== -->
<section class="demo-section" id="section-e">
  <h2>E — Where Pairings Appear</h2>

  <div class="deployment-grid">
    <div class="deployment-card">
      <h4>Ethereum 2.0 Consensus</h4>
      <p>The beacon chain uses BLS signatures for validator attestations. Each slot, ~450,000 validators may attest. Without aggregation, verifying all signatures would require ~900,000 pairing operations per slot. With BLS aggregation, the beacon chain verifies a small number of aggregate signatures — one per committee. This is what makes Ethereum's proof-of-stake computationally feasible at scale.</p>
    </div>
    <div class="deployment-card">
      <h4>Zcash Sapling &amp; Orchard</h4>
      <p>BLS12-381 was designed for Zcash Sapling (2018) to support Groth16 zk-SNARK proofs. The pairing is used in the SNARK verifier — the trusted setup generates points in G₁ and G₂, and verification checks a pairing equation. Zcash Orchard uses Pallas/Vesta curves instead, but BLS12-381 remains the standard for Groth16-based SNARKs.</p>
    </div>
    <div class="deployment-card">
      <h4>DFINITY / Internet Computer</h4>
      <p>The Internet Computer Protocol uses BLS threshold signatures for chain-key cryptography — any t-of-n subnet nodes can produce a valid BLS signature without reconstructing the private key. This enables deterministic randomness beacons and cross-subnet authentication.</p>
    </div>
    <div class="deployment-card">
      <h4>Filecoin</h4>
      <p>Filecoin uses BLS signatures for miner messages to reduce transaction size. A block containing 1,000 miner messages uses 1 aggregate signature instead of 1,000 individual signatures — significant bandwidth savings on-chain.</p>
    </div>
  </div>

  <h3>E5 — Size Comparison</h3>
  <table>
    <tr><th>Scheme</th><th>Public key</th><th>Signature</th><th>Verification</th></tr>
    <tr><td>Ed25519</td><td>32 bytes</td><td>64 bytes</td><td>Fast (no pairing)</td></tr>
    <tr><td>ECDSA P-256</td><td>64 bytes</td><td>64 bytes</td><td>Fast (no pairing)</td></tr>
    <tr><td>BLS (G₁ sig, G₂ key)</td><td>96 bytes</td><td>48 bytes</td><td>Slow (2 pairings)</td></tr>
    <tr><td>BLS aggregate (n signers)</td><td>96 bytes</td><td>48 bytes</td><td>Slow (2 pairings)</td></tr>
  </table>
  <p>The last two rows are identical — <strong>n signatures cost the same to verify as 1</strong>. That is the point.</p>
</section>

<footer>
  <a href="https://systemslibrarian.github.io/crypto-lab/">crypto-lab portfolio</a>
  <p class="scripture">"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
</footer>
`;

// ============================================================
// Init theme toggle
// ============================================================
setTheme(currentTheme());
document.getElementById('theme-toggle')!.addEventListener('click', () => {
  setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
});

// ============================================================
// Section B — BLS Sign / Verify
// ============================================================
interface BKeyState {
  sk: Uint8Array;
  pk: ReturnType<typeof bls.getPublicKey>;
  sig: ReturnType<typeof bls.sign> | null;
  hashedMsg: ReturnType<typeof bls.hash> | null;
  tampered: boolean;
}

let bState: BKeyState | null = null;

const bOutput = () => $('#b-output') as HTMLDivElement;

$('#b-keygen').addEventListener('click', () => {
  const t0 = performance.now();
  const { secretKey, publicKey } = bls.keygen();
  const keygenMs = (performance.now() - t0).toFixed(1);

  bState = { sk: secretKey, pk: publicKey, sig: null, hashedMsg: null, tampered: false };
  ($('#b-sign') as HTMLButtonElement).disabled = false;
  ($('#b-verify') as HTMLButtonElement).disabled = true;
  ($('#b-tamper') as HTMLButtonElement).disabled = true;

  bOutput().innerHTML = `
    <div class="output-block">
      <div class="label">Private key (32 bytes)</div>
      <div class="value">${bytesToHex(secretKey)}</div>
    </div>
    <div class="output-block">
      <div class="label">Public key (96 bytes compressed G₂)</div>
      <div class="value g2">${publicKey.toHex()}</div>
    </div>
    <div class="timing">
      <div class="timing-item"><span class="timing-label">Keygen:</span><span class="timing-value">${keygenMs}ms</span></div>
    </div>
  `;
});

$('#b-sign').addEventListener('click', () => {
  if (!bState) return;
  const msg = ($('#b-msg') as HTMLInputElement).value;
  const encoded = new TextEncoder().encode(msg);

  const t0 = performance.now();
  const hashedMsg = bls.hash(encoded);
  const sig = bls.sign(hashedMsg, bState.sk);
  const signMs = (performance.now() - t0).toFixed(1);

  bState.sig = sig;
  bState.hashedMsg = hashedMsg;
  bState.tampered = false;
  ($('#b-verify') as HTMLButtonElement).disabled = false;
  ($('#b-tamper') as HTMLButtonElement).disabled = false;

  const existingHtml = bOutput().innerHTML;
  bOutput().innerHTML = existingHtml + `
    <div class="output-block">
      <div class="label">Signature (48 bytes compressed G₁)</div>
      <div class="value g1">${sig.toHex()}</div>
    </div>
    <div class="output-block">
      <div class="label">Hash-to-curve H(msg) (48 bytes G₁)</div>
      <div class="value g1">${hashedMsg.toHex()}</div>
    </div>
    <div class="timing">
      <div class="timing-item"><span class="timing-label">Sign:</span><span class="timing-value">${signMs}ms</span></div>
    </div>
  `;
});

$('#b-verify').addEventListener('click', () => {
  if (!bState || !bState.sig || !bState.hashedMsg) return;

  const t0 = performance.now();
  const valid = bls.verify(bState.sig, bState.hashedMsg, bState.pk);
  const verifyMs = (performance.now() - t0).toFixed(1);

  // Compute pairing values for display
  const G2Gen = bls12_381.G2.Point.BASE;
  const left = bls12_381.pairing(bState.sig, G2Gen);
  const right = bls12_381.pairing(bState.hashedMsg, bState.pk);
  const leftHex = bytesToHex(bls12_381.fields.Fp12.toBytes(left));
  const rightHex = bytesToHex(bls12_381.fields.Fp12.toBytes(right));

  const badge = valid
    ? '<span class="badge valid">✅ VALID</span>'
    : '<span class="badge invalid">❌ INVALID</span>';

  const explanation = !valid && bState.tampered
    ? '<p style="color:var(--error)">The tampered signature produces a different G<sub>T</sub> element than the hash-public-key pairing. The two Fp12 values do not match.</p>'
    : '';

  bOutput().innerHTML += `
    <div style="margin-top:0.75rem">${badge}</div>
    ${explanation}
    <div class="output-block">
      <div class="label">e(σ, G₂) — left side</div>
      <div class="value gt">${truncHex(leftHex)}…</div>
    </div>
    <div class="output-block">
      <div class="label">e(H, PK) — right side</div>
      <div class="value gt">${truncHex(rightHex)}…</div>
    </div>
    <div class="timing">
      <div class="timing-item"><span class="timing-label">Verify:</span><span class="timing-value">${verifyMs}ms</span></div>
    </div>
  `;
});

$('#b-tamper').addEventListener('click', () => {
  if (!bState || !bState.sig) return;
  // Get signature bytes, flip one bit, reconstruct
  const sigBytes = bls.Signature.toBytes(bState.sig);
  const tampered = new Uint8Array(sigBytes);
  // Flip a bit in byte 20 (arbitrary interior byte)
  tampered[20] ^= 0x01;
  try {
    bState.sig = bls.Signature.fromBytes(tampered);
  } catch {
    // If the tampered bytes aren't a valid point, flip a different byte
    tampered[20] ^= 0x01; // undo
    tampered[10] ^= 0x02;
    try {
      bState.sig = bls.Signature.fromBytes(tampered);
    } catch {
      // Last resort: just negate the signature to produce a different valid point
      bState.sig = bState.sig.negate();
    }
  }
  bState.tampered = true;
  bOutput().innerHTML += `
    <div class="note" style="border-left-color:var(--error)">One bit of the signature has been flipped. Click <strong>Verify</strong> to see it fail.</div>
  `;
});

// ============================================================
// Section C — Aggregation Demo
// ============================================================
interface Signer {
  index: number;
  sk: Uint8Array;
  pk: ReturnType<typeof bls.getPublicKey>;
  sig: ReturnType<typeof bls.sign> | null;
}

let cSigners: Signer[] = [];
let cHashedMsg: ReturnType<typeof bls.hash> | null = null;

const cGrid = () => $('#c-grid') as HTMLDivElement;
const cOutput = () => $('#c-output') as HTMLDivElement;
const cCountDisplay = () => $('#c-count-display') as HTMLSpanElement;
const cCountInput = () => $('#c-count') as HTMLInputElement;

cCountInput().addEventListener('input', () => {
  cCountDisplay().textContent = cCountInput().value;
});

$('#c-keygen').addEventListener('click', () => {
  const n = parseInt(cCountInput().value);
  cSigners = [];

  const t0 = performance.now();
  for (let i = 0; i < n; i++) {
    const { secretKey, publicKey } = bls.keygen();
    cSigners.push({ index: i + 1, sk: secretKey, pk: publicKey, sig: null });
  }
  const keygenMs = (performance.now() - t0).toFixed(1);

  ($('#c-sign') as HTMLButtonElement).disabled = false;
  ($('#c-aggregate') as HTMLButtonElement).disabled = true;

  renderSignerGrid(false);
  cOutput().innerHTML = `
    <div class="timing">
      <div class="timing-item"><span class="timing-label">${n} keypairs:</span><span class="timing-value">${keygenMs}ms</span></div>
    </div>
  `;
});

function renderSignerGrid(showSig: boolean) {
  const cards = cSigners.map((s) => {
    const pkHex = truncHex(s.pk.toHex(), 8);
    const sigHex = s.sig ? truncHex(s.sig.toHex(), 8) : '—';
    return `
      <div class="signer-card" data-index="${s.index}">
        <div class="signer-index">#${s.index}</div>
        <div class="signer-pk">PK: ${pkHex}</div>
        ${showSig ? `<div class="signer-sig">σ: ${sigHex}</div>` : ''}
        ${showSig && s.sig ? '<span class="badge valid" style="font-size:0.7rem;margin-top:0.25rem">✅</span>' : ''}
      </div>
    `;
  });
  cGrid().innerHTML = cards.join('');
}

$('#c-sign').addEventListener('click', () => {
  const msg = ($('#c-msg') as HTMLInputElement).value;
  const encoded = new TextEncoder().encode(msg);

  const t0 = performance.now();
  cHashedMsg = bls.hash(encoded);
  for (const s of cSigners) {
    s.sig = bls.sign(cHashedMsg, s.sk);
  }
  const signMs = (performance.now() - t0).toFixed(1);

  ($('#c-aggregate') as HTMLButtonElement).disabled = false;
  renderSignerGrid(true);

  cOutput().innerHTML += `
    <div class="timing">
      <div class="timing-item"><span class="timing-label">${cSigners.length} signs:</span><span class="timing-value">${signMs}ms</span></div>
    </div>
  `;
});

$('#c-aggregate').addEventListener('click', async () => {
  if (!cHashedMsg || cSigners.some((s) => !s.sig)) return;
  const n = cSigners.length;

  // Animate merge
  const cards = cGrid().querySelectorAll('.signer-card');
  cards.forEach((card, i) => {
    setTimeout(() => card.classList.add('merging'), i * 30);
  });

  await new Promise((r) => setTimeout(r, Math.min(n * 30 + 400, 3400)));

  // Aggregate
  const sigs = cSigners.map((s) => s.sig!);
  const pks = cSigners.map((s) => s.pk);

  const t0 = performance.now();
  const aggSig = bls.aggregateSignatures(sigs);
  const aggPk = bls.aggregatePublicKeys(pks);
  const aggMs = (performance.now() - t0).toFixed(1);

  const t1 = performance.now();
  const aggValid = bls.verify(aggSig, cHashedMsg, aggPk);
  const aggVerifyMs = (performance.now() - t1).toFixed(1);

  // Estimate individual verify time
  const t2 = performance.now();
  bls.verify(sigs[0], cHashedMsg, pks[0]);
  const singleVerifyMs = performance.now() - t2;
  const estIndividualMs = (singleVerifyMs * n).toFixed(1);

  const savings = ((1 - parseFloat(aggVerifyMs) / parseFloat(estIndividualMs)) * 100).toFixed(0);

  // Show merged card
  cGrid().innerHTML = `
    <div class="signer-card aggregate">
      <div class="signer-index">Aggregated (${n} signers)</div>
      <div class="output-block" style="margin:0.5rem 0">
        <div class="label">Aggregate Signature (48 bytes G₁)</div>
        <div class="value g1">${aggSig.toHex()}</div>
      </div>
      <div class="output-block" style="margin:0.5rem 0">
        <div class="label">Aggregate Public Key (96 bytes G₂)</div>
        <div class="value g2">${aggPk.toHex()}</div>
      </div>
      <div style="margin-top:0.5rem">
        ${aggValid ? '<span class="badge valid">✅ AGGREGATE VALID</span>' : '<span class="badge invalid">❌ AGGREGATE INVALID</span>'}
      </div>
    </div>
  `;

  cOutput().innerHTML = `
    <div class="metric-banner">
      <strong>${n} signatures → 1 verification</strong><br>
      Individual: ${estIndividualMs}ms &nbsp;|&nbsp; Aggregate verify: ${aggVerifyMs}ms &nbsp;|&nbsp; Savings: ${savings}%
    </div>
    <div class="timing">
      <div class="timing-item"><span class="timing-label">Aggregation:</span><span class="timing-value">${aggMs}ms</span></div>
      <div class="timing-item"><span class="timing-label">Agg verify:</span><span class="timing-value">${aggVerifyMs}ms</span></div>
      <div class="timing-item"><span class="timing-label">Est. individual (×${n}):</span><span class="timing-value">${estIndividualMs}ms</span></div>
    </div>
  `;
});
