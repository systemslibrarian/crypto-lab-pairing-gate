import cssText from './style.css?inline';

// Inject styles synchronously as an inline <style> so there is no
// render-blocking stylesheet request before first paint.
{
  const styleEl = document.createElement('style');
  styleEl.textContent = cssText;
  document.head.appendChild(styleEl);
}

// Crypto is loaded lazily (see loadCrypto) so the heavy BLS12-381 field-tower
// code never blocks first paint. Types come from a type-only import expression,
// which is erased at build time and triggers no runtime download.
type Bls12 = (typeof import('@noble/curves/bls12-381.js'))['bls12_381'];
type ShortSigs = Bls12['shortSignatures'];
type PubKey = ReturnType<ShortSigs['getPublicKey']>;
type Sig = ReturnType<ShortSigs['sign']>;
type Hashed = ReturnType<ShortSigs['hash']>;
type G2Point = Bls12['G2']['Point']['BASE'];
type G1Point = Bls12['G1']['Point']['BASE'];

let bls12_381!: Bls12;
let bls!: ShortSigs;
let G1GEN!: G1Point;
let G2GEN!: G2Point;
let cryptoReady: Promise<void> | null = null;
function loadCrypto(): Promise<void> {
  if (!cryptoReady) {
    cryptoReady = import('@noble/curves/bls12-381.js').then((m) => {
      bls12_381 = m.bls12_381;
      bls = bls12_381.shortSignatures; // G1 signatures (48 bytes), G2 keys (96 bytes)
      G1GEN = bls12_381.G1.Point.BASE;
      G2GEN = bls12_381.G2.Point.BASE;
    });
  }
  return cryptoReady;
}

// ============================================================
// Helpers
// ============================================================
// Typed query helper — returns the element as the requested type so call
// sites don't need repeated `as HTMLButtonElement` casts.
const $ = <T extends Element = HTMLElement>(sel: string): T =>
  document.querySelector<T>(sel)!;

const bytesToHex = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const hexToBytes = (hex: string): Uint8Array => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
const truncHex = (hex: string, bytes = 32): string =>
  hex.length > bytes * 2 ? hex.slice(0, bytes * 2) + '…' : hex;

// Truncated hex with the first nibble that differs from `other` highlighted.
const markFirstDiff = (hex: string, other: string, bytes = 32): string => {
  const shown = hex.slice(0, bytes * 2);
  let i = 0;
  while (i < shown.length && shown[i] === other[i]) i++;
  if (i >= shown.length) return shown + '…';
  return `${shown.slice(0, i)}<mark class="diff-mark">${shown[i]}</mark>${shown.slice(i + 1)}…`;
};

// Copy-to-clipboard button (hex is [0-9a-f] only, so safe to inline as an attribute)
const copyBtn = (text: string, what: string): string =>
  `<button type="button" class="copy-btn" data-copy="${text}" aria-label="Copy ${what} to clipboard">Copy</button>`;

// Announce a short message in a polite role=status region (screen readers).
const announce = (id: string, msg: string): void => {
  const el = document.getElementById(id);
  if (el) el.textContent = msg;
};

const setDisabled = (sel: string, v: boolean): void => {
  $<HTMLButtonElement>(sel).disabled = v;
};

const pkBytes = (pk: PubKey): Uint8Array => hexToBytes(pk.toHex());

// GT (Fp12) pairing value as a hex string.
const gtHex = (g1: Sig | Hashed, g2: PubKey | G2Point): string =>
  bytesToHex(bls12_381.fields.Fp12.toBytes(bls12_381.pairing(g1 as Sig, g2 as PubKey)));

// Full 576-byte G_T (Fp12) value from a raw pairing of a G1 and G2 point.
const pairHex = (g1: G1Point, g2: G2Point): string =>
  bytesToHex(bls12_381.fields.Fp12.toBytes(bls12_381.pairing(g1 as Sig, g2 as PubKey)));

// e(P,Q)^k as a full 576-byte hex string (Fp12 exponentiation of a pairing value).
const pairPowHex = (g1: G1Point, g2: G2Point, k: bigint): string => {
  const Fp12 = bls12_381.fields.Fp12;
  return bytesToHex(Fp12.toBytes(Fp12.pow(bls12_381.pairing(g1 as Sig, g2 as PubKey), k)));
};

// Yield to the browser so long crypto loops don't freeze the tab. Returns
// total *compute* time only (idle/paint time during yields is excluded), so
// the displayed timing stays honest.
async function timedChunkedLoop(
  n: number,
  work: (i: number) => void,
  onProgress: (done: number) => void,
): Promise<number> {
  let computeMs = 0;
  for (let i = 0; i < n; i++) {
    const s = performance.now();
    work(i);
    computeMs += performance.now() - s;
    if ((i & 7) === 7 && i < n - 1) {
      onProgress(i + 1);
      await new Promise((r) => requestAnimationFrame(r));
    }
  }
  return computeMs;
}

const reduceMotion = (): boolean =>
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const isNarrow = (): boolean => window.innerWidth < 640;

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
    btn.setAttribute('aria-label', `Switch to ${t === 'dark' ? 'light' : 'dark'} mode`);
  }
}

// ============================================================
// Render HTML
// ============================================================
document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<button id="theme-toggle" class="theme-toggle" aria-label="Switch to light mode">🌙</button>
<header class="cl-hero">
  <div class="cl-hero-main">
    <h1 class="cl-hero-title">Pairing Gate</h1>
    <p class="cl-hero-sub">BLS Signatures · BLS12-381</p>
    <p class="cl-hero-desc">Generate keypairs, sign and verify with real pairing arithmetic, then watch n signatures aggregate into one that verifies with a constant 2 pairings.</p>
  </div>
  <aside class="cl-hero-why" aria-label="Why it matters">
    <span class="cl-hero-why-label">WHY IT MATTERS</span>
    <p class="cl-hero-why-text">Aggregate BLS signatures collapse thousands of validator votes into one constant-size check — the reason Ethereum's consensus depends on them. That same bilinearity enables the rogue-key attack, and its Proof-of-Possession fix.</p>
  </aside>
  <a class="portfolio-link" href="https://systemslibrarian.github.io/crypto-lab/">← crypto-lab portfolio</a>
</header>

<main id="main-content" tabindex="-1">

<!-- ======== Section A: What is a pairing? ======== -->
<section class="demo-section" id="section-a">
  <h2>A — What Is a Pairing?</h2>

  <p class="lead-in">In one sentence: <strong>a pairing is a special kind of multiplication that lets you check a hidden relationship between two secrets without ever learning the secrets themselves.</strong> Feed it one point from group <span class="g1">G₁</span> and one from group <span class="g2">G₂</span>, and it returns a single value in a third group <span class="gt">G<sub>T</sub></span>. The one magical rule it obeys — that scalars slide freely between the two inputs — is what makes both BLS verification and thousand-signature aggregation possible. The playground below lets you <em>feel</em> that rule before we name any of the machinery.</p>

  <h3>A1 — Bilinearity Playground</h3>
  <p>Bilinearity is the single load-bearing property of the whole demo. It says: multiplying an input point by a scalar is the <em>same</em> as raising the pairing's output to that scalar. So four computations that look completely different —</p>
  <div class="math-block">
    e(<span class="g1">aP</span>, <span class="g2">bQ</span>) &nbsp;=&nbsp; e(<span class="g1">P</span>, <span class="g2">Q</span>)<sup>ab</sup> &nbsp;=&nbsp; e(<span class="g1">abP</span>, <span class="g2">Q</span>) &nbsp;=&nbsp; e(<span class="g1">P</span>, <span class="g2">abQ</span>)
  </div>
  <p>— must all land on the <strong>exact same <span class="gt">G<sub>T</sub></span> element</strong>. Drag <code>a</code> and <code>b</code> and watch four unrelated-looking pairings collapse onto one identical value, computed live with real BLS12-381 arithmetic (P = G₁ generator, Q = G₂ generator).</p>
  <div class="field-group">
    <label for="pg-a">Scalar a = <span id="pg-a-display">3</span></label>
    <input type="range" id="pg-a" min="1" max="20" value="3" aria-valuetext="a equals 3">
  </div>
  <div class="field-group">
    <label for="pg-b">Scalar b = <span id="pg-b-display">5</span></label>
    <input type="range" id="pg-b" min="1" max="20" value="5" aria-valuetext="b equals 5">
  </div>
  <div id="pg-output" class="playground-output"></div>
  <p id="pg-status" role="status" class="sr-only"></p>
  <p class="note">This is exactly why pairings are useful: they let a scalar (like a secret key) move from one side of an equation to the other. Signature verification is just this identity with <code>a = sk</code>: <code>e(sk·H, G₂) = e(H, sk·G₂)</code>. Non-degeneracy (below) guarantees the output isn't the trivial value 1, so the equality actually carries information.</p>

  <h3>A2 — The Three Groups</h3>
  <p>BLS12-381 defines three algebraic groups used in pairing-based cryptography:</p>
  <div class="group-boxes">
    <div class="group-box g1">
      <div class="group-label">G₁ <span class="group-tag">source</span></div>
      <div class="group-detail">Points on E(𝔽<sub>p</sub>)<br>48-byte compressed<br>Fast operations</div>
    </div>
    <div class="group-box g2">
      <div class="group-label">G₂ <span class="group-tag">source</span></div>
      <div class="group-detail">Points on E(𝔽<sub>p²</sub>)<br>96-byte compressed<br>Slower operations</div>
    </div>
    <div class="group-box gt">
      <div class="group-label">G<sub>T</sub> <span class="group-tag">target</span></div>
      <div class="group-detail">Target group in 𝔽<sub>p¹²</sub><br>576 bytes<br>Pairing output</div>
    </div>
  </div>
  <div class="note">BLS12-381 was designed by Sean Bowe (Zcash) to achieve ~128-bit classical security with efficient pairings. The colours <span class="g1">G₁</span>, <span class="g2">G₂</span>, and <span class="gt">G<sub>T</sub></span> are reused throughout this page (each is also labelled in text).</div>

  <h3>A3 — The Pairing's Three Properties</h3>
  <p>A pairing <code>e : G₁ × G₂ → G<sub>T</sub></code> is a bilinear map with three key properties:</p>
  <div class="math-block">
    <strong>Bilinearity:</strong> e(<span class="g1">aP</span>, <span class="g2">bQ</span>) = e(<span class="g1">P</span>, <span class="g2">Q</span>)<sup>ab</sup>
  </div>
  <div class="math-block">
    <strong>Non-degeneracy:</strong> e(<span class="g1">P</span>, <span class="g2">Q</span>) ≠ 1 when P, Q are generators
  </div>
  <div class="math-block">
    <strong>Efficiency:</strong> Computable in polynomial time (Ate pairing on BLS12-381)
  </div>
  <p>Bilinearity is powerful because it lets you move scalar multiplication between arguments. This algebraic property is the foundation of signature aggregation: <code>e(sk·H, G₂) = e(H, sk·G₂)</code>.</p>

  <details class="gory-details">
    <summary>The gory details: field towers, embedding degree, and the Ate pairing</summary>
    <div class="gory-body">
      <p>Under the hood, the three groups live in a tower of extension fields built on the 381-bit base prime <em>p</em>. <span class="g1">G₁</span> is a subgroup of the curve over the base field 𝔽<sub>p</sub>; <span class="g2">G₂</span> lives over the quadratic extension 𝔽<sub>p²</sub> (which is why its points are twice as big); and the target <span class="gt">G<sub>T</sub></span> is the group of <em>r</em>-th roots of unity inside the degree-12 extension 𝔽<sub>p¹²</sub> — hence a G<sub>T</sub> element serialises to 12 × 48 = <strong>576 bytes</strong>.</p>
      <p>The number 12 is the <strong>embedding degree</strong> <em>k</em>: the smallest <em>k</em> such that the group order <em>r</em> divides <em>p<sup>k</sup> − 1</em>. It has to be small enough that arithmetic in 𝔽<sub>p¹²</sub> is tractable, yet large enough that the discrete log there stays as hard as an RSA key of comparable size — <em>k</em> = 12 is the sweet spot for the ~128-bit security target.</p>
      <p>The pairing itself is computed as an <strong>optimal Ate pairing</strong>: a Miller loop that accumulates line functions along a scalar multiplication, followed by a <em>final exponentiation</em> to <em>(p¹² − 1)/r</em> that maps the result into the unique G<sub>T</sub> coset. The final exponentiation is what makes <code>e(P,Q)</code> a well-defined single value you can compare byte-for-byte — which is precisely what the demos below do.</p>
    </div>
  </details>

  <h3>A4 — Why BLS12-381 Specifically?</h3>
  <p>Curve parameters:</p>
  <div class="table-wrap" tabindex="0" role="region" aria-label="BLS12-381 curve parameters (scrollable table)">
  <table>
    <caption>BLS12-381 Curve Parameters</caption>
    <thead>
      <tr><th scope="col">Parameter</th><th scope="col">Value</th></tr>
    </thead>
    <tbody>
      <tr><th scope="row">Embedding degree</th><td>k = 12 (required for efficient pairings)</td></tr>
      <tr><th scope="row">Field size</th><td>381 bits</td></tr>
      <tr><th scope="row">Scalar field</th><td>255-bit prime order r (≈ 2²⁵⁵; comparable to Ed25519's ~252-bit scalar)</td></tr>
      <tr><th scope="row">Classical security</th><td>~128 bits</td></tr>
      <tr><th scope="row">Quantum security</th><td>None — Shor's algorithm recovers sk from PK in polynomial time</td></tr>
    </tbody>
  </table>
  </div>
  <p class="note">Like all elliptic-curve and pairing-based schemes, BLS has <strong>no</strong> post-quantum security: a large quantum computer running Shor's algorithm solves the discrete-log problem outright. Grover's algorithm only gives a square-root speedup against <em>symmetric</em> primitives — it does not apply to the discrete-log assumption that secures BLS.</p>
  <p>BLS12-381 was chosen for Zcash Sapling (2018) and later adopted by Ethereum 2.0 (2020). The "12" in BLS12-381 is the embedding degree; the "381" is the field size in bits.</p>
</section>

<!-- ======== Section B: BLS Signature Scheme ======== -->
<section class="demo-section" id="section-b">
  <h2>B — BLS Signature Scheme</h2>

  <h3>B1 — The Three Algorithms</h3>
  <p><strong>Key generation:</strong> Private key sk ∈ ℤ<sub>r</sub> (random scalar). Public key <span class="g2">PK = sk · G₂</span> (G₂ point, 96 bytes).</p>
  <p><strong>Signing:</strong> Hash message to G₁: <span class="g1">H = hash_to_curve(message)</span>. Signature: <span class="g1">σ = sk · H</span> (G₁ point, 48 bytes).</p>

  <aside class="explainer" aria-label="What is hash-to-curve">
    <div class="explainer-head">What is <code>hash_to_curve</code>?</div>
    <div class="explainer-body">
      <p>An ordinary hash like SHA-256 turns a message into <em>random bytes</em>. But BLS needs the message as an actual <span class="g1">point that sits on the elliptic curve</span> — you can't just reinterpret hash bytes as coordinates, because most random (x, y) pairs don't land on the curve. <code>hash_to_curve</code> (standardised in RFC 9380) does the extra work: it hashes the message, maps the result onto a valid curve point, and clears the cofactor so the point lands in the prime-order subgroup <span class="g1">G₁</span>. The output <span class="g1">H</span> is deterministic (same message → same point) and, crucially, nobody knows its discrete log — so it behaves like a random oracle, which the security proof needs.</p>
      <div class="htc-visual" aria-hidden="true">
        <span class="htc-bytes">"slot 9841203"</span>
        <span class="htc-arrow">→ hash_to_curve →</span>
        <span class="htc-curve">
          <svg viewBox="0 0 90 46" role="img" aria-label="a point sitting on an elliptic curve">
            <path d="M6 40 C 20 40, 22 8, 40 8 S 70 40, 84 40" fill="none" stroke="currentColor" stroke-width="1.6"/>
            <circle cx="52" cy="14.5" r="3.5" class="htc-dot"/>
          </svg>
          <span class="htc-label"><span class="g1">H</span> ∈ G₁</span>
        </span>
      </div>
    </div>
  </aside>
  <p><strong>Verification:</strong> Check the pairing equation:</p>
  <div class="math-block">
    e(<span class="g1">σ</span>, <span class="g2">G₂</span>) = e(<span class="g1">H</span>, <span class="g2">PK</span>)
  </div>
  <p>This works because <code>e(sk·H, G₂) = e(H, G₂)^sk = e(H, sk·G₂) = e(H, PK)</code>. <strong>Verification is nothing more than checking that these two pairings land on the <span class="gt">same G<sub>T</sub> element</span></strong> — the demo below proves that byte-for-byte.</p>

  <h3>B2 — Live Sign / Verify</h3>
  <div class="field-group">
    <label for="b-msg">Message</label>
    <input type="text" id="b-msg" value="Ethereum validator attestation: slot 9841203">
  </div>
  <div class="controls">
    <button id="b-keygen" class="primary">Generate Keypair</button>
    <button id="b-sign" disabled>Sign</button>
    <button id="b-verify" disabled>Verify</button>
    <button id="b-tamper" class="danger" disabled>Flip One Bit</button>
    <button id="b-reset" class="ghost" disabled>Reset</button>
  </div>
  <div id="b-verdict" class="verdict-region"></div>
  <div id="b-output"></div>
  <p id="b-status" role="status" class="sr-only"></p>
</section>

<!-- ======== Section C: Signature Aggregation ======== -->
<section class="demo-section" id="section-c">
  <h2>C — Signature Aggregation</h2>

  <h3>C1 — The Aggregation Property</h3>
  <p>Because pairings are bilinear, BLS signatures from different signers <strong>on the same message</strong> can be combined:</p>
  <div class="math-block">
    <span class="g1">σ<sub>agg</sub></span> = σ₁ + σ₂ + … + σ<sub>n</sub> &nbsp;(point addition in <span class="g1">G₁</span>)
  </div>
  <div class="math-block">
    <span class="g2">PK<sub>agg</sub></span> = PK₁ + PK₂ + … + PK<sub>n</sub> &nbsp;(point addition in <span class="g2">G₂</span>)
  </div>
  <div class="math-block">
    <strong>Verify aggregate:</strong> e(<span class="g1">σ<sub>agg</sub></span>, <span class="g2">G₂</span>) = e(<span class="g1">H(msg)</span>, <span class="g2">PK<sub>agg</sub></span>)
  </div>
  <div class="table-wrap" tabindex="0" role="region" aria-label="Aggregation cost comparison (scrollable table)">
  <table>
    <caption>Aggregation Cost Comparison (same message)</caption>
    <thead>
      <tr><th scope="col">Approach</th><th scope="col">Pairings required</th><th scope="col">Verification cost</th></tr>
    </thead>
    <tbody>
      <tr><th scope="row">Verify n signatures individually</th><td>2n</td><td>O(n)</td></tr>
      <tr><th scope="row">Aggregate then verify</th><td>2</td><td>O(1)</td></tr>
    </tbody>
  </table>
  </div>
  <p class="note">The drop to <strong>2 pairings</strong> depends on every signer signing the <strong>same</strong> message. If the messages differ, the aggregate no longer collapses and verification costs one pairing per distinct message (O(n)) — see Section D, defense&nbsp;2.</p>

  <h3>C2 — Live Aggregation Demo</h3>
  <div class="field-group">
    <label for="c-count">Signers: <span id="c-count-display">10</span></label>
    <input type="range" id="c-count" min="2" max="100" value="10" aria-valuetext="10 signers" aria-describedby="c-count-hint">
    <span id="c-count-hint" class="field-hint">Higher counts do more on-device crypto; 100 signers can take a moment on phones.</span>
  </div>
  <div class="field-group">
    <label for="c-msg">Message</label>
    <input type="text" id="c-msg" value="Block 21847293: propose and attest">
  </div>
  <div class="controls">
    <button id="c-keygen" class="primary">Generate All Keypairs</button>
    <button id="c-sign" disabled>Sign All</button>
    <button id="c-aggregate" disabled>Aggregate &amp; Verify</button>
    <button id="c-reset" class="ghost" disabled>Reset</button>
  </div>
  <div id="c-grid" class="signer-grid" role="group" aria-label="Signer keypairs"></div>
  <div id="c-output"></div>
  <p id="c-status" role="status" class="sr-only"></p>
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
      <p class="key-card-note">(Registers key honestly)</p>
    </div>
    <div class="key-card malicious">
      <div class="key-card-title">⚠ Attacker</div>
      <p>PK₂ = sk₂ · G₂ − PK₁</p>
      <p class="key-card-note">(Maliciously chosen to cancel PK₁)</p>
    </div>
  </div>
  <p>Aggregate key: PK<sub>agg</sub> = PK₁ + PK₂ = sk₂ · G₂. The attacker signs alone with sk₂ and the aggregate signature verifies — forging a signature that appears to be from both signers.</p>

  <h3>D2 — Watch It Happen (live)</h3>
  <p class="note" style="border-left-color:var(--error)">This panel runs <strong>naive, deliberately broken</strong> aggregation with no rogue-key protection — exactly what you must <em>not</em> ship.</p>
  <div class="controls">
    <button id="d-attack" class="danger">Forge a 2-of-2 Signature</button>
    <button id="d-defend" disabled>Apply Proof-of-Possession</button>
    <button id="d-reset" class="ghost" disabled>Reset</button>
  </div>
  <div id="d-output"></div>
  <p id="d-status" role="status" class="sr-only"></p>

  <h3>D3 — Defenses</h3>
  <div class="defense-list">
    <div class="defense-item">
      <h4>1. Proof of Possession (PoP) — used by Ethereum</h4>
      <p>Each signer registers a signature of their own public key, proving knowledge of the private key before the public key is accepted. Requires one extra signature per signer during registration — not during signing. The attacker can't produce a valid PoP for a rogue key because they don't know its discrete log.</p>
    </div>
    <div class="defense-item">
      <h4>2. Message Augmentation</h4>
      <p>Each signer includes their public key in the signed message: sign <code>PK_i ‖ message</code> instead of <code>message</code>. Aggregation still works, but because every signer now signs a <em>different</em> message, the aggregate verification needs n+1 pairings (one per distinct message) — it becomes O(n), losing the O(1) benefit.</p>
    </div>
    <div class="defense-item">
      <h4>3. Hash-to-scalar Rogue Key Prevention</h4>
      <p>Multiply each signer's contribution by a hash of all public keys: <code>t_i = H(i, PK₁,…,PK_n)</code>. Aggregate: <code>σ_agg = Σ t_i · σ_i</code>, <code>PK_agg = Σ t_i · PK_i</code>. Prevents the attack but requires knowing all public keys before aggregating.</p>
    </div>
  </div>

  <h3>D4 — What Ethereum Does</h3>
  <p>Ethereum 2.0 uses Proof of Possession. Validators register a PoP signature (signing their own public key) when depositing 32 ETH. The beacon chain verifies PoP before accepting any validator's key into the active set. After that, aggregation proceeds with the O(1) verification property intact.</p>
</section>

<!-- ======== Section E: Where Pairings Appear ======== -->
<section class="demo-section" id="section-e">
  <h2>E — Where Pairings Appear</h2>

  <h3>Production Deployments</h3>
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

  <h3>Size Comparison</h3>
  <div class="table-wrap" tabindex="0" role="region" aria-label="Signature scheme size comparison (scrollable table)">
  <table>
    <caption>Signature Scheme Size Comparison</caption>
    <thead>
      <tr><th scope="col">Scheme</th><th scope="col">Public key</th><th scope="col">Signature</th><th scope="col">Verification</th></tr>
    </thead>
    <tbody>
      <tr><th scope="row">Ed25519</th><td>32 bytes</td><td>64 bytes</td><td>Fast (no pairing)</td></tr>
      <tr><th scope="row">ECDSA P-256</th><td>64 bytes</td><td>64 bytes</td><td>Fast (no pairing)</td></tr>
      <tr><th scope="row">BLS (G₁ sig, G₂ key)</th><td>96 bytes</td><td>48 bytes</td><td>Slow (2 pairings)</td></tr>
      <tr><th scope="row">BLS aggregate (n signers)</th><td>96 bytes</td><td>48 bytes</td><td>Slow (2 pairings)</td></tr>
    </tbody>
  </table>
  </div>
  <p class="note">This demo uses the <strong>short-signature</strong> variant of BLS: signatures live in <span class="g1">G₁</span> (48 bytes) and public keys in <span class="g2">G₂</span> (96 bytes). BLS is symmetric — you can swap the two groups. The other variant (keys in G₁, signatures in G₂) gives 48-byte keys and 96-byte signatures, which is why you may have read "BLS signatures are 96 bytes" elsewhere. The swap is a deliberate tradeoff: putting signatures in the smaller, faster group makes <em>signing and signature storage</em> cheaper — the right choice for Ethereum, where every validator emits a signature every slot — at the cost of larger, slower public keys.</p>
  <p>The last two rows are identical — <strong>n signatures cost the same to verify as 1</strong>. That is the point.</p>
</section>

</main>

<footer>
  <a href="https://systemslibrarian.github.io/crypto-lab/">crypto-lab portfolio</a>
  <p class="related-demos">Related demos:
    <a href="https://systemslibrarian.github.io/crypto-lab-ibe-gate/">crypto-lab-ibe-gate</a> ·
    <a href="https://systemslibrarian.github.io/crypto-lab-frost-threshold/">crypto-lab-frost-threshold</a> ·
    <a href="https://systemslibrarian.github.io/crypto-lab-ed25519-forge/">crypto-lab-ed25519-forge</a> ·
    <a href="https://systemslibrarian.github.io/crypto-lab-zk-proof-lab/">crypto-lab-zk-proof-lab</a></p>
  <p class="scripture">"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31</p>
</footer>

<p id="copy-status" role="status" class="sr-only"></p>
`;

// ============================================================
// Init theme toggle
// ============================================================
setTheme(currentTheme());
document.getElementById('theme-toggle')!.addEventListener('click', () => {
  setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
});

// ============================================================
// Copy-to-clipboard (event delegation for dynamically rendered buttons)
// ============================================================
document.addEventListener('click', async (e) => {
  const btn = (e.target as HTMLElement).closest('.copy-btn') as HTMLButtonElement | null;
  if (!btn) return;
  const text = btn.dataset.copy ?? '';
  try {
    await navigator.clipboard.writeText(text);
    btn.classList.add('copied');
    btn.textContent = 'Copied';
    announce('copy-status', 'Copied to clipboard.');
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.textContent = 'Copy';
    }, 1400);
  } catch {
    btn.textContent = 'Press Ctrl+C';
    announce('copy-status', 'Copy failed — press Ctrl+C to copy the selected value.');
  }
});

// ============================================================
// Crypto warm-up: load the library and absorb the one-time lazy field-table
// init on the FIRST user interaction (not at load), so the heavy BLS eval
// stays off the initial-render critical path.
// ============================================================
let warmed = false;
async function warmup() {
  if (warmed) return;
  warmed = true;
  try {
    await loadCrypto();
    const { secretKey, publicKey } = bls.keygen();
    const h = bls.hash(new Uint8Array([0x01]));
    const s = bls.sign(h, secretKey);
    bls.verify(s, h, publicKey); // exercises the pairing / Fp12 path
  } catch {
    /* warm-up is best-effort */
  }
}
for (const ev of ['pointerdown', 'pointermove', 'keydown', 'touchstart'] as const) {
  window.addEventListener(ev, warmup, { once: true, passive: true });
}

// ============================================================
// Section A — Bilinearity Playground
// e(aP, bQ) = e(P, Q)^ab = e(abP, Q) = e(P, abQ) — four different-looking
// computations, all landing on the SAME G_T element, computed live.
// ============================================================
const pgA = () => $<HTMLInputElement>('#pg-a');
const pgB = () => $<HTMLInputElement>('#pg-b');
const pgOut = () => $<HTMLDivElement>('#pg-output');
let pgShowFull = false;
let pgLastHexes: { label: string; expr: string; hex: string }[] = [];
let pgRenderToken = 0;

// Render the four rows. When all four hexes match (they always will — this is a
// real algebraic identity), show a byte-count match badge and offer the full
// 576-byte reveal so the equality is airtight, not just a matching prefix.
function pgRenderRows(): void {
  const allEqual = pgLastHexes.every((r) => r.hex === pgLastHexes[0].hex);
  const totalBytes = pgLastHexes[0] ? pgLastHexes[0].hex.length / 2 : 0;
  const rows = pgLastHexes
    .map(
      (r) => `
    <div class="pg-row">
      <div class="pg-expr"><span class="pg-expr-name">${r.label}</span> ${r.expr}</div>
      <div class="value gt pg-value${pgShowFull ? ' full' : ''}">${
        pgShowFull ? r.hex : truncHex(r.hex)
      }</div>
    </div>`,
    )
    .join('');
  const badge = allEqual
    ? `<span class="badge valid">✅ IDENTICAL — all ${totalBytes}/${totalBytes} G_T bytes match</span>`
    : '<span class="badge invalid">❌ mismatch</span>';
  pgOut().innerHTML = `
    <div class="verdict-head">${badge}
      <button type="button" id="pg-toggle" class="reveal-btn" aria-expanded="${pgShowFull}">${
        pgShowFull ? 'Hide full G_T value' : 'Show full 576-byte G_T value'
      }</button>
      ${copyBtn(pgLastHexes[0]?.hex ?? '', 'the shared G_T value')}
    </div>
    ${rows}
  `;
}

async function pgCompute(): Promise<void> {
  const token = ++pgRenderToken;
  const a = BigInt(pgA().value);
  const b = BigInt(pgB().value);
  pgA().setAttribute('aria-valuetext', `a equals ${a}`);
  pgB().setAttribute('aria-valuetext', `b equals ${b}`);
  $<HTMLSpanElement>('#pg-a-display').textContent = String(a);
  $<HTMLSpanElement>('#pg-b-display').textContent = String(b);
  try {
    await loadCrypto();
    if (token !== pgRenderToken) return; // a newer drag superseded this one
    const P = G1GEN;
    const Q = G2GEN;
    // Four genuinely different computations of the same G_T element.
    pgLastHexes = [
      { label: 'e(aP, bQ)', expr: `— scale both inputs (a=${a}, b=${b})`, hex: pairHex(P.multiply(a), Q.multiply(b)) },
      { label: 'e(P, Q)^ab', expr: `— pair generators, then exponentiate by ab=${a * b}`, hex: pairPowHex(P, Q, a * b) },
      { label: 'e(abP, Q)', expr: `— push both scalars into G₁ (abP)`, hex: pairHex(P.multiply(a * b), Q) },
      { label: 'e(P, abQ)', expr: `— push both scalars into G₂ (abQ)`, hex: pairHex(P, Q.multiply(a * b)) },
    ];
    pgRenderRows();
    announce(
      'pg-status',
      `With a=${a} and b=${b}, all four pairings produced the same G_T element.`,
    );
  } catch {
    pgOut().innerHTML = '<p class="error-text">Pairing computation failed unexpectedly. Please try again.</p>';
  }
}

pgA().addEventListener('input', () => void pgCompute());
pgB().addEventListener('input', () => void pgCompute());
pgOut().addEventListener('click', (e) => {
  if ((e.target as HTMLElement).id === 'pg-toggle') {
    pgShowFull = !pgShowFull;
    pgRenderRows();
  }
});
// Initial compute on first interaction/idle so it never blocks first paint.
pgOut().innerHTML = '<p class="empty-hint">Drag the sliders above to compute the four pairings.</p>';
{
  const kick = () => void pgCompute();
  if ('requestIdleCallback' in window)
    (window as unknown as { requestIdleCallback: (cb: () => void) => void }).requestIdleCallback(kick);
  else setTimeout(kick, 200);
}

// ============================================================
// Section B — BLS Sign / Verify
// ============================================================
interface BKeyState {
  sk: Uint8Array;
  pk: PubKey;
  sig: Sig | null;
  hashedMsg: Hashed | null;
  tampered: boolean;
}

let bState: BKeyState | null = null;
let bKeygenHtml = '';
let bVerifyHexes: { left: string; right: string; equal: boolean } | null = null;
let bShowFull = false;

const bOutput = () => $<HTMLDivElement>('#b-output');
const bVerdict = () => $<HTMLDivElement>('#b-verdict');

const B_HINT = '<p class="empty-hint">Step 1: generate a keypair to begin.</p>';
bOutput().innerHTML = B_HINT;

function resetB() {
  bState = null;
  bKeygenHtml = '';
  bOutput().innerHTML = B_HINT;
  bVerdict().innerHTML = '';
  setDisabled('#b-sign', true);
  setDisabled('#b-verify', true);
  setDisabled('#b-tamper', true);
  setDisabled('#b-reset', true);
  announce('b-status', 'Reset. Generate a keypair to begin.');
}

$('#b-reset').addEventListener('click', resetB);

// Editing the message invalidates a prior signature (it was over the old message).
$<HTMLInputElement>('#b-msg').addEventListener('input', () => {
  if (bState?.sig) {
    bState.sig = null;
    bState.hashedMsg = null;
    bState.tampered = false;
    setDisabled('#b-verify', true);
    setDisabled('#b-tamper', true);
    bVerdict().innerHTML = '<p class="empty-hint">Message changed — sign again.</p>';
    bOutput().innerHTML = bKeygenHtml;
    announce('b-status', 'Message changed. Sign again.');
  }
});

$('#b-keygen').addEventListener('click', async () => {
  try {
    await loadCrypto();
    const t0 = performance.now();
    const { secretKey, publicKey } = bls.keygen();
    const keygenMs = (performance.now() - t0).toFixed(1);

    bState = { sk: secretKey, pk: publicKey, sig: null, hashedMsg: null, tampered: false };
    setDisabled('#b-sign', false);
    setDisabled('#b-verify', true);
    setDisabled('#b-tamper', true);
    setDisabled('#b-reset', false);
    bVerdict().innerHTML = '';

    const skHex = bytesToHex(secretKey);
    const pkHex = publicKey.toHex();
    bKeygenHtml = `
      <div class="output-block">
        <div class="ob-head"><span class="label">Private key (32 bytes)</span>${copyBtn(skHex, 'private key')}</div>
        <div class="value">${skHex}</div>
      </div>
      <div class="output-block">
        <div class="ob-head"><span class="label">Public key (96 bytes compressed G₂)</span>${copyBtn(pkHex, 'public key')}</div>
        <div class="value g2">${pkHex}</div>
      </div>
      <div class="timing">
        <div class="timing-item"><span class="timing-label">Keygen:</span><span class="timing-value">${keygenMs}ms</span></div>
      </div>
      <p class="empty-hint">Step 2: sign the message above.</p>
    `;
    bOutput().innerHTML = bKeygenHtml;
    announce('b-status', 'Keypair generated. Now sign the message.');
  } catch {
    bVerdict().innerHTML = '<p class="error-text">Key generation failed unexpectedly. Please try again.</p>';
  }
});

$('#b-sign').addEventListener('click', async () => {
  if (!bState) return;
  try {
    await loadCrypto();
    const msg = $<HTMLInputElement>('#b-msg').value;
    const encoded = new TextEncoder().encode(msg);

    const t0 = performance.now();
    const hashedMsg = bls.hash(encoded);
    const sig = bls.sign(hashedMsg, bState.sk);
    const signMs = (performance.now() - t0).toFixed(1);

    bState.sig = sig;
    bState.hashedMsg = hashedMsg;
    bState.tampered = false;
    setDisabled('#b-verify', false);
    setDisabled('#b-tamper', false);
    bVerdict().innerHTML = '';

    const sigHex = sig.toHex();
    const hHex = hashedMsg.toHex();
    bOutput().innerHTML =
      bKeygenHtml.replace(/<p class="empty-hint">Step 2[^<]*<\/p>/, '') +
      `
      <div class="output-block">
        <div class="ob-head"><span class="label">Signature (48 bytes compressed G₁)</span>${copyBtn(sigHex, 'signature')}</div>
        <div class="value g1">${sigHex}</div>
      </div>
      <div class="output-block">
        <div class="ob-head"><span class="label">Hash-to-curve H(msg) (48 bytes G₁)</span>${copyBtn(hHex, 'hash')}</div>
        <div class="value g1">${hHex}</div>
      </div>
      <div class="timing">
        <div class="timing-item"><span class="timing-label">Sign:</span><span class="timing-value">${signMs}ms</span></div>
      </div>
      <p class="empty-hint">Step 3: verify the pairing equation — or flip a bit to break it.</p>
    `;
    announce('b-status', 'Message signed. Now verify, or flip a bit to break it.');
  } catch {
    bVerdict().innerHTML = '<p class="error-text">Signing failed unexpectedly. Please try again.</p>';
  }
});

$('#b-verify').addEventListener('click', async () => {
  if (!bState || !bState.sig || !bState.hashedMsg) return;
  try {
    await loadCrypto();
    const t0 = performance.now();
    const valid = bls.verify(bState.sig, bState.hashedMsg, bState.pk);
    const verifyMs = (performance.now() - t0).toFixed(1);

    // Pairing values for display, and an authoritative equality from FULL hex.
    const leftHex = gtHex(bState.sig, G2GEN);
    const rightHex = gtHex(bState.hashedMsg, bState.pk);
    const equal = leftHex === rightHex;

    const totalBytes = leftHex.length / 2;
    const chip = equal
      ? `<span class="badge valid">✅ MATCH — all ${totalBytes}/${totalBytes} G_T bytes identical</span>`
      : '<span class="badge invalid">❌ NO MATCH — different G_T elements</span>';

    const lead = equal
      ? '<p class="verdict-lead valid-text"><strong>e(σ, G₂) = e(H, PK).</strong> Both pairings produced the <em>same</em> G_T element — that equality <em>is</em> the signature check.</p>'
      : `<p class="verdict-lead error-text"><strong>e(σ, G₂) ≠ e(H, PK).</strong> ${
          bState.tampered ? 'The altered signature' : 'This signature'
        } maps to a different G_T element, so verification fails.</p>`;

    // Stash full hexes so the reveal toggle can swap truncated ↔ full 576 bytes.
    bVerifyHexes = { left: leftHex, right: rightHex, equal };
    bShowFull = false;
    const leftShown = equal ? truncHex(leftHex) : markFirstDiff(leftHex, rightHex);
    const rightShown = equal ? truncHex(rightHex) : markFirstDiff(rightHex, leftHex);

    bVerdict().innerHTML = `
      <div class="verdict-head">
        ${valid ? '<span class="badge valid">✅ VALID</span>' : '<span class="badge invalid">❌ INVALID</span>'}
        ${chip}
        ${equal ? `<button type="button" id="b-reveal" class="reveal-btn" aria-expanded="false">Show full ${totalBytes}-byte G_T values</button>` : ''}
      </div>
      ${lead}
      <div class="output-block">
        <div class="ob-head"><span class="label">e(σ, G₂) — left side</span>${copyBtn(leftHex, 'left pairing value')}</div>
        <div class="value gt" id="b-left-val">${leftShown}</div>
      </div>
      <div class="output-block">
        <div class="ob-head"><span class="label">e(H, PK) — right side</span>${copyBtn(rightHex, 'right pairing value')}</div>
        <div class="value gt" id="b-right-val">${rightShown}</div>
      </div>
      <div class="timing">
        <div class="timing-item"><span class="timing-label">Verify:</span><span class="timing-value">${verifyMs}ms</span></div>
      </div>
    `;
    announce(
      'b-status',
      valid
        ? 'Signature valid. The pairing e of sigma and G2 equals e of H and PK — the same G_T element.'
        : 'Signature invalid. The two pairings produced different G_T elements.',
    );
  } catch {
    bVerdict().innerHTML = '<p class="error-text">Verification failed unexpectedly. Please reset and try again.</p>';
  }
});

// Full-value reveal for the matching G_T pair: prove the equality across all
// 576 bytes, not just a shared 32-byte prefix.
bVerdict().addEventListener('click', (e) => {
  if ((e.target as HTMLElement).id !== 'b-reveal' || !bVerifyHexes) return;
  bShowFull = !bShowFull;
  const btn = $<HTMLButtonElement>('#b-reveal');
  const leftEl = document.getElementById('b-left-val');
  const rightEl = document.getElementById('b-right-val');
  const bytes = bVerifyHexes.left.length / 2;
  if (leftEl) {
    leftEl.textContent = bShowFull ? bVerifyHexes.left : truncHex(bVerifyHexes.left);
    leftEl.classList.toggle('gt-full', bShowFull);
  }
  if (rightEl) {
    rightEl.textContent = bShowFull ? bVerifyHexes.right : truncHex(bVerifyHexes.right);
    rightEl.classList.toggle('gt-full', bShowFull);
  }
  btn.textContent = bShowFull ? `Hide full ${bytes}-byte G_T values` : `Show full ${bytes}-byte G_T values`;
  btn.setAttribute('aria-expanded', String(bShowFull));
});

$('#b-tamper').addEventListener('click', async () => {
  if (!bState || !bState.sig) return;
  try {
    await loadCrypto();
    const sigBytes = bls.Signature.toBytes(bState.sig);
    let note = '';
    let done = false;

    // Try flipping one bit in a few interior bytes until we land on a valid,
    // different G₁ point. Report honestly which byte changed.
    for (const idx of [20, 10, 30, 5, 40]) {
      const tampered = new Uint8Array(sigBytes);
      tampered[idx] ^= 0x01;
      try {
        bState.sig = bls.Signature.fromBytes(tampered);
        note = `One bit of the signature was flipped (byte ${idx}). Click <strong>Verify</strong> to watch the pairing check fail.`;
        done = true;
        break;
      } catch {
        /* not a valid point encoding — try another byte */
      }
    }
    if (!done) {
      // Fallback: negate the signature (always a distinct valid point).
      bState.sig = bState.sig.negate();
      note = 'The signature was replaced with its negation (−σ), a different valid point. Click <strong>Verify</strong> to watch the pairing check fail.';
    }

    bState.tampered = true;
    setDisabled('#b-verify', false);
    bVerdict().innerHTML = `<div class="note" style="border-left-color:var(--error)">${note}</div>`;
    announce('b-status', 'Signature altered. Verify to see it fail.');
  } catch {
    bVerdict().innerHTML = '<p class="error-text">Could not alter the signature. Please reset and try again.</p>';
  }
});

// ============================================================
// Section C — Aggregation Demo
// ============================================================
interface Signer {
  index: number;
  sk: Uint8Array;
  pk: PubKey;
  sig: Sig | null;
}

let cSigners: Signer[] = [];
let cHashedMsg: Hashed | null = null;

const cGrid = () => $<HTMLDivElement>('#c-grid');
const cOutput = () => $<HTMLDivElement>('#c-output');
const cCountDisplay = () => $<HTMLSpanElement>('#c-count-display');
const cCountInput = () => $<HTMLInputElement>('#c-count');

const C_HINT = '<p class="empty-hint">Step 1: pick the number of signers, then generate keypairs.</p>';
cOutput().innerHTML = C_HINT;

function resetC() {
  cSigners = [];
  cHashedMsg = null;
  cGrid().innerHTML = '';
  cGrid().setAttribute('aria-busy', 'false');
  cOutput().innerHTML = C_HINT;
  setDisabled('#c-sign', true);
  setDisabled('#c-aggregate', true);
  setDisabled('#c-reset', true);
  announce('c-status', 'Reset. Generate keypairs to begin.');
}

$('#c-reset').addEventListener('click', resetC);

cCountInput().addEventListener('input', () => {
  cCountDisplay().textContent = cCountInput().value;
  cCountInput().setAttribute('aria-valuetext', `${cCountInput().value} signers`);
  // Changing the count invalidates any existing signer set.
  if (cSigners.length) {
    cSigners = [];
    cHashedMsg = null;
    cGrid().innerHTML = '';
    cOutput().innerHTML = '<p class="empty-hint">Signer count changed — generate keypairs again.</p>';
    setDisabled('#c-sign', true);
    setDisabled('#c-aggregate', true);
  }
});

// Changing the message invalidates existing signatures.
$<HTMLInputElement>('#c-msg').addEventListener('input', () => {
  if (cSigners.some((s) => s.sig)) {
    cHashedMsg = null;
    cSigners.forEach((s) => (s.sig = null));
    renderSignerGrid(false);
    setDisabled('#c-aggregate', true);
    cOutput().innerHTML = '<p class="empty-hint">Message changed — sign again.</p>';
    announce('c-status', 'Message changed. Sign again.');
  }
});

$('#c-keygen').addEventListener('click', async () => {
  await loadCrypto();
  const n = parseInt(cCountInput().value);
  cSigners = [];
  cHashedMsg = null;

  setDisabled('#c-keygen', true);
  setDisabled('#c-sign', true);
  setDisabled('#c-aggregate', true);
  const label = $<HTMLButtonElement>('#c-keygen');
  const originalLabel = 'Generate All Keypairs';
  cGrid().setAttribute('aria-busy', 'true');

  try {
    const computeMs = await timedChunkedLoop(
      n,
      (i) => {
        const { secretKey, publicKey } = bls.keygen();
        cSigners.push({ index: i + 1, sk: secretKey, pk: publicKey, sig: null });
      },
      (done) => {
        label.textContent = `Generating… ${done}/${n}`;
      },
    );

    setDisabled('#c-sign', false);
    setDisabled('#c-reset', false);
    renderSignerGrid(false);
    cOutput().innerHTML = `
      <div class="timing">
        <div class="timing-item"><span class="timing-label">${n} keypairs:</span><span class="timing-value">${computeMs.toFixed(1)}ms</span></div>
      </div>
      <p class="empty-hint">Step 2: sign all ${n} keypairs over the message.</p>
    `;
    announce('c-status', `${n} keypairs generated. Now sign all.`);
  } catch {
    cOutput().innerHTML = '<p class="error-text">Key generation failed unexpectedly. Please reset and try again.</p>';
  } finally {
    label.textContent = originalLabel;
    setDisabled('#c-keygen', false);
    cGrid().setAttribute('aria-busy', 'false');
  }
});

// Cap the number of rendered cards on small screens so 100 signers don't
// produce a giant wall (the full set is always kept in cSigners for the math).
function renderSignerGrid(showSig: boolean) {
  const cap = isNarrow() ? 15 : cSigners.length;
  const shown = cSigners.slice(0, cap);
  const cards = shown.map((s) => {
    const pkHex = truncHex(s.pk.toHex(), 8);
    const sigHex = s.sig ? truncHex(s.sig.toHex(), 8) : '—';
    return `
      <div class="signer-card" data-index="${s.index}">
        <div class="signer-index">#${s.index}</div>
        <div class="signer-pk">PK: ${pkHex}</div>
        ${showSig ? `<div class="signer-sig">σ: ${sigHex}</div>` : ''}
        ${
          showSig && s.sig
            ? '<span class="badge valid card-badge"><span aria-hidden="true">✅</span><span class="sr-only">signed</span></span>'
            : ''
        }
      </div>
    `;
  });
  if (cSigners.length > cap) {
    cards.push(
      `<div class="signer-card more-card">+${cSigners.length - cap} more<br><span class="more-note">(all included in aggregation)</span></div>`,
    );
  }
  cGrid().innerHTML = cards.join('');
}

$('#c-sign').addEventListener('click', async () => {
  if (!cSigners.length) return;
  await loadCrypto();
  const msg = $<HTMLInputElement>('#c-msg').value;
  const encoded = new TextEncoder().encode(msg);

  setDisabled('#c-sign', true);
  setDisabled('#c-keygen', true);
  const label = $<HTMLButtonElement>('#c-sign');

  try {
    cHashedMsg = bls.hash(encoded);
    const hashed = cHashedMsg;
    const computeMs = await timedChunkedLoop(
      cSigners.length,
      (i) => {
        cSigners[i].sig = bls.sign(hashed, cSigners[i].sk);
      },
      (done) => {
        label.textContent = `Signing… ${done}/${cSigners.length}`;
      },
    );

    setDisabled('#c-aggregate', false);
    renderSignerGrid(true);
    cOutput().innerHTML = `
      <div class="timing">
        <div class="timing-item"><span class="timing-label">${cSigners.length} signatures:</span><span class="timing-value">${computeMs.toFixed(1)}ms</span></div>
      </div>
      <p class="empty-hint">Step 3: aggregate all ${cSigners.length} signatures into one and verify.</p>
    `;
    announce('c-status', `${cSigners.length} signatures created. Now aggregate and verify.`);
  } catch {
    cOutput().innerHTML = '<p class="error-text">Signing failed unexpectedly. Please reset and try again.</p>';
  } finally {
    label.textContent = 'Sign All';
    setDisabled('#c-keygen', false);
  }
});

$('#c-aggregate').addEventListener('click', async () => {
  if (!cHashedMsg || cSigners.some((s) => !s.sig)) return;
  await loadCrypto();

  // Snapshot BEFORE any await so a concurrent keygen/sign can't corrupt us.
  const hashed = cHashedMsg;
  const sigs = cSigners.map((s) => s.sig!);
  const pks = cSigners.map((s) => s.pk);
  const n = sigs.length;

  const cKeygen = $<HTMLButtonElement>('#c-keygen');
  const cSign = $<HTMLButtonElement>('#c-sign');
  const prevKeygen = cKeygen.disabled;
  const prevSign = cSign.disabled;
  setDisabled('#c-aggregate', true);
  cKeygen.disabled = true;
  cSign.disabled = true;
  cGrid().setAttribute('aria-busy', 'true');

  try {
    // Mechanism-revealing merge animation (skipped under reduced-motion): each
    // σ card flies into a σ_agg pile and each PK card into a PK_agg pile — a
    // literal depiction of the point-addition sums σ_agg = Σσᵢ and PK_agg = ΣPKᵢ.
    // (The real aggregation math runs afterward on the FULL signer set, not just
    // the on-screen cards, so the visual illustrates but never fakes the result.)
    if (!reduceMotion()) {
      const cards = Array.from(cGrid().querySelectorAll<HTMLElement>('.signer-card'));
      const total = cards.length;
      cards.forEach((card, i) => {
        // Alternate which pile each card flies toward so both sums are visible.
        card.classList.add(i % 2 === 0 ? 'fly-left' : 'fly-right');
        setTimeout(() => card.classList.add('flying'), 120 + i * 24);
      });
      await new Promise((r) => setTimeout(r, Math.min(total * 24 + 520, isNarrow() ? 1300 : 2200)));
    }

    const t0 = performance.now();
    const aggSig = bls.aggregateSignatures(sigs);
    const aggPk = bls.aggregatePublicKeys(pks);
    const aggMs = (performance.now() - t0).toFixed(1);

    const t1 = performance.now();
    const aggValid = bls.verify(aggSig, hashed, aggPk);
    const aggVerifyMs = performance.now() - t1;

    // Surface the aggregate pairing equality explicitly (this is the n→1 payoff).
    const aggLeftHex = gtHex(aggSig, G2GEN);
    const aggRightHex = gtHex(hashed, aggPk);
    const aggEqual = aggLeftHex === aggRightHex;

    // Honest individual estimate: median of a small warm sample × n
    // (bounded work — never n verifies, which would freeze at n=100).
    bls.verify(sigs[0], hashed, pks[0]); // warm-up, discarded
    const k = Math.min(5, n);
    const samples: number[] = [];
    for (let i = 0; i < k; i++) {
      const s = performance.now();
      bls.verify(sigs[i % n], hashed, pks[i % n]);
      samples.push(performance.now() - s);
    }
    samples.sort((a, b) => a - b);
    const medianVerify = samples[Math.floor(samples.length / 2)];
    const estIndividualMs = medianVerify * n;

    const aggSigHex = aggSig.toHex();
    const aggPkHex = aggPk.toHex();

    const gtNode = aggEqual
      ? `<div class="agg-gt-node match" role="img" aria-label="Both pairings meet at one identical G_T element">
           <div class="agg-gt-title">One G<sub>T</sub> element</div>
           <div class="value gt agg-gt-hex">${truncHex(aggLeftHex, 12)}</div>
           <span class="badge valid">✅ both arrows land here</span>
         </div>`
      : `<div class="agg-gt-node nomatch" role="img" aria-label="The two pairings land on different G_T elements">
           <div class="agg-gt-title">Two different G<sub>T</sub> elements</div>
           <span class="badge invalid">❌ no match</span>
         </div>`;

    cGrid().innerHTML = `
      <div class="signer-card aggregate">
        <div class="signer-index">Aggregated (${n} signers)</div>

        <!-- Mechanism diagram: two point-addition sums, then two surviving pairings meeting at one G_T node. -->
        <div class="agg-diagram" role="group" aria-label="How ${n} signatures collapse to 2 pairings">
          <div class="agg-sums">
            <div class="agg-sum g1-tint">
              <div class="agg-sum-op">σ₁ + σ₂ + … + σ<sub>${n}</sub></div>
              <div class="agg-sum-label">point addition in <span class="g1">G₁</span></div>
              <div class="agg-sum-eq">= <span class="g1">σ<sub>agg</sub></span></div>
            </div>
            <div class="agg-sum g2-tint">
              <div class="agg-sum-op">PK₁ + PK₂ + … + PK<sub>${n}</sub></div>
              <div class="agg-sum-label">point addition in <span class="g2">G₂</span></div>
              <div class="agg-sum-eq">= <span class="g2">PK<sub>agg</sub></span></div>
            </div>
          </div>
          <div class="agg-pairings">
            <div class="agg-arrow g1-arrow">e(<span class="g1">σ<sub>agg</sub></span>, <span class="g2">G₂</span>) <span class="agg-arrow-line" aria-hidden="true">↘</span></div>
            <div class="agg-arrow g2-arrow">e(<span class="g1">H</span>, <span class="g2">PK<sub>agg</sub></span>) <span class="agg-arrow-line" aria-hidden="true">↗</span></div>
          </div>
          ${gtNode}
        </div>

        <div class="output-block" style="margin:0.5rem 0">
          <div class="ob-head"><span class="label">Aggregate Signature (48 bytes G₁)</span>${copyBtn(aggSigHex, 'aggregate signature')}</div>
          <div class="value g1">${truncHex(aggSigHex)}</div>
        </div>
        <div class="output-block" style="margin:0.5rem 0">
          <div class="ob-head"><span class="label">Aggregate Public Key (96 bytes G₂)</span>${copyBtn(aggPkHex, 'aggregate public key')}</div>
          <div class="value g2">${truncHex(aggPkHex)}</div>
        </div>
        <div class="output-block" style="margin:0.5rem 0">
          <div class="ob-head"><span class="label">e(σ_agg, G₂) — left side</span>${copyBtn(aggLeftHex, 'left pairing value')}</div>
          <div class="value gt">${aggEqual ? truncHex(aggLeftHex) : markFirstDiff(aggLeftHex, aggRightHex)}</div>
        </div>
        <div class="output-block" style="margin:0.5rem 0">
          <div class="ob-head"><span class="label">e(H, PK_agg) — right side</span>${copyBtn(aggRightHex, 'right pairing value')}</div>
          <div class="value gt">${aggEqual ? truncHex(aggRightHex) : markFirstDiff(aggRightHex, aggLeftHex)}</div>
        </div>
        <div class="verdict-head" style="margin-top:0.5rem">
          ${aggValid ? '<span class="badge valid">✅ AGGREGATE VALID</span>' : '<span class="badge invalid">❌ AGGREGATE INVALID</span>'}
          ${aggEqual ? '<span class="badge valid">✅ MATCH — identical G_T element</span>' : '<span class="badge invalid">❌ NO MATCH</span>'}
        </div>
        <p class="verdict-lead">Adding the ${n} signatures into one point (<span class="g1">σ<sub>agg</sub></span>) and the ${n} keys into one point (<span class="g2">PK<sub>agg</sub></span>) leaves just <strong>two</strong> pairings to compute — and bilinearity makes every signer's contribution add in the exponent, so those two arrows meet at one <span class="gt">G<sub>T</sub></span> element. That is why ${n} signatures verify with 2 pairings instead of ${2 * n}.</p>
      </div>
    `;

    const finite = Number.isFinite(estIndividualMs) && estIndividualMs > 0;
    const savings = finite
      ? Math.max(0, Math.min(100, (1 - aggVerifyMs / estIndividualMs) * 100)).toFixed(0)
      : '—';

    cOutput().innerHTML = `
      <div class="metric-banner">
        <strong>${n} signatures → 1 verification</strong><br>
        Verification work: <strong>${2 * n} pairings</strong> individually vs <strong>2 pairings</strong> aggregated.
      </div>
      <div class="timing">
        <div class="timing-item"><span class="timing-label">Aggregation:</span><span class="timing-value">${aggMs}ms</span></div>
        <div class="timing-item"><span class="timing-label">Agg verify (measured):</span><span class="timing-value">${aggVerifyMs.toFixed(1)}ms</span></div>
        <div class="timing-item"><span class="timing-label">Est. individual ≈ (×${n}):</span><span class="timing-value">${finite ? estIndividualMs.toFixed(1) : '—'}ms</span></div>
        <div class="timing-item"><span class="timing-label">≈ time saved:</span><span class="timing-value">${savings}%</span></div>
      </div>
      <p class="field-hint">Timings are approximate single-run samples; the exact, machine-independent truth is the pairing count above (2n vs 2).</p>
    `;

    if (!reduceMotion()) cGrid().scrollIntoView({ block: 'nearest' });
    announce(
      'c-status',
      `${n} signatures aggregated into one and verified with 2 pairings instead of ${2 * n}. Result: ${aggValid ? 'valid' : 'invalid'}.`,
    );
  } catch {
    cOutput().innerHTML = '<p class="error-text">Aggregation failed unexpectedly. Please reset and try again.</p>';
  } finally {
    cGrid().setAttribute('aria-busy', 'false');
    // Aggregate consumes the grid; leave it disabled on success. Restore siblings.
    cKeygen.disabled = prevKeygen;
    cSign.disabled = prevSign;
  }
});

// ============================================================
// Section D — Rogue Key Attack (live)
// ============================================================
interface DState {
  honest: ReturnType<typeof bls.keygen>;
  attacker: ReturnType<typeof bls.keygen>;
  roguePk: PubKey;
}
let dState: DState | null = null;

const dOutput = () => $<HTMLDivElement>('#d-output');

function resetD() {
  dState = null;
  dOutput().innerHTML = '';
  setDisabled('#d-defend', true);
  setDisabled('#d-reset', true);
  announce('d-status', 'Reset.');
}

$('#d-reset').addEventListener('click', resetD);

$('#d-attack').addEventListener('click', async () => {
  try {
    await loadCrypto();
    const honest = bls.keygen();
    const attacker = bls.keygen();
    // PK2 = sk2·G2 − PK1 — the attacker subtracts the honest key from their own.
    const roguePk = attacker.publicKey.subtract(honest.publicKey);
    dState = { honest, attacker, roguePk };

    const msg = 'Transfer 1000 ETH to the attacker';
    const H = bls.hash(new TextEncoder().encode(msg));
    // Attacker signs ALONE with sk2 — the honest signer never participates.
    const forged = bls.sign(H, attacker.secretKey);
    const aggPk = bls.aggregatePublicKeys([honest.publicKey, roguePk]);
    const forgedValid = bls.verify(forged, H, aggPk);

    const pk1 = honest.publicKey.toHex();
    const rogue = roguePk.toHex();
    const agg = aggPk.toHex();

    dOutput().innerHTML = `
      <div class="output-block">
        <div class="ob-head"><span class="label">Honest signer PK₁ = sk₁·G₂</span>${copyBtn(pk1, 'honest public key')}</div>
        <div class="value g2">${truncHex(pk1)}</div>
      </div>
      <div class="output-block">
        <div class="ob-head"><span class="label">Rogue PK₂ = sk₂·G₂ − PK₁</span>${copyBtn(rogue, 'rogue public key')}</div>
        <div class="value g2">${truncHex(rogue)}</div>
      </div>
      <div class="output-block">
        <div class="ob-head"><span class="label">Aggregate PK₁ + PK₂ (= sk₂·G₂)</span>${copyBtn(agg, 'aggregate public key')}</div>
        <div class="value g2">${truncHex(agg)}</div>
      </div>
      <div class="verdict-head" style="margin-top:0.5rem">
        ${
          forgedValid
            ? '<span class="badge invalid">❌ FORGERY ACCEPTED</span>'
            : '<span class="badge valid">✅ forgery rejected</span>'
        }
      </div>
      <p class="verdict-lead error-text">The attacker signed <strong>alone</strong> with sk₂, yet the signature verifies against the 2-of-2 aggregate key — appearing to prove the honest signer endorsed <em>"${msg}"</em>. The honest signer never touched it.</p>
      <p class="empty-hint">Now apply the Proof-of-Possession defense to see the rogue key rejected at registration.</p>
    `;
    setDisabled('#d-defend', false);
    setDisabled('#d-reset', false);
    announce('d-status', 'Rogue-key forgery accepted by naive aggregation. Apply Proof-of-Possession to defend.');
  } catch {
    dOutput().innerHTML = '<p class="error-text">The attack demo failed unexpectedly. Please reset and try again.</p>';
  }
});

$('#d-defend').addEventListener('click', async () => {
  if (!dState) return;
  try {
    await loadCrypto();
    const { honest, attacker, roguePk } = dState;

    // A Proof of Possession is a BLS signature over one's OWN public key.
    // Honest signer can produce a valid PoP for PK1.
    const honestPopMsg = bls.hash(pkBytes(honest.publicKey));
    const honestPop = bls.sign(honestPopMsg, honest.secretKey);
    const honestPopValid = bls.verify(honestPop, honestPopMsg, honest.publicKey);

    // The attacker doesn't know the discrete log of the rogue key (it is
    // sk₂ − sk₁, and sk₁ is secret), so the best PoP they can forge — signing
    // the rogue key with sk₂ — does NOT verify against the rogue key.
    const roguePopMsg = bls.hash(pkBytes(roguePk));
    const roguePopAttempt = bls.sign(roguePopMsg, attacker.secretKey);
    const roguePopValid = bls.verify(roguePopAttempt, roguePopMsg, roguePk);

    dOutput().innerHTML = `
      <div class="output-block">
        <div class="ob-head"><span class="label">Honest key — PoP check</span></div>
        <div class="value">${
          honestPopValid
            ? '<span class="badge valid">✅ PoP VALID — key accepted</span>'
            : '<span class="badge invalid">❌ PoP invalid</span>'
        }</div>
      </div>
      <div class="output-block">
        <div class="ob-head"><span class="label">Rogue key — PoP check</span></div>
        <div class="value">${
          roguePopValid
            ? '<span class="badge invalid">❌ PoP VALID (unexpected)</span>'
            : '<span class="badge valid">✅ PoP INVALID — key rejected</span>'
        }</div>
      </div>
      <p class="verdict-lead valid-text">With Proof of Possession, the registry rejects the rogue key before it ever enters the aggregate set — the attacker can't prove knowledge of its private key. This is exactly what Ethereum's beacon chain enforces at validator deposit time.</p>
    `;
    setDisabled('#d-defend', true);
    announce(
      'd-status',
      'Proof-of-Possession accepts the honest key and rejects the rogue key, preventing the forgery.',
    );
  } catch {
    dOutput().innerHTML = '<p class="error-text">The defense demo failed unexpectedly. Please reset and try again.</p>';
  }
});
