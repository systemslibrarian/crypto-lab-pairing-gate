// Run only from a committed, clean source baseline. Every mutation is built,
// killed by its exact assertion owner, restored byte-for-byte, rebuilt, and
// tested green before the next mutation begins.
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(root);

const build = ['npm', ['run', 'build']];
const unit = (file, title) => [
  'npx',
  ['tsx', '--test', '--test-name-pattern', title, file],
];
const browser = (title) => [
  'npx',
  [
    'playwright',
    'test',
    'e2e/exhibits.spec.ts',
    '--project=chromium',
    '--grep',
    title,
    '--workers=1',
    '--retries=0',
  ],
];

function run([command, args]) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, CI: '1' },
  });
}

function pass(command, label) {
  const result = run(command);
  if (result.status !== 0) {
    throw new Error(`${label}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function distHash() {
  const hash = createHash('sha256');
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name))) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) walk(path);
      else {
        hash.update(path);
        hash.update(readFileSync(path));
      }
    }
  };
  walk('dist');
  return hash.digest('hex');
}

const cases = [
  [
    'signer count upper bound is bypassed',
    'src/protocol.ts',
    'count < MIN_SIGNERS || count > MAX_SIGNERS',
    'count < MIN_SIGNERS || false',
    unit('tests/protocol.test.ts', 'accepts only the advertised signer-count range'),
  ],
  [
    'encoded message byte bound is bypassed',
    'src/protocol.ts',
    'if (encoded.length > MAX_MESSAGE_BYTES) {',
    'if (false && encoded.length > MAX_MESSAGE_BYTES) {',
    unit('tests/protocol.test.ts', 'bounds messages by encoded bytes rather than JavaScript characters'),
  ],
  [
    'retired operation epoch regains authority',
    'src/protocol.ts',
    'return expected === this.#value;',
    'return true || expected === this.#value;',
    unit('tests/protocol.test.ts', 'only the newest operation epoch retains authority'),
  ],
  [
    'ordinary signatures use the default NUL domain',
    'src/protocol.ts',
    "export const BLS_SIGNATURE_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';",
    "export const BLS_SIGNATURE_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_';",
    unit('tests/protocol.test.ts', 'uses distinct July 2026 CFRG draft domains'),
  ],
  [
    'proofs reuse the ordinary signature domain',
    'src/protocol.ts',
    "export const BLS_POP_PROOF_DST = 'BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';",
    "export const BLS_POP_PROOF_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';",
    unit('tests/protocol.test.ts', 'uses distinct July 2026 CFRG draft domains'),
  ],
  [
    'message edit no longer retires an aggregate animation',
    'src/main.ts',
    '      await new Promise((r) => setTimeout(r, Math.min(total * 24 + 520, isNarrow() ? 1300 : 2200)));\n      if (!cEpoch.isCurrent(token)) throw new RetiredOperationError();',
    '      await new Promise((r) => setTimeout(r, Math.min(total * 24 + 520, isNarrow() ? 1300 : 2200)));\n      if (false && !cEpoch.isCurrent(token)) throw new RetiredOperationError();',
    browser('editing the message retires an in-flight aggregate result'),
  ],
  [
    'Ethereum is said to use the demo orientation',
    'src/main.ts',
    'Ethereum uses that opposite, minimal-public-key-size orientation: 48-byte G₁ keys and 96-byte G₂ signatures.',
    'Ethereum uses this same orientation: 96-byte G₂ keys and 48-byte G₁ signatures.',
    browser('distinguishes this demo orientation from Ethereum consensus'),
  ],
  [
    'aggregate construction is mislabeled constant work',
    'src/main.ts',
    'Building the two aggregate points takes <strong>O(n) point additions</strong>.',
    'Building the two aggregate points takes <strong>O(1) total work</strong>.',
    browser('aggregation reports linear construction and a two-term final equation'),
  ],
  [
    'rogue proof is accepted without verification',
    'src/main.ts',
    '    const roguePopValid = bls.verify(roguePopAttempt, roguePopMsg, roguePk);',
    '    const roguePopValid = bls.verify(roguePopAttempt, roguePopMsg, roguePk) || true;',
    browser('rogue-key defense uses the distinct proof domain and rejects the rogue key'),
  ],
  [
    'raw GT diagnostic is called a standardized wire encoding',
    'src/main.ts',
    "a <strong>576-byte raw diagnostic value</strong>; that is not a claim that protocols use a standardized 576-byte G<sub>T</sub> wire encoding.",
    "a <strong>standardized 576-byte G<sub>T</sub> wire encoding</strong> used by protocols.",
    browser('labels the exposed GT bytes as a raw diagnostic rather than a wire standard'),
  ],
];

const sourceFiles = [...new Set(cases.map((entry) => entry[1]))];
const dirty = spawnSync('git', ['diff', '--exit-code', '--', ...sourceFiles], {
  cwd: root,
  encoding: 'utf8',
});
if (dirty.status !== 0) {
  throw new Error('Commit the source baseline before mutation checks.');
}

pass(build, 'baseline build');
const baseline = distHash();
const evidence = [];
console.log('baseline: unmutated copy PASSES');
mkdirSync('mutation-logs', { recursive: true });

for (const [name, file, before, after, owner] of cases) {
  pass(owner, `${name}: baseline owner`);
  const original = readFileSync(file, 'utf8');
  if (original.split(before).length !== 2) {
    throw new Error(`${name}: expected exactly one mutation site`);
  }

  try {
    writeFileSync(file, original.replace(before, after));
    const sourceDiff = spawnSync('git', ['diff', '--', file], {
      cwd: root,
      encoding: 'utf8',
    }).stdout;
    if (!sourceDiff.trim()) throw new Error(`${name}: source diff is empty`);

    pass(build, `${name}: mutant build`);
    const mutant = distHash();
    if (mutant === baseline) throw new Error(`${name}: production artifact did not move`);

    const result = run(owner);
    writeFileSync(
      `mutation-logs/${name.replaceAll(' ', '-')}.log`,
      result.stdout + result.stderr,
    );
    const output = result.stdout + result.stderr;
    if (
      result.status === 0
      || !/AssertionError|ERR_ASSERTION|Error: expect|Expected values|expected/i.test(output)
    ) {
      throw new Error(`${name}: no assertion kill\n${output}`);
    }

    evidence.push({
      name,
      sourceDiff,
      baseline,
      mutant,
      namedTest: owner[1].includes('--grep')
        ? owner[1][owner[1].indexOf('--grep') + 1]
        : owner[1][owner[1].indexOf('--test-name-pattern') + 1],
      assertionFailure: true,
      retries: 0,
    });
  } finally {
    writeFileSync(file, original);
    pass(build, `${name}: restore build`);
    if (distHash() !== baseline) throw new Error(`${name}: restored artifact hash differs`);
    pass(owner, `${name}: restored owner`);
  }

  evidence.at(-1).restoredGreen = true;
  console.log(`${name}: killed; exact artifact restored; owning test green`);
}

writeFileSync('mutation-evidence.json', `${JSON.stringify(evidence, null, 2)}\n`);
console.log(`all ${cases.length} mutation(s) caught`);
