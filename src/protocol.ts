export const BLS_SIGNATURE_DST = 'BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';
export const BLS_POP_PROOF_DST = 'BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_';

export const MIN_SIGNERS = 2;
export const MAX_SIGNERS = 100;
export const MAX_MESSAGE_BYTES = 4096;

interface DomainHasher<T> {
  hash(message: Uint8Array, domain: string): T;
}

export function hashSignatureMessage<T>(suite: DomainHasher<T>, message: Uint8Array): T {
  return suite.hash(message, BLS_SIGNATURE_DST);
}

export function hashProofPublicKey<T>(suite: DomainHasher<T>, publicKey: Uint8Array): T {
  return suite.hash(publicKey, BLS_POP_PROOF_DST);
}

export function parseSignerCount(value: string): number {
  if (!/^[0-9]+$/.test(value)) {
    throw new Error(`Signer count must be a whole number from ${MIN_SIGNERS} to ${MAX_SIGNERS}.`);
  }
  const count = Number(value);
  if (!Number.isSafeInteger(count) || count < MIN_SIGNERS || count > MAX_SIGNERS) {
    throw new Error(`Signer count must be a whole number from ${MIN_SIGNERS} to ${MAX_SIGNERS}.`);
  }
  return count;
}

export function encodeBoundedMessage(value: string): Uint8Array {
  const encoded = new TextEncoder().encode(value);
  if (encoded.length > MAX_MESSAGE_BYTES) {
    throw new Error(`Message must be at most ${MAX_MESSAGE_BYTES} UTF-8 bytes.`);
  }
  return encoded;
}

export class OperationEpoch {
  #value = 0;

  begin(): number {
    this.#value += 1;
    return this.#value;
  }

  retire(): void {
    this.#value += 1;
  }

  isCurrent(expected: number): boolean {
    return expected === this.#value;
  }
}

export class RetiredOperationError extends Error {
  constructor() {
    super('Operation was retired by newer learner input.');
    this.name = 'RetiredOperationError';
  }
}
