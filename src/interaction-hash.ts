/**
 * GNAP Interaction Hash Verification — RFC 9635 §4.2.3
 *
 * When using the redirect finish method, the AS includes a `hash`
 * parameter in the callback URL. The client MUST verify this hash
 * before sending a continuation request to prevent injection attacks.
 *
 * Hash = Base64URL(SHA(clientNonce + "\n" + asNonce + "\n" + interactRef + "\n" + grantEndpoint))
 */

import { createHash, timingSafeEqual as cryptoTimingSafeEqual } from 'crypto';

/**
 * Hash method to Node.js algorithm mapping.
 */
const HASH_ALGORITHMS: Record<string, string> = {
  'sha-256': 'sha256',
  'sha-512': 'sha512',
  'sha3-256': 'sha3-256',
  'sha3-512': 'sha3-512',
};

/**
 * Verify the interaction hash from a GNAP redirect callback.
 *
 * Per RFC 9635 §4.2.3, the hash is computed as:
 * ```
 * hash = BASE64URL(HASH(clientNonce + "\n" + asNonce + "\n" + interactRef + "\n" + grantEndpoint))
 * ```
 *
 * @param params - Hash verification parameters
 * @returns true if the hash is valid
 *
 * @example
 * ```ts
 * // In your redirect callback handler:
 * const url = new URL(request.url);
 * const hash = url.searchParams.get('hash');
 * const interactRef = url.searchParams.get('interact_ref');
 *
 * const valid = verifyInteractionHash({
 *   receivedHash: hash!,
 *   clientNonce: 'my-client-nonce',
 *   asNonce: asNonceFromGrantResponse,
 *   interactRef: interactRef!,
 *   grantEndpoint: 'https://auth.wallet.example/',
 *   hashMethod: 'sha-256',
 * });
 *
 * if (!valid) {
 *   throw new Error('Interaction hash verification failed — possible injection');
 * }
 * ```
 */
export function verifyInteractionHash(params: {
  /** Hash received from the AS callback */
  receivedHash: string;
  /** Client nonce from the original interact.finish request */
  clientNonce: string;
  /** AS nonce from the grant response */
  asNonce: string;
  /** Interaction reference from the callback */
  interactRef: string;
  /** Grant endpoint URI used in the original request */
  grantEndpoint: string;
  /** Hash method (default: sha-256) */
  hashMethod?: string;
}): boolean {
  const expected = computeInteractionHash(params);
  return timingSafeEqual(expected, params.receivedHash);
}

/**
 * Compute the expected interaction hash.
 */
export function computeInteractionHash(params: {
  clientNonce: string;
  asNonce: string;
  interactRef: string;
  grantEndpoint: string;
  hashMethod?: string;
}): string {
  const method = params.hashMethod || 'sha-256';
  const algorithm = HASH_ALGORITHMS[method];
  if (!algorithm) {
    throw new Error(`Unsupported hash method: ${method}`);
  }

  // RFC 9635 §4.2.3: concatenate with newline separator
  const hashBase = [
    params.clientNonce,
    params.asNonce,
    params.interactRef,
    params.grantEndpoint,
  ].join('\n');

  const hash = createHash(algorithm).update(hashBase).digest();
  return hash.toString('base64url');
}

/**
 * Constant-time string comparison to prevent timing attacks.
 * Uses Node.js crypto.timingSafeEqual for guaranteed constant-time comparison.
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;

  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return cryptoTimingSafeEqual(bufA, bufB);
}
