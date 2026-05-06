/**
 * Tests for GNAP interaction hash verification (RFC 9635 §4.2.3)
 */

import { verifyInteractionHash, computeInteractionHash } from '../src/interaction-hash';
import { createHash } from 'crypto';

describe('Interaction Hash Verification', () => {
  const baseParams = {
    clientNonce: 'LKLTI25DK82FX4T4QFZC',
    asNonce: '4ASVBN85TH',
    interactRef: '4IFWWIKYB2PQ6U56NL1',
    grantEndpoint: 'https://auth.wallet.example/',
  };

  it('computes correct SHA-256 interaction hash', () => {
    // Manually compute expected hash
    const hashBase = [
      baseParams.clientNonce,
      baseParams.asNonce,
      baseParams.interactRef,
      baseParams.grantEndpoint,
    ].join('\n');
    const expected = createHash('sha256').update(hashBase).digest('base64url');

    const result = computeInteractionHash({
      ...baseParams,
      hashMethod: 'sha-256',
    });

    expect(result).toBe(expected);
  });

  it('computes correct SHA-512 interaction hash', () => {
    const hashBase = [
      baseParams.clientNonce,
      baseParams.asNonce,
      baseParams.interactRef,
      baseParams.grantEndpoint,
    ].join('\n');
    const expected = createHash('sha512').update(hashBase).digest('base64url');

    const result = computeInteractionHash({
      ...baseParams,
      hashMethod: 'sha-512',
    });

    expect(result).toBe(expected);
  });

  it('defaults to SHA-256 when no hash method specified', () => {
    const hashBase = [
      baseParams.clientNonce,
      baseParams.asNonce,
      baseParams.interactRef,
      baseParams.grantEndpoint,
    ].join('\n');
    const expected = createHash('sha256').update(hashBase).digest('base64url');

    const result = computeInteractionHash(baseParams);
    expect(result).toBe(expected);
  });

  it('verifies a valid interaction hash', () => {
    const hash = computeInteractionHash(baseParams);

    expect(
      verifyInteractionHash({
        ...baseParams,
        receivedHash: hash,
      })
    ).toBe(true);
  });

  it('rejects a tampered interaction hash', () => {
    expect(
      verifyInteractionHash({
        ...baseParams,
        receivedHash: 'INVALID_HASH_VALUE',
      })
    ).toBe(false);
  });

  it('rejects when interactRef is different', () => {
    const validHash = computeInteractionHash(baseParams);

    expect(
      verifyInteractionHash({
        ...baseParams,
        interactRef: 'TAMPERED_INTERACT_REF',
        receivedHash: validHash,
      })
    ).toBe(false);
  });

  it('rejects when grant endpoint differs (injection attack)', () => {
    const validHash = computeInteractionHash(baseParams);

    expect(
      verifyInteractionHash({
        ...baseParams,
        grantEndpoint: 'https://evil.example/',
        receivedHash: validHash,
      })
    ).toBe(false);
  });

  it('throws for unsupported hash method', () => {
    expect(() =>
      computeInteractionHash({
        ...baseParams,
        hashMethod: 'md5',
      })
    ).toThrow('Unsupported hash method: md5');
  });
});
