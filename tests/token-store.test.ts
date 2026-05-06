/**
 * Tests for InMemoryTokenStore
 *
 * Covers: CRUD operations, TTL-based expiry, clear, and edge cases.
 */

import { InMemoryTokenStore } from '../src/token-store';
import type { TokenInfo } from '../src/types';

function makeToken(overrides?: Partial<TokenInfo>): TokenInfo {
  return {
    value: 'os_token_test123',
    access: [{ type: 'incoming-payment', actions: ['create', 'read'] }],
    ...overrides,
  };
}

describe('InMemoryTokenStore', () => {
  let store: InMemoryTokenStore;

  beforeEach(() => {
    store = new InMemoryTokenStore();
  });

  it('returns undefined for missing key', async () => {
    const result = await store.get('nonexistent');
    expect(result).toBeUndefined();
  });

  it('stores and retrieves a token', async () => {
    const token = makeToken();
    await store.set('scope1', token);
    const result = await store.get('scope1');
    expect(result).toEqual(token);
  });

  it('overwrites an existing token', async () => {
    await store.set('scope1', makeToken({ value: 'first' }));
    await store.set('scope1', makeToken({ value: 'second' }));
    const result = await store.get('scope1');
    expect(result?.value).toBe('second');
  });

  it('deletes a token', async () => {
    await store.set('scope1', makeToken());
    await store.delete('scope1');
    const result = await store.get('scope1');
    expect(result).toBeUndefined();
  });

  it('clears all tokens', async () => {
    await store.set('scope1', makeToken());
    await store.set('scope2', makeToken());
    expect(store.size).toBe(2);
    await store.clear();
    expect(store.size).toBe(0);
  });

  it('returns undefined for expired token', async () => {
    const expiredToken = makeToken({ expiresAt: Date.now() - 1000 });
    await store.set('scope1', expiredToken);
    const result = await store.get('scope1');
    expect(result).toBeUndefined();
  });

  it('auto-prunes expired token from store on access', async () => {
    const expiredToken = makeToken({ expiresAt: Date.now() - 1000 });
    await store.set('scope1', expiredToken);
    expect(store.size).toBe(1); // Still in map before access
    await store.get('scope1');  // Access triggers prune
    expect(store.size).toBe(0); // Now removed
  });

  it('returns valid token before expiry', async () => {
    const futureToken = makeToken({ expiresAt: Date.now() + 60_000 });
    await store.set('scope1', futureToken);
    const result = await store.get('scope1');
    expect(result?.value).toBe('os_token_test123');
  });

  it('returns token without expiresAt indefinitely', async () => {
    const permanentToken = makeToken({ expiresAt: undefined });
    await store.set('scope1', permanentToken);
    const result = await store.get('scope1');
    expect(result).toBeDefined();
  });

  it('handles multiple scopes independently', async () => {
    await store.set('incoming', makeToken({ value: 'token-a' }));
    await store.set('outgoing', makeToken({ value: 'token-b' }));
    expect((await store.get('incoming'))?.value).toBe('token-a');
    expect((await store.get('outgoing'))?.value).toBe('token-b');
  });
});
