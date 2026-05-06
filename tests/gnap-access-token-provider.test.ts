/**
 * Tests for GnapAccessTokenProvider
 *
 * Covers: cache-first retrieval, new grant acquisition, token rotation,
 * interaction-required handling, and grace period refresh.
 */

import { GnapAccessTokenProvider } from '../src/gnap-access-token-provider';
import { InMemoryTokenStore } from '../src/token-store';
import type { AccessRight, TokenInfo } from '../src/types';

// --- Mock grant manager (manual, not jest.mock) ---
function createMockGrantManager() {
  return {
    requestGrant: jest.fn(),
    continueGrant: jest.fn(),
    rotateToken: jest.fn(),
    revokeToken: jest.fn(),
  };
}

const accessRights: AccessRight[] = [
  { type: 'incoming-payment', actions: ['create', 'read'] },
];

function createProvider(storeOverride?: InMemoryTokenStore) {
  const manager = createMockGrantManager();
  const store = storeOverride || new InMemoryTokenStore();
  const provider = new GnapAccessTokenProvider(
    manager as any,
    store,
    accessRights
  );
  return { provider, manager, store };
}

describe('GnapAccessTokenProvider', () => {
  it('returns cached token when still valid', async () => {
    const store = new InMemoryTokenStore();
    const token: TokenInfo = {
      value: 'cached_token',
      access: accessRights,
      expiresAt: Date.now() + 120_000, // 2 min from now (beyond 30s grace)
    };
    const scopeKey = 'incoming-payment:create,read';
    await store.set(scopeKey, token);

    const { provider } = createProvider(store);
    const result = await provider.getAuthorizationToken('https://wallet.example/payments');
    expect(result).toBe('cached_token');
  });

  it('requests new grant when no cached token exists', async () => {
    const { provider, manager } = createProvider();

    manager.requestGrant.mockResolvedValueOnce({
      accessToken: {
        value: 'fresh_token',
        access: accessRights,
        expires_in: 3600,
      },
    });

    const result = await provider.getAuthorizationToken('https://wallet.example/payments');
    expect(result).toBe('fresh_token');
    expect(manager.requestGrant).toHaveBeenCalledWith(accessRights, undefined);
  });

  it('stores acquired token in the token store', async () => {
    const store = new InMemoryTokenStore();
    const { provider, manager } = createProvider(store);

    manager.requestGrant.mockResolvedValueOnce({
      accessToken: {
        value: 'stored_token',
        access: accessRights,
        expires_in: 3600,
        manage: { uri: 'https://auth.example/manage/1' },
      },
    });

    await provider.getAuthorizationToken();
    const scopeKey = 'incoming-payment:create,read';
    const stored = await store.get(scopeKey);
    expect(stored?.value).toBe('stored_token');
    expect(stored?.managementUri).toBe('https://auth.example/manage/1');
  });

  it('throws when interaction is required', async () => {
    const { provider, manager } = createProvider();

    manager.requestGrant.mockResolvedValueOnce({
      interact: {
        redirect: 'https://auth.example/interact/abc',
      },
      continue: {
        access_token: { value: 'cont_tok' },
        uri: 'https://auth.example/continue/abc',
      },
    });

    await expect(provider.getAuthorizationToken()).rejects.toThrow(
      'GNAP grant requires resource owner interaction'
    );
  });

  it('attempts token rotation before new grant when expired token has management URI', async () => {
    const store = new InMemoryTokenStore();
    const scopeKey = 'incoming-payment:create,read';
    await store.set(scopeKey, {
      value: 'expired_token',
      access: accessRights,
      expiresAt: Date.now() - 1000, // Expired
      managementUri: 'https://auth.example/manage/1',
    });

    const { provider, manager } = createProvider(store);

    manager.rotateToken.mockResolvedValueOnce('rotated_token');

    const result = await provider.getAuthorizationToken();
    expect(result).toBe('rotated_token');
    expect(manager.rotateToken).toHaveBeenCalledWith(
      'https://auth.example/manage/1',
      'expired_token'
    );
    // requestGrant should NOT have been called
    expect(manager.requestGrant).not.toHaveBeenCalled();
  });

  it('falls back to new grant if rotation fails', async () => {
    const store = new InMemoryTokenStore();
    const scopeKey = 'incoming-payment:create,read';
    await store.set(scopeKey, {
      value: 'expired_token',
      access: accessRights,
      expiresAt: Date.now() - 1000,
      managementUri: 'https://auth.example/manage/1',
    });

    const { provider, manager } = createProvider(store);

    manager.rotateToken.mockRejectedValueOnce(new Error('401'));
    manager.requestGrant.mockResolvedValueOnce({
      accessToken: {
        value: 'fallback_token',
        access: accessRights,
        expires_in: 3600,
      },
    });

    const result = await provider.getAuthorizationToken();
    expect(result).toBe('fallback_token');
    expect(manager.rotateToken).toHaveBeenCalled();
    expect(manager.requestGrant).toHaveBeenCalled();
  });

  it('proactively refreshes within grace period', async () => {
    const store = new InMemoryTokenStore();
    const scopeKey = 'incoming-payment:create,read';
    // Token expires in 10 seconds — within 30-second grace period
    await store.set(scopeKey, {
      value: 'soon_expired',
      access: accessRights,
      expiresAt: Date.now() + 10_000,
      managementUri: 'https://auth.example/manage/1',
    });

    const { provider, manager } = createProvider(store);

    manager.rotateToken.mockResolvedValueOnce('proactive_refresh');

    const result = await provider.getAuthorizationToken();
    expect(result).toBe('proactive_refresh');
  });

  describe('continueGrant', () => {
    it('continues a pending grant and stores the token', async () => {
      const store = new InMemoryTokenStore();
      const { provider, manager } = createProvider(store);

      manager.continueGrant.mockResolvedValueOnce({
        accessToken: {
          value: 'continued_token',
          access: accessRights,
          expires_in: 3600,
        },
      });

      const result = await provider.continueGrant(
        'https://auth.example/continue/abc',
        'cont_tok',
        'interact_ref_xyz'
      );

      expect(result).toBe('continued_token');
      const scopeKey = 'incoming-payment:create,read';
      const stored = await store.get(scopeKey);
      expect(stored?.value).toBe('continued_token');
    });

    it('throws if continuation returns no token', async () => {
      const { provider, manager } = createProvider();

      manager.continueGrant.mockResolvedValueOnce({});

      await expect(
        provider.continueGrant('https://auth.example/continue/abc', 'tok', 'ref')
      ).rejects.toThrow('GNAP continuation did not return an access token');
    });
  });
});
