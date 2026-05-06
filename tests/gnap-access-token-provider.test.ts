/**
 * Tests for GnapAccessTokenProvider
 *
 * Covers: cache-first retrieval, new grant acquisition, token rotation,
 * interaction-required handling, grace period refresh, concurrent guard,
 * event emission, and continuation polling.
 */

import { GnapAccessTokenProvider } from '../src/gnap-access-token-provider';
import { InMemoryTokenStore } from '../src/token-store';
import { GnapInteractionRequiredError } from '../src/errors';
import type { AccessRight, TokenInfo } from '../src/types';

// --- Mock grant manager (manual) ---
function createMockGrantManager() {
  return {
    requestGrant: jest.fn(),
    continueGrant: jest.fn(),
    rotateToken: jest.fn(),
    revokeToken: jest.fn(),
    deleteGrant: jest.fn(),
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
      expiresAt: Date.now() + 120_000,
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
        manage: 'https://auth.example/manage/1',
      },
    });

    await provider.getAuthorizationToken();
    const scopeKey = 'incoming-payment:create,read';
    const stored = await store.get(scopeKey);
    expect(stored?.value).toBe('stored_token');
    expect(stored?.managementUri).toBe('https://auth.example/manage/1');
  });

  it('throws GnapInteractionRequiredError when interaction is needed', async () => {
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

    try {
      await provider.getAuthorizationToken();
      fail('Should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(GnapInteractionRequiredError);
      const err = e as GnapInteractionRequiredError;
      expect(err.redirectUrl).toBe('https://auth.example/interact/abc');
      expect(err.continuation?.uri).toBe('https://auth.example/continue/abc');
    }
  });

  it('attempts token rotation before new grant when expired token has management URI', async () => {
    const store = new InMemoryTokenStore();
    const scopeKey = 'incoming-payment:create,read';
    await store.set(scopeKey, {
      value: 'expired_token',
      access: accessRights,
      expiresAt: Date.now() - 1000,
      managementUri: 'https://auth.example/manage/1',
    });

    const { provider, manager } = createProvider(store);
    manager.rotateToken.mockResolvedValueOnce({ value: 'rotated_token', manage: 'https://auth.example/manage/1' });

    const result = await provider.getAuthorizationToken();
    expect(result).toBe('rotated_token');
    expect(manager.rotateToken).toHaveBeenCalledWith(
      'https://auth.example/manage/1',
      'expired_token'
    );
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
    await store.set(scopeKey, {
      value: 'soon_expired',
      access: accessRights,
      expiresAt: Date.now() + 10_000,
      managementUri: 'https://auth.example/manage/1',
    });

    const { provider, manager } = createProvider(store);
    manager.rotateToken.mockResolvedValueOnce({ value: 'proactive_refresh', manage: 'https://auth.example/manage/1', expiresIn: 3600 });

    const result = await provider.getAuthorizationToken();
    expect(result).toBe('proactive_refresh');
  });

  describe('concurrent acquisition guard', () => {
    it('prevents duplicate grants for simultaneous requests', async () => {
      const { provider, manager } = createProvider();
      let resolveGrant: (v: any) => void;
      const grantPromise = new Promise((r) => { resolveGrant = r; });

      manager.requestGrant.mockReturnValueOnce(grantPromise);

      // Fire two requests simultaneously
      const p1 = provider.getAuthorizationToken();
      const p2 = provider.getAuthorizationToken();

      // Resolve the single grant
      resolveGrant!({
        accessToken: {
          value: 'shared_token',
          access: accessRights,
          expires_in: 3600,
        },
      });

      const [r1, r2] = await Promise.all([p1, p2]);
      expect(r1).toBe('shared_token');
      expect(r2).toBe('shared_token');
      // Should only have called requestGrant ONCE
      expect(manager.requestGrant).toHaveBeenCalledTimes(1);
    });
  });

  describe('event emission', () => {
    it('emits token:acquired on new grant', async () => {
      const { provider, manager } = createProvider();
      const events: any[] = [];
      provider.events.on('token:acquired', (e) => events.push(e));

      manager.requestGrant.mockResolvedValueOnce({
        accessToken: {
          value: 'event_token',
          access: accessRights,
          expires_in: 3600,
          manage: 'https://auth.example/manage/1',
        },
      });

      await provider.getAuthorizationToken();
      expect(events).toHaveLength(1);
      expect(events[0].hasManagementUri).toBe(true);
      expect(events[0].expiresIn).toBe(3600);
    });

    it('emits token:rotated on successful rotation', async () => {
      const store = new InMemoryTokenStore();
      const scopeKey = 'incoming-payment:create,read';
      await store.set(scopeKey, {
        value: 'old',
        access: accessRights,
        expiresAt: Date.now() - 1000,
        managementUri: 'https://auth.example/manage/1',
      });

      const { provider, manager } = createProvider(store);
      const events: any[] = [];
      provider.events.on('token:rotated', (e) => events.push(e));

      manager.rotateToken.mockResolvedValueOnce({ value: 'rotated', manage: 'https://auth.example/manage/1' });
      await provider.getAuthorizationToken();

      expect(events).toHaveLength(1);
      expect(events[0].managementUri).toBe('https://auth.example/manage/1');
    });

    it('emits token:rotation_failed when rotation errors', async () => {
      const store = new InMemoryTokenStore();
      const scopeKey = 'incoming-payment:create,read';
      await store.set(scopeKey, {
        value: 'old',
        access: accessRights,
        expiresAt: Date.now() - 1000,
        managementUri: 'https://auth.example/manage/1',
      });

      const { provider, manager } = createProvider(store);
      const events: any[] = [];
      provider.events.on('token:rotation_failed', (e) => events.push(e));

      manager.rotateToken.mockRejectedValueOnce(new Error('401'));
      manager.requestGrant.mockResolvedValueOnce({
        accessToken: { value: 'new', access: accessRights, expires_in: 3600 },
      });

      await provider.getAuthorizationToken();
      expect(events).toHaveLength(1);
      expect(events[0].error).toBe('401');
    });

    it('emits grant:interaction_required on interaction', async () => {
      const { provider, manager } = createProvider();
      const events: any[] = [];
      provider.events.on('grant:interaction_required', (e) => events.push(e));

      manager.requestGrant.mockResolvedValueOnce({
        interact: { redirect: 'https://auth.example/interact' },
        continue: { access_token: { value: 'ct' }, uri: 'https://auth.example/continue/1' },
      });

      await expect(provider.getAuthorizationToken()).rejects.toThrow();
      expect(events).toHaveLength(1);
      expect(events[0].redirectUrl).toBe('https://auth.example/interact');
    });
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
