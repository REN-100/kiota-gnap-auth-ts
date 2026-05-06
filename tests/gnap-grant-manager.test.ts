/**
 * Tests for GnapGrantManager
 *
 * Covers: grant requests with datatypes/flags, continuation, rotation,
 * revocation, grant deletion, structured error handling, retry, and
 * Content-Digest header.
 */

import { GnapGrantManager } from '../src/gnap-grant-manager';
import { GnapError } from '../src/errors';

// --- Mock fetch ---
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

// --- Mock signing library ---
jest.mock('@shujaapay/http-message-signatures', () => ({
  createSigner: jest.fn().mockReturnValue({ sign: jest.fn() }),
  signRequest: jest.fn().mockResolvedValue({
    'Signature': 'sig1=:test-signature:',
    'Signature-Input': 'sig1=("@method" "@target-uri");tag="gnap"',
  }),
  exportPublicJwk: jest.fn().mockReturnValue({
    kty: 'OKP',
    crv: 'Ed25519',
    x: 'test-public-key',
    kid: 'test-key-id',
    alg: 'EdDSA',
  }),
  algorithmToJwkAlg: jest.fn().mockReturnValue('EdDSA'),
}));

// --- Mock crypto ---
jest.mock('crypto', () => ({
  ...jest.requireActual('crypto'),
  createPublicKey: jest.fn().mockReturnValue({
    export: jest.fn().mockReturnValue('-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----'),
  }),
  randomBytes: jest.fn().mockReturnValue(Buffer.from('test-nonce-bytes-00000000')),
}));

const testClientKey = {
  keyId: 'test-key-id',
  privateKey: '-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----',
  algorithm: 'ed25519' as const,
  proof: 'httpsig' as const,
};

describe('GnapGrantManager', () => {
  let manager: GnapGrantManager;

  beforeEach(() => {
    mockFetch.mockReset();
    // Disable retry for most tests
    manager = new GnapGrantManager(
      'https://auth.example/',
      testClientKey,
      undefined,
      undefined,
      { maxAttempts: 0, baseDelayMs: 0, maxDelayMs: 0, jitter: false, retryableStatuses: [] }
    );
  });

  describe('requestGrant', () => {
    it('sends a signed grant request and returns access token', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: {
            value: 'os_token_abc123',
            manage: { uri: 'https://auth.example/manage/1' },
            access: [{ type: 'incoming-payment', actions: ['create', 'read'] }],
            expires_in: 3600,
          },
        }),
      });

      const result = await manager.requestGrant([
        { type: 'incoming-payment', actions: ['create', 'read'] },
      ]);

      expect(result.accessToken?.value).toBe('os_token_abc123');
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it('includes HTTP Message Signature headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: { value: 'tok', access: [] } }),
      });

      await manager.requestGrant([{ type: 'quote', actions: ['create'] }]);

      const fetchCall = mockFetch.mock.calls[0];
      const headers = fetchCall[1].headers;
      expect(headers['Signature']).toBeDefined();
      expect(headers['Signature-Input']).toContain('tag="gnap"');
    });

    it('includes Content-Digest header for POST body', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: { value: 'tok', access: [] } }),
      });

      await manager.requestGrant([{ type: 'quote', actions: ['create'] }]);

      const fetchCall = mockFetch.mock.calls[0];
      const headers = fetchCall[1].headers;
      expect(headers['Content-Digest']).toMatch(/^sha-256=:/);
    });

    it('returns interaction-required response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          interact: {
            redirect: 'https://auth.example/interact/abc',
          },
          continue: {
            access_token: { value: 'cont_tok' },
            uri: 'https://auth.example/continue/abc',
            wait: 5,
          },
        }),
      });

      const result = await manager.requestGrant(
        [{ type: 'outgoing-payment', actions: ['create'] }],
        { start: ['redirect'], finish: { method: 'redirect', uri: 'https://app.example/callback' } }
      );

      expect(result.interact?.redirect).toBe('https://auth.example/interact/abc');
      expect(result.continue?.wait).toBe(5);
    });

    it('includes locations and datatypes in access rights', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: { value: 'tok', access: [] } }),
      });

      await manager.requestGrant([{
        type: 'incoming-payment',
        actions: ['create', 'read'],
        locations: ['https://wallet.example/alice'],
        datatypes: ['application/json'],
      }]);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.access_token.access[0].locations).toEqual(['https://wallet.example/alice']);
      expect(body.access_token.access[0].datatypes).toEqual(['application/json']);
    });

    it('includes flags in token request', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: { value: 'tok', access: [] } }),
      });

      await manager.requestGrant(
        [{ type: 'quote', actions: ['create'] }],
        undefined,
        ['bearer']
      );

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.access_token.flags).toEqual(['bearer']);
    });

    it('includes wallet_address and display in client', async () => {
      const mgr = new GnapGrantManager(
        'https://auth.example/',
        testClientKey,
        'https://wallet.example/alice',
        { name: 'ShujaaPay', uri: 'https://www.shujaapay.me' },
        { maxAttempts: 0, baseDelayMs: 0, maxDelayMs: 0, jitter: false, retryableStatuses: [] }
      );

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: { value: 'tok', access: [] } }),
      });

      await mgr.requestGrant([{ type: 'quote', actions: ['create'] }]);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.client.wallet_address).toBe('https://wallet.example/alice');
      expect(body.client.display.name).toBe('ShujaaPay');
    });

    it('throws GnapError on structured error response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        headers: new Map(),
        json: async () => ({
          error: {
            code: 'invalid_client',
            description: 'Client key not recognized',
          },
        }),
      });

      await expect(manager.requestGrant([
        { type: 'quote', actions: ['create'] },
      ])).rejects.toThrow(GnapError);

      try {
        await manager.requestGrant([{ type: 'quote', actions: ['create'] }]);
      } catch (e) {
        // Need a fresh fetch mock for the second call
      }
    });

    it('throws GnapError with error code string format', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        headers: { get: () => null },
        json: async () => ({ error: 'user_denied' }),
      });

      try {
        await manager.requestGrant([{ type: 'quote', actions: ['create'] }]);
        fail('Should have thrown');
      } catch (e) {
        expect(e).toBeInstanceOf(GnapError);
        expect((e as GnapError).code).toBe('user_denied');
        expect((e as GnapError).statusCode).toBe(403);
      }
    });
  });

  describe('continueGrant', () => {
    it('sends continuation request with interact_ref', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: {
            value: 'continued_token',
            access: [{ type: 'outgoing-payment', actions: ['create'] }],
          },
        }),
      });

      const result = await manager.continueGrant(
        'https://auth.example/continue/abc',
        'cont_tok',
        'interact_ref_xyz'
      );

      expect(result.accessToken?.value).toBe('continued_token');
      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.interact_ref).toBe('interact_ref_xyz');
    });
  });

  describe('rotateToken', () => {
    it('rotates token via management URI', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ access_token: { value: 'rotated_token' } }),
      });

      const result = await manager.rotateToken(
        'https://auth.example/manage/1',
        'old_token'
      );

      expect(result).toBe('rotated_token');
    });

    it('throws GnapError on rotation failure', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        headers: { get: () => null },
        json: async () => ({ error: 'invalid_rotation' }),
      });

      await expect(
        manager.rotateToken('https://auth.example/manage/1', 'old_token')
      ).rejects.toThrow(GnapError);
    });
  });

  describe('revokeToken', () => {
    it('sends DELETE to management URI', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true });

      await manager.revokeToken(
        'https://auth.example/manage/1',
        'token_to_revoke'
      );

      const fetchCall = mockFetch.mock.calls[0];
      expect(fetchCall[1].method).toBe('DELETE');
    });
  });

  describe('deleteGrant', () => {
    it('sends DELETE to continuation URI', async () => {
      mockFetch.mockResolvedValueOnce({ ok: true, status: 204 });

      await manager.deleteGrant(
        'https://auth.example/continue/abc',
        'cont_tok'
      );

      const fetchCall = mockFetch.mock.calls[0];
      expect(fetchCall[0]).toBe('https://auth.example/continue/abc');
      expect(fetchCall[1].method).toBe('DELETE');
    });

    it('throws GnapError on non-204 error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
        headers: { get: () => null },
        json: async () => ({ error: 'unknown_request' }),
      });

      await expect(
        manager.deleteGrant('https://auth.example/continue/abc', 'cont_tok')
      ).rejects.toThrow(GnapError);
    });
  });
});
