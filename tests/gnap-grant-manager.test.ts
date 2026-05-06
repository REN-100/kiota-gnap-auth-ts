/**
 * Tests for GnapGrantManager
 *
 * Covers: grant requests, continuation, token rotation, revocation,
 * JWK export, HTTP signature presence, and error handling.
 *
 * Uses a mocked global fetch to simulate the GNAP authorization server.
 */

import { GnapGrantManager } from '../src/gnap-grant-manager';
import { generateKeyPair } from '@shujaapay/http-message-signatures';
import type { ClientKeyConfig } from '../src/types';

// --- Mock fetch ---
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

// --- Test key pair ---
let clientKey: ClientKeyConfig;
let testPrivateKey: string;

beforeAll(() => {
  const pair = generateKeyPair('ed25519');
  testPrivateKey = pair.privateKey;
  clientKey = {
    keyId: 'test-key-1',
    privateKey: testPrivateKey,
    algorithm: 'ed25519',
    proof: 'httpsig',
  };
});

beforeEach(() => {
  mockFetch.mockReset();
});

describe('GnapGrantManager', () => {
  const grantEndpoint = 'https://auth.wallet.example/';

  describe('requestGrant', () => {
    it('sends a signed grant request and returns access token', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: {
            value: 'os_token_abc123',
            access: [{ type: 'incoming-payment', actions: ['create'] }],
            expires_in: 3600,
            manage: { uri: 'https://auth.wallet.example/token/123' },
          },
        }),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      const result = await manager.requestGrant([
        { type: 'incoming-payment', actions: ['create'] },
      ]);

      expect(result.accessToken).toBeDefined();
      expect(result.accessToken!.value).toBe('os_token_abc123');
      expect(result.accessToken!.expires_in).toBe(3600);
      expect(result.accessToken!.manage?.uri).toBe('https://auth.wallet.example/token/123');

      // Verify fetch was called with correct URL and method
      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe(grantEndpoint);
      expect(options.method).toBe('POST');

      // Verify request body contains grant structure
      const body = JSON.parse(options.body);
      expect(body.access_token.access).toEqual([
        { type: 'incoming-payment', actions: ['create'] },
      ]);
      expect(body.client.key.proof).toBe('httpsig');
      expect(body.client.key.jwk).toBeDefined();
      expect(body.client.key.jwk.kty).toBe('OKP');
      expect(body.client.key.jwk.kid).toBe('test-key-1');
      expect(body.client.key.jwk.alg).toBe('EdDSA');
    });

    it('includes HTTP Message Signature headers', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: { value: 'token', access: [], expires_in: 3600 },
        }),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      await manager.requestGrant([
        { type: 'incoming-payment', actions: ['create'] },
      ]);

      const headers = mockFetch.mock.calls[0][1].headers;
      expect(headers['Signature']).toBeDefined();
      expect(headers['Signature-Input']).toBeDefined();
      expect(headers['Content-Digest']).toBeDefined();
      // Verify GNAP tag is present in signature input
      expect(headers['Signature-Input']).toContain('tag="gnap"');
    });

    it('returns interaction-required response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          interact: {
            redirect: 'https://auth.wallet.example/interact/abc',
            finish: 'interact_ref_xyz',
          },
          continue: {
            access_token: { value: 'cont_token' },
            uri: 'https://auth.wallet.example/continue/abc',
          },
        }),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      const result = await manager.requestGrant(
        [{ type: 'outgoing-payment', actions: ['create'] }],
        { start: ['redirect'], finish: { method: 'redirect', uri: 'https://myapp.example/callback' } }
      );

      expect(result.interact?.redirect).toBe('https://auth.wallet.example/interact/abc');
      expect(result.continue?.uri).toBe('https://auth.wallet.example/continue/abc');
      expect(result.accessToken).toBeUndefined();
    });

    it('includes locations in access rights when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: { value: 'token', access: [], expires_in: 3600 },
        }),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      await manager.requestGrant([
        {
          type: 'outgoing-payment',
          actions: ['create'],
          locations: ['https://wallet.example/alice'],
        },
      ]);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.access_token.access[0].locations).toEqual([
        'https://wallet.example/alice',
      ]);
    });

    it('throws on non-OK response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      await expect(
        manager.requestGrant([{ type: 'incoming-payment', actions: ['create'] }])
      ).rejects.toThrow('GNAP grant request failed: 400 Bad Request');
    });
  });

  describe('continueGrant', () => {
    it('sends continuation request with interact_ref', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: {
            value: 'os_final_token',
            access: [{ type: 'outgoing-payment', actions: ['create'] }],
            expires_in: 3600,
          },
        }),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      const result = await manager.continueGrant(
        'https://auth.wallet.example/continue/abc',
        'cont_token',
        'interact_ref_xyz'
      );

      expect(result.accessToken?.value).toBe('os_final_token');

      // Verify the request
      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe('https://auth.wallet.example/continue/abc');
      expect(options.method).toBe('POST');

      const body = JSON.parse(options.body);
      expect(body.interact_ref).toBe('interact_ref_xyz');

      // Verify GNAP authorization header
      expect(options.headers['Authorization']).toBe('GNAP cont_token');
    });
  });

  describe('rotateToken', () => {
    it('rotates token via management URI', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          access_token: { value: 'os_rotated_token' },
        }),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      const newToken = await manager.rotateToken(
        'https://auth.wallet.example/token/123',
        'os_old_token'
      );

      expect(newToken).toBe('os_rotated_token');
      expect(mockFetch.mock.calls[0][1].headers['Authorization']).toBe('GNAP os_old_token');
    });
  });

  describe('revokeToken', () => {
    it('sends DELETE to management URI', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => ({}),
      });

      const manager = new GnapGrantManager(grantEndpoint, clientKey);
      await manager.revokeToken(
        'https://auth.wallet.example/token/123',
        'os_revoke_me'
      );

      const [url, options] = mockFetch.mock.calls[0];
      expect(url).toBe('https://auth.wallet.example/token/123');
      expect(options.method).toBe('DELETE');
      expect(options.headers['Authorization']).toBe('GNAP os_revoke_me');
    });
  });
});
