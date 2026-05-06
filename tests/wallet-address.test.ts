import { resolveWalletAddress, getWalletAddressKeys, WalletAddressResolutionError } from '../src/wallet-address';

// Mock global fetch
const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

const VALID_WALLET_RESPONSE = {
  id: 'https://wallet.example/alice',
  publicName: 'Alice',
  authServer: 'https://auth.wallet.example',
  resourceServer: 'https://wallet.example',
  assetCode: 'USD',
  assetScale: 2,
};

const VALID_JWKS_RESPONSE = {
  keys: [
    {
      kid: 'key-1',
      alg: 'EdDSA',
      use: 'sig',
      kty: 'OKP',
      crv: 'Ed25519',
      x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
    },
  ],
};

function mockOkResponse(data: Record<string, unknown> = VALID_WALLET_RESPONSE) {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(data),
  };
}

function mockErrorResponse(status: number, statusText: string) {
  return {
    ok: false,
    status,
    statusText,
    json: () => Promise.resolve({}),
  };
}

afterEach(() => {
  mockFetch.mockReset();
});

describe('resolveWalletAddress', () => {
  it('resolves a valid wallet address', async () => {
    mockFetch.mockResolvedValue(mockOkResponse());

    const info = await resolveWalletAddress('https://wallet.example/alice');

    expect(info.id).toBe('https://wallet.example/alice');
    expect(info.publicName).toBe('Alice');
    expect(info.authServer).toBe('https://auth.wallet.example');
    expect(info.resourceServer).toBe('https://wallet.example');
    expect(info.assetCode).toBe('USD');
    expect(info.assetScale).toBe(2);

    expect(mockFetch).toHaveBeenCalledWith(
      'https://wallet.example/alice',
      expect.objectContaining({
        method: 'GET',
        headers: { Accept: 'application/json' },
      })
    );
  });

  it('resolves without publicName', async () => {
    const { publicName, ...rest } = VALID_WALLET_RESPONSE;
    mockFetch.mockResolvedValue(mockOkResponse(rest));

    const info = await resolveWalletAddress('https://wallet.example/bob');

    expect(info.publicName).toBeUndefined();
    expect(info.authServer).toBe('https://auth.wallet.example');
  });

  it('converts legacy payment pointer ($) to https URL', async () => {
    mockFetch.mockResolvedValue(mockOkResponse());

    await resolveWalletAddress('$wallet.example/alice');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://wallet.example/alice',
      expect.anything()
    );
  });

  it('auto-prepends https:// for bare hostnames', async () => {
    mockFetch.mockResolvedValue(mockOkResponse());

    await resolveWalletAddress('wallet.example/alice');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://wallet.example/alice',
      expect.anything()
    );
  });

  it('rejects http:// URLs', async () => {
    await expect(
      resolveWalletAddress('http://wallet.example/alice')
    ).rejects.toThrow(WalletAddressResolutionError);

    await expect(
      resolveWalletAddress('http://wallet.example/alice')
    ).rejects.toThrow(/HTTPS/);
  });

  it('throws on HTTP error responses', async () => {
    mockFetch.mockResolvedValue(mockErrorResponse(404, 'Not Found'));

    await expect(
      resolveWalletAddress('https://wallet.example/unknown')
    ).rejects.toThrow(WalletAddressResolutionError);
  });

  it('throws on network errors', async () => {
    mockFetch.mockRejectedValue(new Error('DNS resolution failed'));

    await expect(
      resolveWalletAddress('https://wallet.example/alice')
    ).rejects.toThrow(WalletAddressResolutionError);

    await expect(
      resolveWalletAddress('https://wallet.example/alice')
    ).rejects.toThrow(/Network error/);
  });

  it('throws on missing required fields', async () => {
    mockFetch.mockResolvedValue(mockOkResponse({
      id: 'https://wallet.example/alice',
      // Missing authServer, resourceServer, assetCode, assetScale
    }));

    await expect(
      resolveWalletAddress('https://wallet.example/alice')
    ).rejects.toThrow(/missing required fields/);
  });

  it('resolves KES wallet correctly', async () => {
    mockFetch.mockResolvedValue(mockOkResponse({
      id: 'https://wallet.shujaapay.me/renson',
      publicName: 'Renson',
      authServer: 'https://auth.shujaapay.me',
      resourceServer: 'https://wallet.shujaapay.me',
      assetCode: 'KES',
      assetScale: 2,
    }));

    const info = await resolveWalletAddress('https://wallet.shujaapay.me/renson');

    expect(info.assetCode).toBe('KES');
    expect(info.publicName).toBe('Renson');
    expect(info.authServer).toBe('https://auth.shujaapay.me');
  });

  it('error includes walletAddress context', async () => {
    mockFetch.mockResolvedValue(mockErrorResponse(500, 'Internal Server Error'));

    try {
      await resolveWalletAddress('https://wallet.example/alice');
      fail('Should have thrown');
    } catch (e) {
      const err = e as WalletAddressResolutionError;
      expect(err.walletAddress).toBe('https://wallet.example/alice');
      expect(err.statusCode).toBe(500);
    }
  });
});

describe('getWalletAddressKeys', () => {
  it('fetches JWKS from wallet address /jwks.json', async () => {
    mockFetch.mockResolvedValue(mockOkResponse(VALID_JWKS_RESPONSE));

    const result = await getWalletAddressKeys('https://wallet.example/alice');

    expect(result.keys).toHaveLength(1);
    expect(result.keys[0].kty).toBe('OKP');
    expect(result.keys[0].crv).toBe('Ed25519');
    expect(result.keys[0].kid).toBe('key-1');
    expect(result.keys[0].alg).toBe('EdDSA');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://wallet.example/alice/jwks.json',
      expect.objectContaining({
        method: 'GET',
        headers: { Accept: 'application/json' },
      })
    );
  });

  it('handles trailing slash in wallet address', async () => {
    mockFetch.mockResolvedValue(mockOkResponse(VALID_JWKS_RESPONSE));

    await getWalletAddressKeys('https://wallet.example/alice/');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://wallet.example/alice/jwks.json',
      expect.anything()
    );
  });

  it('converts $ payment pointer for keys', async () => {
    mockFetch.mockResolvedValue(mockOkResponse(VALID_JWKS_RESPONSE));

    await getWalletAddressKeys('$wallet.example/alice');

    expect(mockFetch).toHaveBeenCalledWith(
      'https://wallet.example/alice/jwks.json',
      expect.anything()
    );
  });

  it('returns multiple keys', async () => {
    mockFetch.mockResolvedValue(mockOkResponse({
      keys: [
        { kty: 'OKP', crv: 'Ed25519', x: 'key1-x', kid: 'key-1' },
        { kty: 'OKP', crv: 'Ed25519', x: 'key2-x', kid: 'key-2' },
      ],
    }));

    const result = await getWalletAddressKeys('https://wallet.example/alice');
    expect(result.keys).toHaveLength(2);
  });

  it('rejects http:// URLs', async () => {
    await expect(
      getWalletAddressKeys('http://wallet.example/alice')
    ).rejects.toThrow(WalletAddressResolutionError);
  });

  it('throws on HTTP error responses', async () => {
    mockFetch.mockResolvedValue(mockErrorResponse(404, 'Not Found'));

    await expect(
      getWalletAddressKeys('https://wallet.example/alice')
    ).rejects.toThrow(WalletAddressResolutionError);
  });

  it('throws when response has no keys array', async () => {
    mockFetch.mockResolvedValue(mockOkResponse({ notKeys: [] }));

    await expect(
      getWalletAddressKeys('https://wallet.example/alice')
    ).rejects.toThrow(/missing "keys" array/);
  });

  it('throws on network errors', async () => {
    mockFetch.mockRejectedValue(new Error('Connection refused'));

    await expect(
      getWalletAddressKeys('https://wallet.example/alice')
    ).rejects.toThrow(/Network error/);
  });
});

