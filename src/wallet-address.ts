/**
 * Open Payments Wallet Address Resolution
 *
 * Resolves a wallet address URL to discover the authorization server,
 * resource server, asset information, and public name.
 *
 * This is the TypeScript counterpart of the Python SDK's
 * `wallet_address.py` module.
 *
 * @see https://openpayments.dev/apis/wallet-address-server/operations/get-wallet-address/
 * @see https://www.rfc-editor.org/rfc/rfc9635
 */

/**
 * Resolved wallet address information.
 */
export interface WalletAddressInfo {
  /** Canonical wallet address URL (e.g., 'https://wallet.example/alice') */
  id: string;
  /** Human-readable public name (e.g., 'Alice') */
  publicName?: string;
  /** GNAP authorization server URL */
  authServer: string;
  /** Resource server URL */
  resourceServer: string;
  /** ISO 4217 currency code (e.g., 'USD', 'KES') */
  assetCode: string;
  /** Decimal scale (e.g., 2 for cents) */
  assetScale: number;
}

/**
 * Error thrown when wallet address resolution fails.
 */
export class WalletAddressResolutionError extends Error {
  readonly name = 'WalletAddressResolutionError';

  constructor(
    message: string,
    public readonly walletAddress: string,
    public readonly statusCode?: number
  ) {
    super(message);
  }
}

/**
 * Resolve a wallet address to discover authorization and resource servers.
 *
 * Performs an HTTP GET to the wallet address URL with
 * `Accept: application/json` to retrieve the Open Payments
 * wallet address document.
 *
 * Supports:
 * - Full HTTPS URLs: `https://wallet.example/alice`
 * - Bare hostnames: `wallet.example/alice` (auto-prepends https://)
 * - Legacy payment pointers: `$wallet.example/alice` (converts `$` → `https://`)
 *
 * @param walletAddress - Wallet address URL or payment pointer
 * @returns Resolved wallet address information
 * @throws {WalletAddressResolutionError} On resolution failure
 *
 * @example
 * ```ts
 * const info = await resolveWalletAddress('https://ilp.rafiki.money/alice');
 * // info.authServer → 'https://auth.rafiki.money'
 * // info.assetCode → 'USD'
 * // info.assetScale → 2
 * ```
 */
export async function resolveWalletAddress(
  walletAddress: string
): Promise<WalletAddressInfo> {
  // Normalize the URL
  let url = walletAddress.trim();

  // Handle legacy payment pointers ($wallet.example/alice → https://wallet.example/alice)
  if (url.startsWith('$')) {
    url = `https://${url.slice(1)}`;
  }

  // Auto-prepend https:// if no protocol
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  // Reject insecure connections
  if (url.startsWith('http://')) {
    throw new WalletAddressResolutionError(
      'Wallet address resolution requires HTTPS',
      walletAddress
    );
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      redirect: 'follow',
    });
  } catch (error) {
    throw new WalletAddressResolutionError(
      `Network error resolving wallet address: ${(error as Error).message}`,
      walletAddress
    );
  }

  if (!response.ok) {
    throw new WalletAddressResolutionError(
      `HTTP ${response.status} resolving wallet address: ${response.statusText}`,
      walletAddress,
      response.status
    );
  }

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    throw new WalletAddressResolutionError(
      'Invalid JSON in wallet address response',
      walletAddress
    );
  }

  // Validate required fields
  const id = data.id as string | undefined;
  const authServer = data.authServer as string | undefined;
  const resourceServer = data.resourceServer as string | undefined;
  const assetCode = data.assetCode as string | undefined;
  const assetScale = data.assetScale as number | undefined;

  if (!id || !authServer || !resourceServer || !assetCode || assetScale === undefined) {
    const missing: string[] = [];
    if (!id) missing.push('id');
    if (!authServer) missing.push('authServer');
    if (!resourceServer) missing.push('resourceServer');
    if (!assetCode) missing.push('assetCode');
    if (assetScale === undefined) missing.push('assetScale');
    throw new WalletAddressResolutionError(
      `Wallet address response missing required fields: ${missing.join(', ')}`,
      walletAddress
    );
  }

  return {
    id,
    publicName: data.publicName as string | undefined,
    authServer,
    resourceServer,
    assetCode,
    assetScale,
  };
}

/**
 * JSON Web Key (JWK) as returned by the wallet address keys endpoint.
 */
export interface WalletAddressKey {
  /** Key type (e.g., 'OKP' for Ed25519) */
  kty: string;
  /** Curve (e.g., 'Ed25519') */
  crv: string;
  /** Public key (base64url-encoded) */
  x: string;
  /** Key ID */
  kid?: string;
  /** Algorithm (e.g., 'EdDSA') */
  alg?: string;
  /** Key usage (e.g., 'sig') */
  use?: string;
}

/**
 * Response from the wallet address keys endpoint.
 */
export interface WalletAddressKeys {
  /** Array of JWK public keys bound to this wallet address */
  keys: WalletAddressKey[];
}

/**
 * Fetch the public keys bound to a wallet address.
 *
 * Performs an HTTP GET to `{walletAddress}/jwks.json` to retrieve the
 * JWKS (JSON Web Key Set) associated with the wallet address.
 * These keys are used by authorization servers to verify client identity.
 *
 * @param walletAddress - Wallet address URL (same formats as resolveWalletAddress)
 * @returns JWKS containing the wallet's bound public keys
 * @throws {WalletAddressResolutionError} On resolution failure
 *
 * @see https://openpayments.dev/apis/wallet-address-server/operations/get-wallet-address-keys/
 *
 * @example
 * ```ts
 * const { keys } = await getWalletAddressKeys('https://ilp.rafiki.money/alice');
 * // keys[0].kty → 'OKP', keys[0].crv → 'Ed25519'
 * ```
 */
export async function getWalletAddressKeys(
  walletAddress: string
): Promise<WalletAddressKeys> {
  // Normalize the URL (same logic as resolveWalletAddress)
  let url = walletAddress.trim();

  if (url.startsWith('$')) {
    url = `https://${url.slice(1)}`;
  }

  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  if (url.startsWith('http://')) {
    throw new WalletAddressResolutionError(
      'Wallet address key resolution requires HTTPS',
      walletAddress
    );
  }

  // Ensure trailing slash before appending jwks.json
  const keysUrl = url.endsWith('/')
    ? `${url}jwks.json`
    : `${url}/jwks.json`;

  let response: Response;
  try {
    response = await fetch(keysUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
      redirect: 'follow',
    });
  } catch (error) {
    throw new WalletAddressResolutionError(
      `Network error fetching wallet address keys: ${(error as Error).message}`,
      walletAddress
    );
  }

  if (!response.ok) {
    throw new WalletAddressResolutionError(
      `HTTP ${response.status} fetching wallet address keys: ${response.statusText}`,
      walletAddress,
      response.status
    );
  }

  let data: Record<string, unknown>;
  try {
    data = await response.json() as Record<string, unknown>;
  } catch {
    throw new WalletAddressResolutionError(
      'Invalid JSON in wallet address keys response',
      walletAddress
    );
  }

  const keys = data.keys as WalletAddressKey[] | undefined;
  if (!Array.isArray(keys)) {
    throw new WalletAddressResolutionError(
      'Wallet address keys response missing "keys" array',
      walletAddress
    );
  }

  return { keys };
}
