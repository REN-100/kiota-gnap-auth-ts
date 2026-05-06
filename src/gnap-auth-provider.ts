/**
 * GNAP Authentication Provider for Kiota
 *
 * Implements Kiota's AuthenticationProvider interface to handle
 * GNAP (RFC 9635) authorization for generated SDK clients.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://learn.microsoft.com/en-us/openapi/kiota/
 */

import type { AuthenticationProvider, RequestInformation } from '@microsoft/kiota-abstractions';
import { createSigner, signRequest } from '@shujaapay/http-message-signatures';
import { GnapAccessTokenProvider } from './gnap-access-token-provider';
import { GnapGrantManager } from './gnap-grant-manager';
import { InMemoryTokenStore } from './token-store';
import type { GnapAuthOptions, TokenStore } from './types';

/**
 * Kiota AuthenticationProvider that handles GNAP authorization.
 *
 * This provider manages the complete GNAP lifecycle:
 * 1. Requests grants from the authorization server
 * 2. Handles interaction (redirect/user_code) if required
 * 3. Acquires and caches access tokens
 * 4. Automatically refreshes expired tokens
 * 5. Signs requests with HTTP Message Signatures (RFC 9421)
 *
 * Security: Uses AllowedHosts validation (Kiota best practice) to prevent
 * credential leakage to unauthorized domains.
 *
 * @example
 * ```typescript
 * import { GnapAuthenticationProvider } from '@shujaapay/kiota-gnap-auth-ts';
 *
 * const authProvider = new GnapAuthenticationProvider({
 *   grantEndpoint: 'https://auth.wallet.example/',
 *   clientKey: {
 *     keyId: 'my-key',
 *     privateKey: myPrivateKey,
 *     algorithm: 'ed25519',
 *     proof: 'httpsig',
 *   },
 *   accessRights: [
 *     { type: 'incoming-payment', actions: ['create', 'read'] },
 *   ],
 *   allowedHosts: ['wallet.example', 'auth.wallet.example'],
 * });
 *
 * // Use with Kiota-generated client
 * const adapter = new FetchRequestAdapter(authProvider);
 * const client = new OpenPaymentsClient(adapter);
 * ```
 */
export class GnapAuthenticationProvider implements AuthenticationProvider {
  private readonly grantManager: GnapGrantManager;
  private readonly tokenStore: TokenStore;
  private readonly accessTokenProvider: GnapAccessTokenProvider;
  private readonly allowedHosts?: Set<string>;

  constructor(private readonly options: GnapAuthOptions) {
    this.grantManager = new GnapGrantManager(
      options.grantEndpoint,
      options.clientKey,
      options.walletAddress,
      options.clientDisplay
    );
    this.tokenStore = options.tokenStore || new InMemoryTokenStore();
    this.accessTokenProvider = new GnapAccessTokenProvider(
      this.grantManager,
      this.tokenStore,
      options.accessRights,
      options.interaction
    );

    // Build AllowedHosts set for Kiota-style host validation
    if (options.allowedHosts && options.allowedHosts.length > 0) {
      this.allowedHosts = new Set(
        options.allowedHosts.map((h) => h.toLowerCase())
      );
    }
  }

  /**
   * Authenticates an outgoing HTTP request by:
   * 1. Validating the target host (if allowedHosts is configured)
   * 2. Obtaining a valid GNAP access token
   * 3. Adding the Authorization header (GNAP token)
   * 4. Signing the request with HTTP Message Signatures (RFC 9421)
   *
   * This method is called automatically by Kiota's request adapter
   * before each API call.
   */
  async authenticateRequest(
    request: RequestInformation,
    additionalAuthenticationContext?: Record<string, unknown>
  ): Promise<void> {
    // AllowedHosts validation — Kiota best practice to prevent token leakage
    if (this.allowedHosts && !this.isHostAllowed(request.URL)) {
      return; // Skip authentication for non-allowed hosts
    }

    // Get a valid access token (acquires new one or uses cached)
    const token = await this.accessTokenProvider.getAuthorizationToken(
      request.URL,
      additionalAuthenticationContext
    );

    if (!token) {
      throw new Error('Failed to obtain GNAP access token');
    }

    // Add GNAP authorization header
    request.headers.add('Authorization', `GNAP ${token}`);

    // Sign the request with HTTP Message Signatures (RFC 9421)
    await this.signOutgoingRequest(request);
  }

  /**
   * Signs the request using RFC 9421 HTTP Message Signatures
   * with the GNAP httpsig proof method (tag="gnap").
   *
   * Covered components for Open Payments:
   * - @method, @target-uri, authorization
   * - content-type, content-digest (for requests with bodies)
   */
  private async signOutgoingRequest(request: RequestInformation): Promise<void> {
    const coveredComponents = ['@method', '@target-uri', 'authorization'];

    // Add body-related components for POST/PUT/PATCH
    const method = request.httpMethod?.toString().toUpperCase();
    if (method && ['POST', 'PUT', 'PATCH'].includes(method)) {
      coveredComponents.push('content-type', 'content-digest');
    }

    const signer = createSigner({
      keyId: this.options.clientKey.keyId,
      algorithm: this.options.clientKey.algorithm,
      privateKey: this.options.clientKey.privateKey,
    });

    // Extract current headers from the request using Kiota's Headers API
    // Headers extends Map<string, Set<string>>
    const headers: Record<string, string> = {};
    request.headers.forEach((values, key) => {
      if (values && values.size > 0) {
        headers[key] = Array.from(values).join(', ');
      }
    });

    const signedHeaders = await signRequest({
      method: method || 'GET',
      url: request.URL,
      headers,
      body: request.content ? Buffer.from(request.content) : undefined,
      signer,
      coveredComponents,
      includeContentDigest: !!request.content,
      tag: 'gnap',
    });

    // Merge signature headers into the request
    for (const [key, value] of Object.entries(signedHeaders)) {
      request.headers.add(key, value);
    }
  }

  /**
   * Check whether a request URL's host is in the allowed hosts set.
   * Prevents accidental token transmission to unauthorized domains.
   */
  private isHostAllowed(url: string): boolean {
    try {
      const parsed = new URL(url);
      return this.allowedHosts!.has(parsed.hostname.toLowerCase());
    } catch {
      return false;
    }
  }

  /**
   * Returns the underlying access token provider for direct use.
   * Useful for grant continuation after user interaction.
   */
  getAccessTokenProvider(): GnapAccessTokenProvider {
    return this.accessTokenProvider;
  }

  /**
   * Close the provider and release any resources.
   * Called automatically when using `await using` or manual cleanup.
   */
  async close(): Promise<void> {
    // Currently stateless (uses global fetch), but provides
    // a lifecycle signal for future resource management.
  }

  /**
   * Support `await using` syntax (TC39 Explicit Resource Management).
   * Available in Node.js 18+ with --harmony flag, native in 20+.
   */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}
