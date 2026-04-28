/**
 * GNAP Authentication Provider for Kiota
 * 
 * Implements Kiota's AuthenticationProvider interface to handle
 * GNAP (RFC 9635) authorization for generated SDK clients.
 */

import type { AuthenticationProvider, RequestInformation } from '@microsoft/kiota-abstractions';
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
 * @example
 * ```typescript
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
 * });
 * 
 * const adapter = new FetchRequestAdapter(authProvider);
 * const client = new OpenPaymentsClient(adapter);
 * ```
 */
export class GnapAuthenticationProvider implements AuthenticationProvider {
  private readonly grantManager: GnapGrantManager;
  private readonly tokenStore: TokenStore;
  private readonly accessTokenProvider: GnapAccessTokenProvider;

  constructor(private readonly options: GnapAuthOptions) {
    this.grantManager = new GnapGrantManager(
      options.grantEndpoint,
      options.clientKey
    );
    this.tokenStore = options.tokenStore || new InMemoryTokenStore();
    this.accessTokenProvider = new GnapAccessTokenProvider(
      this.grantManager,
      this.tokenStore,
      options.accessRights,
      options.interaction
    );
  }

  /**
   * Authenticates an outgoing HTTP request by:
   * 1. Obtaining a valid GNAP access token
   * 2. Adding the Authorization header (GNAP token)
   * 3. Signing the request with HTTP Message Signatures
   * 
   * This method is called automatically by Kiota's request adapter
   * before each API call.
   */
  async authenticateRequest(
    request: RequestInformation,
    additionalAuthenticationContext?: Record<string, unknown>
  ): Promise<void> {
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
    await this.signRequest(request);
  }

  /**
   * Signs the request using RFC 9421 HTTP Message Signatures.
   * 
   * Covered components for Open Payments:
   * - @method, @target-uri, authorization
   * - content-type, content-digest (for requests with bodies)
   */
  private async signRequest(request: RequestInformation): Promise<void> {
    const coveredComponents = ['@method', '@target-uri', 'authorization'];

    // Add body-related components for POST/PUT/PATCH
    const method = request.httpMethod?.toString().toUpperCase();
    if (method && ['POST', 'PUT', 'PATCH'].includes(method)) {
      coveredComponents.push('content-type', 'content-digest');
    }

    // Delegate to HTTP Message Signatures library
    // The actual signing is handled by @shujaapay/http-message-signatures
    const { signRequest, createSigner } = await import('@shujaapay/http-message-signatures');
    
    const signer = createSigner({
      keyId: this.options.clientKey.keyId,
      algorithm: this.options.clientKey.algorithm,
      privateKey: this.options.clientKey.privateKey,
    });

    const headers: Record<string, string> = {};
    request.headers.getAll().forEach((values, key) => {
      headers[key] = values.join(', ');
    });

    const signedHeaders = await signRequest({
      method: method || 'GET',
      url: request.URL,
      headers,
      body: request.content ? Buffer.from(request.content) : undefined,
      signer,
      coveredComponents,
      includeContentDigest: !!request.content,
    });

    // Merge signature headers into the request
    Object.entries(signedHeaders).forEach(([key, value]) => {
      request.headers.add(key, value);
    });
  }

  /**
   * Returns the underlying access token provider for direct use.
   */
  getAccessTokenProvider(): GnapAccessTokenProvider {
    return this.accessTokenProvider;
  }
}
