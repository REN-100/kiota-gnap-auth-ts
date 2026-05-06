/**
 * GNAP Grant Manager — RFC 9635 Grant Lifecycle
 *
 * Handles the full GNAP authorization lifecycle:
 * - Grant requests (§2)
 * - Grant responses (§3)
 * - Error handling (§3.6)
 * - Continuation (§5)
 * - Grant deletion (§5.4)
 * - Token management (§6)
 *
 * All requests are signed with HTTP Message Signatures (RFC 9421)
 * using the GNAP httpsig proof method (RFC 9635 §7.3.3).
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 */

import { randomBytes, createPublicKey, createHash } from 'crypto';
import {
  createSigner,
  signRequest,
  exportPublicJwk,
  algorithmToJwkAlg,
} from '@shujaapay/http-message-signatures';
import type { ClientKeyConfig, ClientDisplay, AccessRight, InteractionConfig, GrantResponse, ContinueResponse } from './types';
import { GnapError, parseGnapErrorResponse } from './errors';
import { withRetry, DEFAULT_RETRY_POLICY, type RetryPolicy } from './retry';

/**
 * Manages GNAP grant requests and responses.
 *
 * Implements the grant lifecycle defined in RFC 9635:
 * 1. Client sends a grant request to the AS
 * 2. AS responds with tokens, interaction requirements, or continuation
 * 3. Client handles interaction (if required) and continues the grant
 * 4. Client manages token rotation and revocation
 * 5. Client can delete pending grants
 */
export class GnapGrantManager {
  private readonly retryPolicy: RetryPolicy;

  constructor(
    private readonly grantEndpoint: string,
    private readonly clientKey: ClientKeyConfig,
    private readonly walletAddress?: string,
    private readonly clientDisplay?: ClientDisplay,
    retryPolicy?: Partial<RetryPolicy>
  ) {
    this.retryPolicy = { ...DEFAULT_RETRY_POLICY, ...retryPolicy };
  }

  /**
   * Request a new grant from the authorization server.
   *
   * Per RFC 9635 §2, the grant request includes:
   * - access_token: requested access rights with flags and datatypes
   * - client: client key information with JWK and proof method
   * - interact: interaction preferences (optional)
   *
   * @param accessRights - Resources and actions to request
   * @param interaction - Interaction configuration (optional)
   * @param flags - Token flags (bearer, durable)
   * @returns Grant response with tokens and/or continuation info
   * @throws {GnapError} On structured AS error responses
   */
  async requestGrant(
    accessRights: AccessRight[],
    interaction?: InteractionConfig,
    flags?: string[]
  ): Promise<GrantResponse> {
    const grantRequest: Record<string, unknown> = {
      access_token: {
        access: accessRights.map(right => ({
          type: right.type,
          actions: right.actions,
          ...(right.locations ? { locations: right.locations } : {}),
          ...(right.datatypes ? { datatypes: right.datatypes } : {}),
        })),
        ...(flags && flags.length > 0 ? { flags } : {}),
      },
      client: {
        key: {
          proof: this.clientKey.proof,
          jwk: this.getPublicJwk(),
        },
        ...(this.walletAddress ? { wallet_address: this.walletAddress } : {}),
        ...(this.clientDisplay ? { display: this.clientDisplay } : {}),
      },
    };

    // Add interaction if configured
    if (interaction) {
      grantRequest.interact = {
        start: interaction.start || ['redirect'],
        finish: interaction.finish
          ? {
              method: interaction.finish.method,
              uri: interaction.finish.uri,
              nonce: interaction.finish.nonce || this.generateNonce(),
              ...(interaction.finish.hash_method ? { hash_method: interaction.finish.hash_method } : {}),
            }
          : undefined,
      };
    }

    const response = await this.makeSignedRequest(
      this.grantEndpoint,
      'POST',
      grantRequest
    );

    return this.parseGrantResponse(response);
  }

  /**
   * Continue a pending grant after resource owner interaction.
   *
   * Per RFC 9635 §5.1, the continuation request uses the
   * continuation access token from the initial grant response.
   *
   * @param continueUri - Continuation URI from the grant response
   * @param continueToken - Continuation access token
   * @param interactRef - Interaction reference from the callback
   * @returns Updated grant response with access token
   * @throws {GnapError} On structured AS error responses
   */
  async continueGrant(
    continueUri: string,
    continueToken: string,
    interactRef: string
  ): Promise<ContinueResponse> {
    const response = await this.makeSignedRequest(
      continueUri,
      'POST',
      { interact_ref: interactRef },
      continueToken
    );

    return this.parseContinueResponse(response);
  }

  /**
   * Rotate an existing access token.
   *
   * Per RFC 9635 §6.1, the client presents the current
   * access token to the token management URI to get a new one.
   *
   * @throws {GnapError} On structured AS error responses
   */
  async rotateToken(
    managementUri: string,
    currentToken: string
  ): Promise<string> {
    const response = await this.makeSignedRequest(
      managementUri,
      'POST',
      {},
      currentToken
    );

    if (!response.ok) {
      throw await parseGnapErrorResponse(response);
    }

    const data = await response.json() as { access_token: { value: string } };
    return data.access_token.value;
  }

  /**
   * Revoke an access token.
   *
   * Per RFC 9635 §6.2, sends DELETE to the management URI.
   */
  async revokeToken(
    managementUri: string,
    currentToken: string
  ): Promise<void> {
    await this.makeSignedRequest(
      managementUri,
      'DELETE',
      undefined,
      currentToken
    );
  }

  /**
   * Delete (abandon) a pending grant.
   *
   * Per RFC 9635 §5.4, sends DELETE to the continuation URI
   * to explicitly abandon a pending grant.
   *
   * @param continueUri - Continuation URI from the grant response
   * @param continueToken - Continuation access token
   */
  async deleteGrant(
    continueUri: string,
    continueToken: string
  ): Promise<void> {
    const response = await this.makeSignedRequest(
      continueUri,
      'DELETE',
      undefined,
      continueToken
    );

    if (!response.ok && response.status !== 204) {
      throw await parseGnapErrorResponse(response);
    }
  }

  /**
   * Make an HTTP request signed with HTTP Message Signatures (RFC 9421).
   *
   * All GNAP requests use the httpsig proof method with tag="gnap"
   * per RFC 9635 §7.3.3.
   *
   * Includes configurable retry with exponential backoff for transient failures.
   */
  private async makeSignedRequest(
    url: string,
    method: string,
    body?: Record<string, unknown>,
    bearerToken?: string
  ): Promise<Response> {
    const headers: Record<string, string> = {};

    if (body && method !== 'DELETE') {
      headers['Content-Type'] = 'application/json';
    }

    if (bearerToken) {
      headers['Authorization'] = `GNAP ${bearerToken}`;
    }

    const bodyStr = body && method !== 'DELETE' ? JSON.stringify(body) : undefined;

    // Compute Content-Digest header for request body integrity (RFC 9530)
    if (bodyStr) {
      const digest = createHash('sha256').update(bodyStr).digest('base64');
      headers['Content-Digest'] = `sha-256=:${digest}:`;
    }

    // Sign the request using HTTP Message Signatures with GNAP tag
    const signer = createSigner({
      keyId: this.clientKey.keyId,
      algorithm: this.clientKey.algorithm,
      privateKey: this.clientKey.privateKey,
    });

    const coveredComponents = ['@method', '@target-uri'];
    if (bearerToken) coveredComponents.push('authorization');
    if (bodyStr) coveredComponents.push('content-type', 'content-digest');

    const signedHeaders = await signRequest({
      method,
      url,
      headers,
      body: bodyStr,
      signer,
      coveredComponents,
      includeContentDigest: !!bodyStr,
      tag: 'gnap', // RFC 9635 §7.3.3 — GNAP httpsig proof method
    });

    const allHeaders = { ...headers, ...signedHeaders };

    // Wrap in retry for transient failures
    return withRetry(
      () => fetch(url, {
        method,
        headers: allHeaders,
        body: bodyStr,
      }),
      this.retryPolicy,
      (response) => this.retryPolicy.retryableStatuses.includes(response.status)
    );
  }

  /**
   * Export the client's public key as a JWK for inclusion in grant requests.
   *
   * Derives the public key from the private key material, then uses
   * exportPublicJwk from @shujaapay/http-message-signatures to produce
   * a spec-compliant JWK with kty, crv, x, kid, and alg fields.
   */
  private getPublicJwk(): Record<string, unknown> {
    // Derive public key from private key
    const publicKeyObj = createPublicKey(this.clientKey.privateKey);
    const publicKeyPem = publicKeyObj.export({ type: 'spki', format: 'pem' }) as string;

    const jwk = exportPublicJwk(publicKeyPem, {
      kid: this.clientKey.keyId,
      alg: algorithmToJwkAlg(this.clientKey.algorithm),
    });

    return jwk as Record<string, unknown>;
  }

  /**
   * Generate a cryptographic nonce for interaction (RFC 9635 §2.5.2).
   */
  private generateNonce(): string {
    return randomBytes(32).toString('base64url');
  }

  /**
   * Parse a grant response from the authorization server.
   *
   * Per RFC 9635 §3.6, non-OK responses may contain structured error
   * bodies with error codes, descriptions, and continuation info.
   *
   * @throws {GnapError} On structured AS error responses
   */
  private async parseGrantResponse(response: Response): Promise<GrantResponse> {
    if (!response.ok) {
      throw await parseGnapErrorResponse(response);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      accessToken: data.access_token as GrantResponse['accessToken'],
      interact: data.interact as GrantResponse['interact'],
      continue: data.continue as GrantResponse['continue'],
    };
  }

  /**
   * Parse a continuation response.
   *
   * @throws {GnapError} On structured AS error responses
   */
  private async parseContinueResponse(response: Response): Promise<ContinueResponse> {
    if (!response.ok) {
      throw await parseGnapErrorResponse(response);
    }

    const data = await response.json() as Record<string, unknown>;

    return {
      accessToken: data.access_token as ContinueResponse['accessToken'],
      continue: data.continue as ContinueResponse['continue'],
    };
  }
}
