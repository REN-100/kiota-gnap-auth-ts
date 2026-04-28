/**
 * GNAP Grant Manager - RFC 9635 Grant Lifecycle
 * 
 * Handles the full GNAP grant lifecycle:
 * - Grant requests (Section 2)
 * - Grant responses (Section 3)
 * - Continuation (Section 5)
 * - Token management (Section 6)
 */

import type { ClientKeyConfig, AccessRight, InteractionConfig, GrantResponse, ContinueResponse } from './types';

/**
 * Manages GNAP grant requests and responses.
 * 
 * Implements the grant lifecycle defined in RFC 9635:
 * 1. Client sends a grant request to the AS
 * 2. AS responds with tokens, interaction requirements, or continuation
 * 3. Client handles interaction (if required) and continues the grant
 * 4. Client manages token rotation and revocation
 */
export class GnapGrantManager {
  constructor(
    private readonly grantEndpoint: string,
    private readonly clientKey: ClientKeyConfig
  ) {}

  /**
   * Request a new grant from the authorization server.
   * 
   * Per RFC 9635 Section 2, the grant request includes:
   * - access_token: requested access rights
   * - client: client key information
   * - interact: interaction preferences (optional)
   * 
   * @param accessRights - Resources and actions to request
   * @param interaction - Interaction configuration (optional)
   * @returns Grant response with tokens and/or continuation info
   */
  async requestGrant(
    accessRights: AccessRight[],
    interaction?: InteractionConfig
  ): Promise<GrantResponse> {
    const grantRequest: Record<string, unknown> = {
      access_token: {
        access: accessRights.map(right => ({
          type: right.type,
          actions: right.actions,
          ...(right.locations ? { locations: right.locations } : {}),
        })),
      },
      client: {
        key: {
          proof: this.clientKey.proof,
          jwk: await this.exportPublicJwk(),
        },
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
   * Per RFC 9635 Section 5.1, the continuation request uses the
   * continuation access token from the initial grant response.
   * 
   * @param continueUri - Continuation URI from the grant response
   * @param continueToken - Continuation access token
   * @param interactRef - Interaction reference from the callback
   * @returns Updated grant response with access token
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
   * Per RFC 9635 Section 6.1, the client presents the current
   * access token to the token management URI to get a new one.
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

    const data = await response.json() as { access_token: { value: string } };
    return data.access_token.value;
  }

  /**
   * Revoke an access token.
   * 
   * Per RFC 9635 Section 6.2, sends DELETE to the management URI.
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
   * Make an HTTP request signed with HTTP Message Signatures (RFC 9421).
   */
  private async makeSignedRequest(
    url: string,
    method: string,
    body?: Record<string, unknown>,
    bearerToken?: string
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (bearerToken) {
      headers['Authorization'] = `GNAP ${bearerToken}`;
    }

    const bodyStr = body ? JSON.stringify(body) : undefined;

    // Sign the request using HTTP Message Signatures
    const { signRequest, createSigner } = await import('@shujaapay/http-message-signatures');
    
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
    });

    const allHeaders = { ...headers, ...signedHeaders };

    return fetch(url, {
      method,
      headers: allHeaders,
      body: bodyStr,
    });
  }

  /**
   * Export the client's public key as a JWK.
   */
  private async exportPublicJwk(): Promise<Record<string, string>> {
    // Placeholder: In production, derive from the private key
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      kid: this.clientKey.keyId,
      // x: base64url-encoded public key
    };
  }

  /**
   * Parse a grant response from the authorization server.
   */
  private async parseGrantResponse(response: Response): Promise<GrantResponse> {
    const data = await response.json() as Record<string, unknown>;
    
    return {
      accessToken: data.access_token as GrantResponse['accessToken'],
      interact: data.interact as GrantResponse['interact'],
      continue: data.continue as GrantResponse['continue'],
    };
  }

  /**
   * Parse a continuation response.
   */
  private async parseContinueResponse(response: Response): Promise<ContinueResponse> {
    const data = await response.json() as Record<string, unknown>;
    
    return {
      accessToken: data.access_token as ContinueResponse['accessToken'],
      continue: data.continue as ContinueResponse['continue'],
    };
  }

  /**
   * Generate a cryptographic nonce for interaction.
   */
  private generateNonce(): string {
    const { randomBytes } = require('crypto');
    return randomBytes(32).toString('base64url');
  }
}
