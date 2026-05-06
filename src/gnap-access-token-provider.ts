/**
 * GNAP Access Token Provider for Kiota
 *
 * Implements Kiota's AccessTokenProvider pattern to orchestrate the
 * GNAP grant lifecycle: check cache → request grant → store token → return.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-2
 */

import { GnapGrantManager } from './gnap-grant-manager';
import type { TokenStore, TokenInfo, AccessRight, InteractionConfig } from './types';

/** Grace period (ms) before expiry to trigger proactive refresh */
const REFRESH_GRACE_MS = 30_000; // 30 seconds

/**
 * Provides GNAP access tokens for Kiota request adapters.
 *
 * This class manages the token lifecycle:
 * 1. Check the token store for a valid cached token
 * 2. If expired or missing, request a new grant from the AS
 * 3. If the AS requires interaction, throw with details
 * 4. Store the token and return it
 *
 * @example
 * ```ts
 * const provider = new GnapAccessTokenProvider(grantManager, tokenStore, accessRights);
 * const token = await provider.getAuthorizationToken('https://wallet.example/payments');
 * // Returns 'os_token_abc123' or null
 * ```
 */
export class GnapAccessTokenProvider {
  constructor(
    private readonly grantManager: GnapGrantManager,
    private readonly tokenStore: TokenStore,
    private readonly accessRights: AccessRight[],
    private readonly interaction?: InteractionConfig
  ) {}

  /**
   * Get a valid GNAP access token for the given URL.
   *
   * Implements the Kiota AccessTokenProvider pattern:
   * - Returns the cached token if still valid
   * - Requests a new grant if no valid token exists
   * - Returns null if the URL should not be authenticated
   *
   * @param url - The target URL (used as scope key)
   * @param additionalContext - Optional context from Kiota
   * @returns Access token string, or null if unauthenticated
   */
  async getAuthorizationToken(
    url?: string,
    additionalContext?: Record<string, unknown>
  ): Promise<string | null> {
    const scopeKey = this.buildScopeKey();

    // 1. Peek at what's in the store (non-pruning) for rotation info
    const peeked = await this.peekToken(scopeKey);

    // 2. Check cache for a valid (non-expired) token
    const cached = await this.tokenStore.get(scopeKey);
    if (cached && this.isTokenValid(cached)) {
      return cached.value;
    }

    // 3. Try to rotate an existing (possibly expired) token
    //    Use the peeked value since get() may have auto-pruned it
    const stale = cached || peeked;
    if (stale?.managementUri && stale.value) {
      try {
        const newTokenValue = await this.grantManager.rotateToken(
          stale.managementUri,
          stale.value
        );
        const refreshed: TokenInfo = {
          ...stale,
          value: newTokenValue,
          expiresAt: Date.now() + 3600_000, // Default 1 hour
        };
        await this.tokenStore.set(scopeKey, refreshed);
        return refreshed.value;
      } catch {
        // Rotation failed — fall through to new grant
        await this.tokenStore.delete(scopeKey);
      }
    }

    // 3. Request a new grant
    const grantResponse = await this.grantManager.requestGrant(
      this.accessRights,
      this.interaction
    );

    // 4. Handle immediate token issuance
    if (grantResponse.accessToken) {
      const tokenInfo: TokenInfo = {
        value: grantResponse.accessToken.value,
        managementUri: grantResponse.accessToken.manage?.uri,
        access: grantResponse.accessToken.access,
        expiresAt: grantResponse.accessToken.expires_in
          ? Date.now() + grantResponse.accessToken.expires_in * 1000
          : undefined,
        continuation: grantResponse.continue
          ? {
              uri: grantResponse.continue.uri,
              token: grantResponse.continue.access_token.value,
            }
          : undefined,
      };

      await this.tokenStore.set(scopeKey, tokenInfo);
      return tokenInfo.value;
    }

    // 5. Handle interaction-required response
    if (grantResponse.interact) {
      const interactError = new Error(
        'GNAP grant requires resource owner interaction'
      ) as Error & { interact: typeof grantResponse.interact; continue: typeof grantResponse.continue };
      interactError.interact = grantResponse.interact;
      interactError.continue = grantResponse.continue;
      throw interactError;
    }

    // 6. No token and no interaction — shouldn't happen per RFC
    return null;
  }

  /**
   * Continue a pending grant after resource owner interaction.
   *
   * Call this after the user has completed the redirect/user_code flow.
   *
   * @param continueUri - Continuation URI from the grant response
   * @param continueToken - Continuation access token
   * @param interactRef - Interaction reference from the callback
   * @returns The access token value
   */
  async continueGrant(
    continueUri: string,
    continueToken: string,
    interactRef: string
  ): Promise<string> {
    const response = await this.grantManager.continueGrant(
      continueUri,
      continueToken,
      interactRef
    );

    if (!response.accessToken) {
      throw new Error('GNAP continuation did not return an access token');
    }

    const scopeKey = this.buildScopeKey();
    const tokenInfo: TokenInfo = {
      value: response.accessToken.value,
      managementUri: response.accessToken.manage?.uri,
      access: response.accessToken.access,
      expiresAt: response.accessToken.expires_in
        ? Date.now() + response.accessToken.expires_in * 1000
        : undefined,
      continuation: response.continue
        ? {
            uri: response.continue.uri,
            token: response.continue.access_token.value,
          }
        : undefined,
    };

    await this.tokenStore.set(scopeKey, tokenInfo);
    return tokenInfo.value;
  }

  /**
   * Check if a cached token is still valid (not expired, with grace period).
   */
  private isTokenValid(token: TokenInfo): boolean {
    if (token.expiresAt === undefined) return true;
    return Date.now() < token.expiresAt - REFRESH_GRACE_MS;
  }

  /**
   * Peek at a stored token without auto-pruning.
   * Falls back to regular get() if the store doesn't support peek.
   */
  private async peekToken(scopeKey: string): Promise<TokenInfo | undefined> {
    if ('peek' in this.tokenStore && typeof this.tokenStore.peek === 'function') {
      return (this.tokenStore as any).peek(scopeKey);
    }
    return undefined;
  }

  /**
   * Build a stable scope key from the access rights.
   * Used as the token store key.
   */
  private buildScopeKey(): string {
    return this.accessRights
      .map((r) => `${r.type}:${r.actions.sort().join(',')}`)
      .sort()
      .join('|');
  }
}

