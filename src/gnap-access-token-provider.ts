/**
 * GNAP Access Token Provider for Kiota
 *
 * Implements Kiota's AccessTokenProvider pattern to orchestrate the
 * GNAP grant lifecycle: check cache → rotate → request grant → store token.
 *
 * Features:
 * - Cache-first token retrieval with TTL-aware storage
 * - Proactive token refresh within grace period
 * - Token rotation via management URI with fallback
 * - Concurrent acquisition guard (prevents duplicate grants)
 * - Continuation polling with wait interval support
 * - Typed event emission for lifecycle observability
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-2
 */

import { GnapGrantManager } from './gnap-grant-manager';
import { GnapInteractionRequiredError } from './errors';
import { GnapEventEmitter } from './events';
import type { TokenStore, TokenInfo, AccessRight, InteractionConfig } from './types';

/** Grace period (ms) before expiry to trigger proactive refresh */
const REFRESH_GRACE_MS = 30_000; // 30 seconds

/** Default maximum polling attempts for continuation */
const MAX_POLL_ATTEMPTS = 30;

/** Default poll interval if AS doesn't specify `wait` (seconds) */
const DEFAULT_POLL_WAIT_S = 5;

/**
 * Provides GNAP access tokens for Kiota request adapters.
 *
 * This class manages the token lifecycle:
 * 1. Check the token store for a valid cached token
 * 2. If within grace period or expired, try token rotation
 * 3. If no token or rotation fails, request a new grant
 * 4. If the AS requires interaction, throw with details
 * 5. Store the token and return it
 *
 * @example
 * ```ts
 * const provider = new GnapAccessTokenProvider(grantManager, tokenStore, accessRights);
 * provider.events.on('token:acquired', (e) => console.log('New token:', e));
 * const token = await provider.getAuthorizationToken('https://wallet.example/payments');
 * ```
 */
export class GnapAccessTokenProvider {
  /** Event emitter for grant lifecycle observability */
  readonly events = new GnapEventEmitter();

  /**
   * In-flight token acquisition promises, keyed by scope.
   * Prevents duplicate concurrent grant requests for the same scope.
   */
  private readonly _inflight = new Map<string, Promise<string | null>>();

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
   * - Uses concurrent acquisition guard to prevent duplicate grants
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

    // Fast path: use peek (non-pruning) so expired tokens survive for rotation
    const cached = await this.peekToken(scopeKey);
    if (cached && this.isTokenValid(cached)) {
      return cached.value;
    }

    // Concurrent acquisition guard:
    // If another caller is already acquiring a token for this scope,
    // wait for that result instead of creating a duplicate grant.
    const existing = this._inflight.get(scopeKey);
    if (existing) {
      return existing;
    }

    // Acquire and cache
    const promise = this._acquireToken(scopeKey);
    this._inflight.set(scopeKey, promise);

    try {
      return await promise;
    } finally {
      this._inflight.delete(scopeKey);
    }
  }

  /**
   * Internal token acquisition — called once per scope key at a time.
   */
  private async _acquireToken(scopeKey: string): Promise<string | null> {
    // 1. Peek at what's in the store (non-pruning) for rotation info
    const peeked = await this.peekToken(scopeKey);

    // 2. Re-check cache (may have been populated by another call)
    const cached = await this.tokenStore.get(scopeKey);
    if (cached && this.isTokenValid(cached)) {
      return cached.value;
    }

    // 3. Try to rotate an existing (possibly expired) token
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
        this.events.emit('token:rotated', {
          scopeKey,
          managementUri: stale.managementUri,
        });
        return refreshed.value;
      } catch (rotateErr) {
        // Rotation failed — emit event and fall through to new grant
        this.events.emit('token:rotation_failed', {
          scopeKey,
          error: (rotateErr as Error).message,
        });
        await this.tokenStore.delete(scopeKey);
      }
    }

    // 4. Request a new grant
    const grantResponse = await this.grantManager.requestGrant(
      this.accessRights,
      this.interaction
    );

    // 5. Handle immediate token issuance
    if (grantResponse.accessToken) {
      const tokenInfo = this.buildTokenInfo(grantResponse);
      await this.tokenStore.set(scopeKey, tokenInfo);
      this.events.emit('token:acquired', {
        scopeKey,
        expiresIn: grantResponse.accessToken.expires_in,
        hasManagementUri: !!grantResponse.accessToken.manage,
      });
      return tokenInfo.value;
    }

    // 6. Handle interaction-required response
    if (grantResponse.interact) {
      this.events.emit('grant:interaction_required', {
        redirectUrl: grantResponse.interact.redirect,
        userCode: grantResponse.interact.user_code?.code,
        continueUri: grantResponse.continue?.uri,
      });

      throw new GnapInteractionRequiredError(
        grantResponse.interact,
        grantResponse.continue
          ? {
              uri: grantResponse.continue.uri,
              token: grantResponse.continue.access_token.value,
              wait: grantResponse.continue.wait,
            }
          : undefined
      );
    }

    // 7. No token and no interaction — shouldn't happen per RFC
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
    const tokenInfo = this.buildTokenInfoFromContinuation(response);

    await this.tokenStore.set(scopeKey, tokenInfo);
    this.events.emit('token:acquired', {
      scopeKey,
      expiresIn: response.accessToken.expires_in,
      hasManagementUri: !!response.accessToken.manage,
    });
    return tokenInfo.value;
  }

  /**
   * Poll for continuation until the AS returns a token.
   *
   * Per RFC 9635 §5.2, the AS may respond with `continue.wait`
   * indicating the client should poll again after N seconds.
   *
   * @param continueUri - Initial continuation URI
   * @param continueToken - Continuation access token
   * @param interactRef - Interaction reference from the callback
   * @param maxAttempts - Maximum polling attempts (default: 30)
   * @returns The access token value
   */
  async pollContinuation(
    continueUri: string,
    continueToken: string,
    interactRef: string,
    maxAttempts: number = MAX_POLL_ATTEMPTS
  ): Promise<string> {
    let currentUri = continueUri;
    let currentToken = continueToken;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      this.events.emit('grant:polling', {
        continueUri: currentUri,
        attempt,
      });

      try {
        const response = await this.grantManager.continueGrant(
          currentUri,
          currentToken,
          interactRef
        );

        // Got a token — done
        if (response.accessToken) {
          const scopeKey = this.buildScopeKey();
          const tokenInfo = this.buildTokenInfoFromContinuation(response);
          await this.tokenStore.set(scopeKey, tokenInfo);
          this.events.emit('token:acquired', {
            scopeKey,
            expiresIn: response.accessToken.expires_in,
            hasManagementUri: !!response.accessToken.manage,
          });
          return tokenInfo.value;
        }

        // Got continuation with wait — poll again
        if (response.continue) {
          const waitSeconds = response.continue.wait ?? DEFAULT_POLL_WAIT_S;

          this.events.emit('grant:polling', {
            continueUri: response.continue.uri,
            attempt,
            waitSeconds,
          });

          // Update for next iteration (AS may change URI/token)
          currentUri = response.continue.uri;
          currentToken = response.continue.access_token.value;

          await this.sleep(waitSeconds * 1000);
          continue;
        }

        // No token and no continuation — unexpected
        throw new Error('GNAP continuation returned neither token nor continuation');
      } catch (error) {
        // If it's a 'too_fast' error, back off and retry
        if (error && typeof error === 'object' && 'code' in error) {
          const gnapErr = error as { code: string; retryAfter?: number };
          if (gnapErr.code === 'too_fast') {
            const backoff = gnapErr.retryAfter ?? DEFAULT_POLL_WAIT_S * 2;
            await this.sleep(backoff * 1000);
            continue;
          }
        }
        throw error;
      }
    }

    throw new Error(`GNAP continuation polling exhausted after ${maxAttempts} attempts`);
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
   * Build TokenInfo from a grant response.
   */
  private buildTokenInfo(grantResponse: { accessToken?: any; continue?: any }): TokenInfo {
    return {
      value: grantResponse.accessToken.value,
      managementUri: grantResponse.accessToken.manage,
      access: grantResponse.accessToken.access,
      flags: grantResponse.accessToken.flags,
      expiresAt: grantResponse.accessToken.expires_in
        ? Date.now() + grantResponse.accessToken.expires_in * 1000
        : undefined,
      continuation: grantResponse.continue
        ? {
            uri: grantResponse.continue.uri,
            token: grantResponse.continue.access_token.value,
            wait: grantResponse.continue.wait,
          }
        : undefined,
    };
  }

  /**
   * Build TokenInfo from a continuation response.
   */
  private buildTokenInfoFromContinuation(response: { accessToken?: any; continue?: any }): TokenInfo {
    return this.buildTokenInfo(response);
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

  /**
   * Sleep for the given number of milliseconds.
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
