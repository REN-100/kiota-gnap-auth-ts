/**
 * In-Memory Token Store
 *
 * Default token storage implementation for the GNAP authentication provider.
 * Stores tokens in a Map with TTL-aware retrieval — expired tokens are
 * automatically pruned on access.
 *
 * For production use with multiple server instances, replace with a
 * Redis/database-backed implementation of the TokenStore interface.
 */

import type { TokenStore, TokenInfo } from './types';

/**
 * In-memory token store with automatic expiry detection.
 *
 * @example
 * ```ts
 * const store = new InMemoryTokenStore();
 * await store.set('incoming-payment', {
 *   value: 'os_token_abc123',
 *   access: [{ type: 'incoming-payment', actions: ['create'] }],
 *   expiresAt: Date.now() + 3600_000,
 * });
 *
 * const token = await store.get('incoming-payment');
 * // Returns undefined if expired
 * ```
 */
export class InMemoryTokenStore implements TokenStore {
  private readonly tokens = new Map<string, TokenInfo>();

  /**
   * Retrieve a stored token by scope key.
   * Returns undefined if the token doesn't exist or has expired.
   */
  async get(scopeKey: string): Promise<TokenInfo | undefined> {
    const token = this.tokens.get(scopeKey);
    if (!token) return undefined;

    // Check TTL — auto-prune expired tokens
    if (token.expiresAt !== undefined && Date.now() >= token.expiresAt) {
      this.tokens.delete(scopeKey);
      return undefined;
    }

    return token;
  }

  /**
   * Store a token under the given scope key.
   * Overwrites any existing token for this scope.
   */
  async set(scopeKey: string, token: TokenInfo): Promise<void> {
    this.tokens.set(scopeKey, token);
  }

  /**
   * Remove a token by scope key.
   */
  async delete(scopeKey: string): Promise<void> {
    this.tokens.delete(scopeKey);
  }

  /**
   * Clear all stored tokens (e.g., on logout).
   */
  async clear(): Promise<void> {
    this.tokens.clear();
  }

  /**
   * Returns the number of currently stored tokens (includes expired).
   * Useful for testing and debugging.
   */
  get size(): number {
    return this.tokens.size;
  }

  /**
   * Retrieve a stored token without auto-pruning expired entries.
   * Used internally for token rotation — we need the management URI
   * even after the token has expired.
   */
  async peek(scopeKey: string): Promise<TokenInfo | undefined> {
    return this.tokens.get(scopeKey);
  }
}
