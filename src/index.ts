/**
 * @shujaapay/kiota-gnap-auth-ts
 *
 * Kiota GNAP Authentication Provider for TypeScript
 * Implements RFC 9635 (GNAP) authorization for Open Payments SDK generation.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://www.shujaapay.me
 */

// Core providers
export { GnapAuthenticationProvider } from './gnap-auth-provider';
export { GnapAccessTokenProvider } from './gnap-access-token-provider';
export { GnapGrantManager } from './gnap-grant-manager';

// Token storage
export { InMemoryTokenStore } from './token-store';

// Error handling (RFC 9635 §3.6)
export { GnapError, GnapInteractionRequiredError, parseGnapErrorResponse } from './errors';
export type { GnapErrorCode } from './errors';

// Interaction hash verification (RFC 9635 §4.2.3)
export { verifyInteractionHash, computeInteractionHash } from './interaction-hash';

// Retry policy
export { withRetry, DEFAULT_RETRY_POLICY } from './retry';
export type { RetryPolicy } from './retry';

// Event system
export { GnapEventEmitter } from './events';
export type { GnapEvents } from './events';

// Type definitions
export type {
  GnapAuthOptions,
  ClientKeyConfig,
  ClientDisplay,
  AccessRight,
  InteractionConfig,
  GrantResponse,
  ContinueResponse,
  TokenInfo,
  TokenStore,
  PaymentLimits,
  Amount,
} from './types';
