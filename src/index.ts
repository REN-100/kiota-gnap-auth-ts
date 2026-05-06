/**
 * @shujaapay/kiota-gnap-auth-ts
 *
 * Kiota GNAP Authentication Provider for TypeScript
 * Implements RFC 9635 (GNAP) authorization for Open Payments SDK generation.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635
 * @see https://www.shujaapay.me
 */

export { GnapAuthenticationProvider } from './gnap-auth-provider';
export { GnapAccessTokenProvider } from './gnap-access-token-provider';
export { GnapGrantManager } from './gnap-grant-manager';
export { InMemoryTokenStore } from './token-store';
export { verifyInteractionHash, computeInteractionHash } from './interaction-hash';

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
} from './types';
