/**
 * TypeScript interfaces for the Kiota GNAP Authentication Provider.
 */

import type { Algorithm } from '@shujaapay/http-message-signatures';

/** Configuration for the GNAP authentication provider */
export interface GnapAuthOptions {
  /** GNAP authorization server grant endpoint URL */
  grantEndpoint: string;
  /** Client key configuration for GNAP proofs */
  clientKey: ClientKeyConfig;
  /** Resources and actions to request access to */
  accessRights: AccessRight[];
  /** Interaction mode configuration (optional) */
  interaction?: InteractionConfig;
  /** Custom token store (default: InMemoryTokenStore) */
  tokenStore?: TokenStore;
  /**
   * Allowed hosts for token transmission (Kiota best practice).
   * If set, tokens are only attached to requests targeting these hosts.
   * Prevents credential leakage to unauthorized domains.
   * @example ['wallet.example', 'auth.wallet.example']
   */
  allowedHosts?: string[];
  /**
   * Client display information for GNAP grant requests.
   * Shown to the resource owner during interaction.
   */
  clientDisplay?: ClientDisplay;
  /**
   * Wallet address for client identification (Open Payments).
   * If set, the AS resolves the client's JWKS from this endpoint
   * instead of using inline JWK in the grant request.
   * @example 'https://wallet.example/alice'
   */
  walletAddress?: string;
}

/** Client key configuration for GNAP key proofs */
export interface ClientKeyConfig {
  /** Key identifier */
  keyId: string;
  /** Private key material (PEM string or Buffer) */
  privateKey: string | Buffer;
  /** Signing algorithm */
  algorithm: Algorithm;
  /** Key proof method */
  proof: 'httpsig' | 'mtls' | 'jwsd' | 'dpop';
}

/** GNAP access right request (RFC 9635 Section 8 + Open Payments extensions) */
export interface AccessRight {
  /** Resource type (e.g., 'incoming-payment', 'outgoing-payment', 'quote') */
  type: string;
  /**
   * Permitted actions on this resource type.
   *
   * Open Payments standard actions:
   * - incoming-payment: create, complete, read, read-all, list, list-all
   * - outgoing-payment: create, read, read-all, list, list-all
   * - quote: create, read, read-all
   */
  actions: string[];
  /**
   * Specific resource identifier at the RS (Open Payments).
   * Typically a wallet address URL: 'https://wallet.example/alice'
   */
  identifier?: string;
  /** Specific resource locations (RFC 9635 generic) */
  locations?: string[];
  /** Data types (optional) */
  datatypes?: string[];
  /**
   * Payment limits for outgoing-payment grants (Open Payments).
   * Constrains the total amount that can be sent under this grant.
   */
  limits?: PaymentLimits;
}

/**
 * Payment limits for outgoing-payment grants (Open Payments).
 *
 * Used to constrain the total debit/receive amounts and payment
 * intervals for grants that authorize outgoing payments.
 *
 * @example
 * ```ts
 * limits: {
 *   receiver: 'https://wallet.example/bob/incoming-payments/abc',
 *   debitAmount: { value: '1000', assetCode: 'USD', assetScale: 2 },
 *   interval: 'R12/2024-01-01T00:00:00Z/P1M'
 * }
 * ```
 */
export interface PaymentLimits {
  /** URL of the incoming payment being paid */
  receiver?: string;
  /** Maximum debit amount per interval */
  debitAmount?: Amount;
  /** Maximum receive amount per interval */
  receiveAmount?: Amount;
  /**
   * ISO 8601 repeating interval for recurring payments.
   * @example 'R12/2024-01-01T00:00:00Z/P1M' (12 monthly payments)
   */
  interval?: string;
}

/**
 * Monetary amount representation (Open Payments).
 *
 * Uses integer-based representation with asset scale to avoid
 * floating-point precision issues in financial calculations.
 *
 * @example
 * ```ts
 * // $10.00 USD
 * { value: '1000', assetCode: 'USD', assetScale: 2 }
 * // KES 500.00
 * { value: '50000', assetCode: 'KES', assetScale: 2 }
 * ```
 */
export interface Amount {
  /** Unsigned 64-bit integer amount as a string */
  value: string;
  /** ISO 4217 currency code (e.g., 'USD', 'KES', 'EUR') */
  assetCode: string;
  /** Decimal places defining the smallest divisible unit */
  assetScale: number;
}

/** Interaction configuration for resource owner authorization */
export interface InteractionConfig {
  /** How to start interaction */
  start?: ('redirect' | 'app' | 'user_code' | 'user_code_uri')[];
  /** How to receive interaction results */
  finish?: {
    method: 'redirect' | 'push';
    uri: string;
    nonce?: string;
    /** Hash method for interaction hash verification (default: sha-256) */
    hash_method?: 'sha-256' | 'sha-512' | 'sha3-256' | 'sha3-512';
  };
}

/**
 * Client display information (RFC 9635 §2.3).
 * Shown to the resource owner during interaction.
 */
export interface ClientDisplay {
  /** Human-readable client name */
  name?: string;
  /** Client logo URI */
  uri?: string;
  /** Client logo image */
  logo_uri?: string;
}

/** GNAP grant response (RFC 9635 Section 3) */
export interface GrantResponse {
  /** Access token (present if grant is immediately approved) */
  accessToken?: {
    value: string;
    /** Token management URI (for rotation/revocation) */
    manage?: string;
    access: AccessRight[];
    expires_in?: number;
    /** Token flags (RFC 9635 §2.1.1) */
    flags?: ('bearer' | 'durable' | string)[];
  };
  /** Interaction requirements (present if RO interaction is needed) */
  interact?: {
    redirect?: string;
    app?: string;
    user_code?: {
      code: string;
      url?: string;
    };
    finish?: string;
  };
  /** Continuation info for pending grants */
  continue?: {
    access_token: {
      value: string;
    };
    uri: string;
    wait?: number;
  };
}

/** GNAP continuation response */
export interface ContinueResponse {
  accessToken?: GrantResponse['accessToken'];
  continue?: GrantResponse['continue'];
}

/** Stored token information */
export interface TokenInfo {
  /** Access token value */
  value: string;
  /** Token management URI */
  managementUri?: string;
  /** Access rights granted */
  access: AccessRight[];
  /** Expiration timestamp (ms since epoch) */
  expiresAt?: number;
  /** Token flags (bearer, durable) */
  flags?: string[];
  /** Continuation info for grant updates */
  continuation?: {
    uri: string;
    token: string;
    /** Wait interval (seconds) before polling */
    wait?: number;
  };
}

/** Token storage interface (implement for custom storage) */
export interface TokenStore {
  /** Get a stored token for the given scope key */
  get(scopeKey: string): Promise<TokenInfo | undefined>;
  /** Store a token */
  set(scopeKey: string, token: TokenInfo): Promise<void>;
  /** Remove a stored token */
  delete(scopeKey: string): Promise<void>;
  /** Clear all stored tokens */
  clear(): Promise<void>;
}
