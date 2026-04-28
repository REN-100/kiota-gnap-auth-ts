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
}

/** Client key configuration for GNAP key proofs */
export interface ClientKeyConfig {
  /** Key identifier */
  keyId: string;
  /** Private key material */
  privateKey: string | Buffer | CryptoKey;
  /** Signing algorithm */
  algorithm: Algorithm;
  /** Key proof method */
  proof: 'httpsig' | 'mtls' | 'jwsd' | 'dpop';
}

/** GNAP access right request (RFC 9635 Section 8) */
export interface AccessRight {
  /** Resource type (e.g., 'incoming-payment', 'outgoing-payment') */
  type: string;
  /** Permitted actions on this resource type */
  actions: string[];
  /** Specific resource locations (optional) */
  locations?: string[];
  /** Data types (optional) */
  datatypes?: string[];
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
  };
}

/** GNAP grant response (RFC 9635 Section 3) */
export interface GrantResponse {
  /** Access token (present if grant is immediately approved) */
  accessToken?: {
    value: string;
    manage?: {
      uri: string;
    };
    access: AccessRight[];
    expires_in?: number;
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
  /** Continuation info for grant updates */
  continuation?: {
    uri: string;
    token: string;
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
