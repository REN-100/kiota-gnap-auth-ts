/**
 * GNAP Error Types — RFC 9635 §3.6
 *
 * Provides structured, machine-readable error types for GNAP
 * authorization failures. Consumers can inspect `error.code` for
 * programmatic error handling.
 *
 * @see https://www.rfc-editor.org/rfc/rfc9635#section-3.6
 */

/**
 * GNAP error codes as defined in RFC 9635 §3.6 and the IANA registry.
 */
export type GnapErrorCode =
  | 'invalid_client'
  | 'invalid_interaction'
  | 'invalid_flag'
  | 'invalid_rotation'
  | 'key_rotation_not_supported'
  | 'need_key'
  | 'too_fast'
  | 'too_many_attempts'
  | 'unknown_interaction'
  | 'unknown_user'
  | 'user_denied'
  | 'request_denied'
  | 'unknown_request'
  | 'too_short'
  | string; // Allow extension error codes

/**
 * Structured GNAP error with machine-readable code.
 *
 * @example
 * ```ts
 * try {
 *   await grantManager.requestGrant(rights);
 * } catch (e) {
 *   if (e instanceof GnapError) {
 *     switch (e.code) {
 *       case 'user_denied':
 *         console.log('User denied the grant request');
 *         break;
 *       case 'too_fast':
 *         console.log(`Retry after ${e.retryAfter}s`);
 *         break;
 *       case 'invalid_client':
 *         console.log('Client key/signature validation failed');
 *         break;
 *     }
 *     // Recoverable error — AS may have sent continuation info
 *     if (e.continue) {
 *       await grantManager.continueGrant(e.continue.uri, e.continue.token);
 *     }
 *   }
 * }
 * ```
 */
export class GnapError extends Error {
  /** Machine-readable GNAP error code (RFC 9635 §3.6) */
  readonly code: GnapErrorCode;

  /** HTTP status code from the AS response */
  readonly statusCode: number;

  /** Human-readable error description from the AS */
  readonly description?: string;

  /**
   * Continuation info if the grant is still recoverable.
   * The AS may include this even in error responses.
   */
  readonly continue?: {
    uri: string;
    token: string;
    wait?: number;
  };

  /** Retry-After hint (seconds) for rate-limited requests */
  readonly retryAfter?: number;

  constructor(params: {
    code: GnapErrorCode;
    statusCode: number;
    description?: string;
    continue?: GnapError['continue'];
    retryAfter?: number;
  }) {
    const msg = params.description
      ? `GNAP error [${params.code}]: ${params.description}`
      : `GNAP error [${params.code}]`;
    super(msg);
    this.name = 'GnapError';
    this.code = params.code;
    this.statusCode = params.statusCode;
    this.description = params.description;
    this.continue = params.continue;
    this.retryAfter = params.retryAfter;
  }

  /** Whether this error is recoverable via continuation */
  get isRecoverable(): boolean {
    return this.continue !== undefined;
  }

  /** Whether the client should retry after a delay */
  get shouldRetry(): boolean {
    return this.code === 'too_fast' || this.statusCode === 429 || this.statusCode >= 500;
  }
}

/**
 * GNAP Interaction Required error.
 * Thrown when the AS requires resource owner interaction.
 */
export class GnapInteractionRequiredError extends Error {
  readonly name = 'GnapInteractionRequiredError';

  constructor(
    public readonly interact: {
      redirect?: string;
      app?: string;
      user_code?: { code: string; url?: string };
      finish?: string;
    },
    public readonly continuation?: {
      uri: string;
      token: string;
      wait?: number;
    }
  ) {
    super('GNAP grant requires resource owner interaction');
  }

  /** Get the redirect URL for browser-based interaction */
  get redirectUrl(): string | undefined {
    return this.interact.redirect;
  }

  /** Get the user code for device-based interaction */
  get userCode(): string | undefined {
    return this.interact.user_code?.code;
  }
}

/**
 * Parse an HTTP error response from a GNAP Authorization Server.
 *
 * Per RFC 9635 §3.6, error responses contain:
 * - `error.code`: Machine-readable error code
 * - `error.description`: Optional human-readable description
 * - `continue`: Optional continuation info (recoverable errors)
 */
export async function parseGnapErrorResponse(
  response: Response
): Promise<GnapError> {
  let code: GnapErrorCode = 'request_denied';
  let description: string | undefined;
  let continuation: GnapError['continue'] | undefined;
  let retryAfter: number | undefined;

  // Parse Retry-After header
  const retryHeader = response.headers.get('retry-after');
  if (retryHeader) {
    retryAfter = parseInt(retryHeader, 10);
    if (isNaN(retryAfter)) retryAfter = undefined;
  }

  try {
    const data = await response.json() as Record<string, unknown>;

    // RFC 9635 §3.6 — error can be a string or an object
    if (typeof data.error === 'string') {
      code = data.error as GnapErrorCode;
    } else if (data.error && typeof data.error === 'object') {
      const errorObj = data.error as Record<string, unknown>;
      code = (errorObj.code as string) || 'request_denied';
      description = errorObj.description as string | undefined;
    }

    // Check for continuation info in error response
    if (data.continue && typeof data.continue === 'object') {
      const cont = data.continue as Record<string, unknown>;
      const accessToken = cont.access_token as Record<string, unknown> | undefined;
      if (cont.uri && accessToken?.value) {
        continuation = {
          uri: cont.uri as string,
          token: accessToken.value as string,
          wait: cont.wait as number | undefined,
        };
      }
    }
  } catch {
    // Response body wasn't JSON — use status-based defaults
    description = response.statusText;
  }

  return new GnapError({
    code,
    statusCode: response.status,
    description,
    continue: continuation,
    retryAfter,
  });
}
