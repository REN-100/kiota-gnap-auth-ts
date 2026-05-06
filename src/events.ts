/**
 * GNAP Grant Lifecycle Events
 *
 * Typed event system for observing grant lifecycle events.
 * Uses Node.js EventEmitter for lightweight, framework-agnostic observability.
 *
 * @example
 * ```ts
 * const emitter = new GnapEventEmitter();
 * emitter.on('token:acquired', (e) => {
 *   console.log(`New token acquired, expires in ${e.expiresIn}s`);
 * });
 * emitter.on('grant:error', (e) => {
 *   console.error(`GNAP error [${e.code}]: ${e.message}`);
 * });
 * ```
 */

import { EventEmitter } from 'events';

/** Event payloads for each lifecycle event */
export interface GnapEvents {
  /** New access token successfully acquired from AS */
  'token:acquired': {
    scopeKey: string;
    expiresIn?: number;
    hasManagementUri: boolean;
  };
  /** Access token successfully rotated */
  'token:rotated': {
    scopeKey: string;
    managementUri: string;
  };
  /** Cached token expired and was pruned */
  'token:expired': {
    scopeKey: string;
  };
  /** Resource owner interaction required */
  'grant:interaction_required': {
    redirectUrl?: string;
    userCode?: string;
    continueUri?: string;
  };
  /** Grant request or continuation failed */
  'grant:error': {
    code?: string;
    message: string;
    statusCode?: number;
    recoverable: boolean;
  };
  /** Grant continuation started (polling) */
  'grant:polling': {
    continueUri: string;
    attempt: number;
    waitSeconds?: number;
  };
  /** Token rotation failed, falling back to new grant */
  'token:rotation_failed': {
    scopeKey: string;
    error: string;
  };
}

/**
 * Typed event emitter for GNAP lifecycle events.
 *
 * Extends Node.js EventEmitter with type-safe event names and payloads.
 */
export class GnapEventEmitter extends EventEmitter {
  emit<K extends keyof GnapEvents>(event: K, payload: GnapEvents[K]): boolean {
    return super.emit(event, payload);
  }

  on<K extends keyof GnapEvents>(
    event: K,
    listener: (payload: GnapEvents[K]) => void
  ): this {
    return super.on(event, listener);
  }

  once<K extends keyof GnapEvents>(
    event: K,
    listener: (payload: GnapEvents[K]) => void
  ): this {
    return super.once(event, listener);
  }

  off<K extends keyof GnapEvents>(
    event: K,
    listener: (payload: GnapEvents[K]) => void
  ): this {
    return super.off(event, listener);
  }
}
