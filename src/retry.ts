/**
 * Retry Policy for GNAP HTTP Requests
 *
 * Provides configurable retry with exponential backoff and jitter
 * for transient network failures and rate-limited responses.
 */

/** Configuration for retry behavior */
export interface RetryPolicy {
  /** Maximum number of retry attempts (default: 3) */
  maxAttempts: number;
  /** Base delay in ms before first retry (default: 500) */
  baseDelayMs: number;
  /** Maximum delay in ms (default: 5000) */
  maxDelayMs: number;
  /** Whether to add random jitter to delays (default: true) */
  jitter: boolean;
  /** HTTP status codes that trigger a retry (default: [429, 500, 502, 503, 504]) */
  retryableStatuses: number[];
}

/** Default retry policy */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 500,
  maxDelayMs: 5000,
  jitter: true,
  retryableStatuses: [429, 500, 502, 503, 504],
};

/**
 * Execute a function with retry logic using exponential backoff.
 *
 * @param fn - The async function to execute
 * @param policy - Retry policy configuration
 * @param shouldRetry - Optional predicate to determine if a result should trigger retry
 * @returns The result of the function
 *
 * @example
 * ```ts
 * const response = await withRetry(
 *   () => fetch(url, options),
 *   { maxAttempts: 3, baseDelayMs: 500, maxDelayMs: 5000, jitter: true, retryableStatuses: [429, 500] },
 *   (response) => !response.ok && [429, 500].includes(response.status)
 * );
 * ```
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  policy: RetryPolicy = DEFAULT_RETRY_POLICY,
  shouldRetry?: (result: T) => boolean
): Promise<T> {
  let lastError: Error | undefined;

  for (let attempt = 0; attempt <= policy.maxAttempts; attempt++) {
    try {
      const result = await fn();

      // Check if the result indicates we should retry
      if (shouldRetry && shouldRetry(result) && attempt < policy.maxAttempts) {
        await sleep(calculateDelay(attempt, policy));
        continue;
      }

      return result;
    } catch (error) {
      lastError = error as Error;

      if (attempt < policy.maxAttempts) {
        await sleep(calculateDelay(attempt, policy));
      }
    }
  }

  throw lastError || new Error('Retry failed: no attempts succeeded');
}

/**
 * Calculate the delay for a given attempt using exponential backoff.
 */
function calculateDelay(attempt: number, policy: RetryPolicy): number {
  // Exponential backoff: baseDelay * 2^attempt
  let delay = policy.baseDelayMs * Math.pow(2, attempt);

  // Cap at maximum
  delay = Math.min(delay, policy.maxDelayMs);

  // Add jitter (±25%)
  if (policy.jitter) {
    const jitterRange = delay * 0.25;
    delay += (Math.random() * 2 - 1) * jitterRange;
  }

  return Math.max(0, Math.round(delay));
}

/**
 * Sleep for the given number of milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
