/**
 * Tests for retry policy
 */

import { withRetry, DEFAULT_RETRY_POLICY, type RetryPolicy } from '../src/retry';

describe('withRetry', () => {
  const noDelayPolicy: RetryPolicy = {
    maxAttempts: 3,
    baseDelayMs: 0,
    maxDelayMs: 0,
    jitter: false,
    retryableStatuses: [429, 500],
  };

  it('returns result on first success', async () => {
    const fn = jest.fn().mockResolvedValueOnce('ok');
    const result = await withRetry(fn, noDelayPolicy);
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries on exception and succeeds', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce(new Error('fail'))
      .mockResolvedValueOnce('ok');

    const result = await withRetry(fn, noDelayPolicy);
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('retries based on shouldRetry predicate', async () => {
    const fn = jest.fn()
      .mockResolvedValueOnce({ status: 500 })
      .mockResolvedValueOnce({ status: 200 });

    const result = await withRetry(
      fn,
      noDelayPolicy,
      (r: any) => r.status >= 500
    );

    expect(result.status).toBe(200);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('throws after exhausting all retries', async () => {
    const fn = jest.fn().mockRejectedValue(new Error('persistent failure'));

    await expect(
      withRetry(fn, { ...noDelayPolicy, maxAttempts: 2 })
    ).rejects.toThrow('persistent failure');

    expect(fn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it('does not retry when maxAttempts is 0', async () => {
    const fn = jest.fn().mockRejectedValueOnce(new Error('fail'));

    await expect(
      withRetry(fn, { ...noDelayPolicy, maxAttempts: 0 })
    ).rejects.toThrow('fail');

    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('returns last result when shouldRetry always true and retries exhausted', async () => {
    const fn = jest.fn().mockResolvedValue({ status: 500 });

    const result = await withRetry(
      fn,
      { ...noDelayPolicy, maxAttempts: 2 },
      (r: any) => r.status >= 500
    );

    // After exhausting retries, returns the last result
    expect(result.status).toBe(500);
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('default policy has sensible values', () => {
    expect(DEFAULT_RETRY_POLICY.maxAttempts).toBe(3);
    expect(DEFAULT_RETRY_POLICY.baseDelayMs).toBe(500);
    expect(DEFAULT_RETRY_POLICY.maxDelayMs).toBe(5000);
    expect(DEFAULT_RETRY_POLICY.jitter).toBe(true);
    expect(DEFAULT_RETRY_POLICY.retryableStatuses).toContain(429);
    expect(DEFAULT_RETRY_POLICY.retryableStatuses).toContain(503);
  });
});
