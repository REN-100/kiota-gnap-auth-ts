/**
 * Tests for GNAP Error Types (RFC 9635 §3.6)
 */

import { GnapError, GnapInteractionRequiredError, parseGnapErrorResponse } from '../src/errors';

describe('GnapError', () => {
  it('creates error with code and description', () => {
    const err = new GnapError({
      code: 'invalid_client',
      statusCode: 400,
      description: 'Client key not recognized',
    });

    expect(err.code).toBe('invalid_client');
    expect(err.statusCode).toBe(400);
    expect(err.description).toBe('Client key not recognized');
    expect(err.message).toBe('GNAP error [invalid_client]: Client key not recognized');
    expect(err.name).toBe('GnapError');
  });

  it('creates error without description', () => {
    const err = new GnapError({ code: 'user_denied', statusCode: 403 });
    expect(err.message).toBe('GNAP error [user_denied]');
  });

  it('marks error as recoverable when continue info present', () => {
    const err = new GnapError({
      code: 'unknown_interaction',
      statusCode: 400,
      continue: { uri: 'https://auth.example/continue/1', token: 'ct' },
    });
    expect(err.isRecoverable).toBe(true);
  });

  it('marks error as non-recoverable without continue info', () => {
    const err = new GnapError({ code: 'invalid_client', statusCode: 400 });
    expect(err.isRecoverable).toBe(false);
  });

  it('identifies retryable errors', () => {
    expect(new GnapError({ code: 'too_fast', statusCode: 400 }).shouldRetry).toBe(true);
    expect(new GnapError({ code: 'request_denied', statusCode: 429 }).shouldRetry).toBe(true);
    expect(new GnapError({ code: 'request_denied', statusCode: 503 }).shouldRetry).toBe(true);
    expect(new GnapError({ code: 'invalid_client', statusCode: 400 }).shouldRetry).toBe(false);
  });

  it('includes retryAfter when provided', () => {
    const err = new GnapError({
      code: 'too_fast',
      statusCode: 429,
      retryAfter: 5,
    });
    expect(err.retryAfter).toBe(5);
  });
});

describe('GnapInteractionRequiredError', () => {
  it('creates error with redirect URL', () => {
    const err = new GnapInteractionRequiredError(
      { redirect: 'https://auth.example/interact/abc' },
      { uri: 'https://auth.example/continue/abc', token: 'ct' }
    );
    expect(err.redirectUrl).toBe('https://auth.example/interact/abc');
    expect(err.continuation?.uri).toBe('https://auth.example/continue/abc');
    expect(err.message).toBe('GNAP grant requires resource owner interaction');
  });

  it('creates error with user code', () => {
    const err = new GnapInteractionRequiredError({
      user_code: { code: 'A1B2C3', url: 'https://auth.example/device' },
    });
    expect(err.userCode).toBe('A1B2C3');
    expect(err.redirectUrl).toBeUndefined();
  });
});

describe('parseGnapErrorResponse', () => {
  it('parses error object format', async () => {
    const response = {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      headers: { get: () => null },
      json: async () => ({
        error: { code: 'invalid_client', description: 'Key not found' },
      }),
    } as unknown as Response;

    const err = await parseGnapErrorResponse(response);
    expect(err.code).toBe('invalid_client');
    expect(err.description).toBe('Key not found');
    expect(err.statusCode).toBe(400);
  });

  it('parses error string format', async () => {
    const response = {
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      headers: { get: () => null },
      json: async () => ({ error: 'user_denied' }),
    } as unknown as Response;

    const err = await parseGnapErrorResponse(response);
    expect(err.code).toBe('user_denied');
    expect(err.statusCode).toBe(403);
  });

  it('parses Retry-After header', async () => {
    const response = {
      ok: false,
      status: 429,
      statusText: 'Too Many Requests',
      headers: { get: (h: string) => h === 'retry-after' ? '10' : null },
      json: async () => ({ error: 'too_fast' }),
    } as unknown as Response;

    const err = await parseGnapErrorResponse(response);
    expect(err.code).toBe('too_fast');
    expect(err.retryAfter).toBe(10);
  });

  it('parses continuation info in error response', async () => {
    const response = {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      headers: { get: () => null },
      json: async () => ({
        error: 'unknown_interaction',
        continue: {
          access_token: { value: 'cont_tok' },
          uri: 'https://auth.example/continue/1',
          wait: 5,
        },
      }),
    } as unknown as Response;

    const err = await parseGnapErrorResponse(response);
    expect(err.isRecoverable).toBe(true);
    expect(err.continue?.uri).toBe('https://auth.example/continue/1');
    expect(err.continue?.wait).toBe(5);
  });

  it('handles non-JSON response body', async () => {
    const response = {
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      headers: { get: () => null },
      json: async () => { throw new Error('not JSON'); },
    } as unknown as Response;

    const err = await parseGnapErrorResponse(response);
    expect(err.code).toBe('request_denied');
    expect(err.statusCode).toBe(500);
    expect(err.description).toBe('Internal Server Error');
  });
});
