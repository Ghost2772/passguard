import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ApiClient, ApiError } from '../src/api.ts';

test('mutations use scoped cookies and the current in-memory CSRF token', async () => {
  const calls: RequestInit[] = [];
  const client = new ApiClient(async (_url, options) => { calls.push(options!); return new Response('{}', { status: 200 }); });
  client.csrf = 'synthetic-csrf';
  await client.request('/secrets');
  await client.request('/checks/demo', { method: 'POST' });
  assert.equal(new Headers(calls[0].headers).has('X-CSRF-Token'), false);
  assert.equal(new Headers(calls[1].headers).get('X-CSRF-Token'), 'synthetic-csrf');
  assert.equal(calls[1].credentials, 'same-origin');
  assert.equal(calls[1].cache, 'no-store');
  assert.equal(new Headers(calls[1].headers).has('Authorization'), false);
});

test('ZIP uploads stay binary and are not JSON-encoded', async () => {
  const archive = new Blob([new Uint8Array([0x50, 0x4b, 0, 255])]);
  const client = new ApiClient(async (_url, options) => {
    assert.equal(options!.body, archive);
    assert.equal(new Headers(options!.headers).get('Content-Type'), 'application/zip');
    return new Response('{}', { status: 201 });
  });
  await client.request('/scans', { method: 'POST', body: archive });
});

test('expired-session responses clear UI auth but bad login does not trigger that callback', async () => {
  let expired = 0;
  const client = new ApiClient(async () => new Response('{"detail":"Требуется вход","code":"authentication_required"}', { status: 401 }));
  client.onUnauthorized = () => { expired++; client.setSession(null); };
  client.csrf = 'synthetic-csrf';
  await assert.rejects(client.request('/scans'), ApiError);
  assert.equal(expired, 1); assert.equal(client.csrf, '');
  await assert.rejects(client.request('/auth/login', { method: 'POST', silent401: true }), ApiError);
  assert.equal(expired, 1);
});

test('validation errors never display request inputs from a provider response', async () => {
  const client = new ApiClient(async () => new Response(JSON.stringify({ detail: [{ msg: 'input rejected', input: 'synthetic-sensitive-value' }] }), { status: 422 }));
  await assert.rejects(client.request('/users'), error => error instanceof ApiError && !error.message.includes('synthetic-sensitive-value'));
});

test('a non-JSON proxy failure is not treated as an operation success', async () => {
  const client = new ApiClient(async () => new Response('<html>upstream unavailable</html>', { status: 502 }));
  await assert.rejects(client.request('/secrets/demo-db/rotate', { method: 'POST' }), error => error instanceof ApiError && error.code === 'invalid_response');
});
