import assert from 'node:assert/strict';
import { createMuseLinkTokenLifecycle } from './muse-token-lifecycle.mjs';

function response(status, body = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

async function testPreExpiryRefreshAndRotation() {
  let now = 1_000_000;
  let state = { access_token: 'old-a', refresh_token: 'old-r', token_type: 'Bearer', expires_at_ms: now + 4 * 60_000 };
  let refreshCalls = 0;
  let apiBearer = null;
  const lifecycle = createMuseLinkTokenLifecycle({
    loadState: async () => ({ ...state }),
    saveState: async next => { state = { ...next }; },
    now: () => now,
    fetchImpl: async (url, init) => {
      if (String(url).endsWith('/oauth/token')) {
        refreshCalls++;
        const form = new URLSearchParams(init.body);
        assert.equal(form.get('grant_type'), 'refresh_token');
        assert.equal(form.get('refresh_token'), 'old-r');
        return response(200, { access_token: 'new-a', refresh_token: 'new-r', token_type: 'Bearer', expires_in: 28800, scope: 'link.observe link.act' });
      }
      apiBearer = new Headers(init.headers).get('authorization');
      return response(200, { ok: true });
    },
  });
  const r = await lifecycle.authorizedFetch('https://example.invalid/link/mcp', { method: 'POST', body: '{}' });
  assert.equal(r.status, 200);
  assert.equal(refreshCalls, 1);
  assert.equal(apiBearer, 'Bearer new-a');
  assert.equal(state.refresh_token, 'new-r');
  assert.equal(state.expires_at_ms, now + 28800 * 1000);
}

async function test401RefreshRetry() {
  let now = 2_000_000;
  let state = { access_token: 'old-a', refresh_token: 'old-r', token_type: 'Bearer' };
  let apiCalls = 0;
  let refreshCalls = 0;
  const lifecycle = createMuseLinkTokenLifecycle({
    loadState: async () => ({ ...state }),
    saveState: async next => { state = { ...next }; },
    now: () => now,
    fetchImpl: async (url, init) => {
      if (String(url).endsWith('/oauth/token')) {
        refreshCalls++;
        return response(200, { access_token: 'new-a', refresh_token: 'new-r', token_type: 'Bearer', expires_in: 28800 });
      }
      apiCalls++;
      const bearer = new Headers(init.headers).get('authorization');
      if (apiCalls === 1) { assert.equal(bearer, 'Bearer old-a'); return response(401, { error: 'authentication_required' }); }
      assert.equal(bearer, 'Bearer new-a');
      return response(200, { ok: true });
    },
  });
  const r = await lifecycle.authorizedFetch('https://example.invalid/link/mcp', { method: 'POST', body: '{}' });
  assert.equal(r.status, 200);
  assert.equal(apiCalls, 2);
  assert.equal(refreshCalls, 1);
}

async function testConcurrentRefreshIsSingleFlight() {
  let now = 3_000_000;
  let state = { access_token: 'old-a', refresh_token: 'old-r', token_type: 'Bearer', expires_at_ms: now + 1 };
  let refreshCalls = 0;
  const lifecycle = createMuseLinkTokenLifecycle({
    loadState: async () => ({ ...state }),
    saveState: async next => { state = { ...next }; },
    now: () => now,
    fetchImpl: async url => {
      assert.ok(String(url).endsWith('/oauth/token'));
      refreshCalls++;
      await new Promise(r => setTimeout(r, 20));
      return response(200, { access_token: 'new-a', refresh_token: 'new-r', token_type: 'Bearer', expires_in: 28800 });
    },
  });
  await Promise.all(Array.from({ length: 8 }, () => lifecycle.ensureFreshAccessToken()));
  assert.equal(refreshCalls, 1);
}

async function testFailedRefreshDoesNotOverwriteState() {
  let now = 4_000_000;
  const initial = { access_token: 'old-a', refresh_token: 'old-r', token_type: 'Bearer', expires_at_ms: now + 1 };
  let state = { ...initial };
  let saves = 0;
  const lifecycle = createMuseLinkTokenLifecycle({
    loadState: async () => ({ ...state }),
    saveState: async next => { saves++; state = { ...next }; },
    now: () => now,
    fetchImpl: async () => response(500, { error: 'server_error' }),
  });
  await assert.rejects(() => lifecycle.ensureFreshAccessToken(), /HTTP 500/);
  assert.equal(saves, 0);
  assert.deepEqual(state, initial);
}

async function testAdoptTokenResponseSeedsExpiry() {
  let now = 5_000_000;
  let state = { access_token: 'legacy-a', refresh_token: 'legacy-r' };
  const lifecycle = createMuseLinkTokenLifecycle({
    loadState: async () => ({ ...state }),
    saveState: async next => { state = { ...next }; },
    now: () => now,
    fetchImpl: async () => { throw new Error('not used'); },
  });
  await lifecycle.adoptTokenResponse({ access_token: 'fresh-a', refresh_token: 'fresh-r', expires_in: 28800, token_type: 'Bearer', scope: 'link.observe link.act' });
  assert.equal(state.expires_at_ms, now + 28800 * 1000);
  assert.equal(state.refresh_token, 'fresh-r');
}

await testPreExpiryRefreshAndRotation();
await test401RefreshRetry();
await testConcurrentRefreshIsSingleFlight();
await testFailedRefreshDoesNotOverwriteState();
await testAdoptTokenResponseSeedsExpiry();
console.log('muse-token-lifecycle: 5/5 passed');
