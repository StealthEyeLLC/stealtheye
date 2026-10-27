export const MUSE_LINK_OAUTH_DEFAULTS = Object.freeze({
  tokenEndpoint: 'https://stealtheye-connection.tailcfe213.ts.net:8443/oauth/token',
  clientId: 'https://raw.githubusercontent.com/StealthEyeLLC/stealtheye/muse-cimd-20261025/oauth/muse-client.json',
  resource: 'https://stealtheye-connection.tailcfe213.ts.net:8443/link/mcp',
  scope: 'link.observe link.act',
});

const DEFAULT_REFRESH_SKEW_MS = 5 * 60 * 1000;

export class LinkOAuthRefreshError extends Error {
  constructor(message, cause) {
    super(message, { cause });
    this.name = 'LinkOAuthRefreshError';
  }
}

function requireFn(value, name) {
  if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  return value;
}

function copyHeaders(input) {
  return new Headers(input || {});
}

function replayableBody(body) {
  if (body == null || typeof body === 'string' || body instanceof URLSearchParams || body instanceof ArrayBuffer || ArrayBuffer.isView(body)) return true;
  if (typeof Blob !== 'undefined' && body instanceof Blob) return true;
  return false;
}

function normalizeState(state) {
  if (!state || typeof state !== 'object') throw new LinkOAuthRefreshError('LINK OAuth state is missing');
  if (typeof state.access_token !== 'string' || !state.access_token) throw new LinkOAuthRefreshError('LINK access token is missing');
  if (typeof state.refresh_token !== 'string' || !state.refresh_token) throw new LinkOAuthRefreshError('LINK refresh token is missing');
  return { ...state };
}

function normalizeTokenResponse(body, issuedAtMs, previousState) {
  if (!body || typeof body !== 'object') throw new LinkOAuthRefreshError('LINK token endpoint returned an invalid response');
  if (typeof body.access_token !== 'string' || !body.access_token) throw new LinkOAuthRefreshError('LINK token response omitted access_token');
  if (typeof body.refresh_token !== 'string' || !body.refresh_token) throw new LinkOAuthRefreshError('LINK token response omitted rotated refresh_token');
  const expiresIn = Number(body.expires_in);
  if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw new LinkOAuthRefreshError('LINK token response omitted a valid expires_in');
  return {
    ...previousState,
    access_token: body.access_token,
    refresh_token: body.refresh_token,
    token_type: typeof body.token_type === 'string' && body.token_type ? body.token_type : 'Bearer',
    scope: typeof body.scope === 'string' && body.scope ? body.scope : previousState.scope,
    issued_at_ms: issuedAtMs,
    expires_in: expiresIn,
    expires_at_ms: issuedAtMs + expiresIn * 1000,
  };
}

export function createMuseLinkTokenLifecycle(options) {
  const cfg = { ...MUSE_LINK_OAUTH_DEFAULTS, ...options };
  const loadState = requireFn(cfg.loadState, 'loadState');
  const saveState = requireFn(cfg.saveState, 'saveState');
  const fetchImpl = requireFn(cfg.fetchImpl || globalThis.fetch, 'fetchImpl');
  const now = requireFn(cfg.now || Date.now, 'now');
  const emit = typeof cfg.onEvent === 'function' ? cfg.onEvent : () => {};
  const refreshSkewMs = Number.isFinite(cfg.refreshSkewMs) ? Math.max(0, cfg.refreshSkewMs) : DEFAULT_REFRESH_SKEW_MS;
  let inFlightRefresh = null;

  function safeEvent(event, fields = {}) {
    // Never include access_token, refresh_token, Authorization, or response bodies.
    emit({ event, at_ms: now(), ...fields });
  }

  async function refreshNow(reason = 'forced') {
    if (inFlightRefresh) return inFlightRefresh;
    inFlightRefresh = (async () => {
      const before = normalizeState(await loadState());
      safeEvent('link_oauth_refresh_start', {
        reason,
        previous_expires_at_ms: Number.isFinite(Number(before.expires_at_ms)) ? Number(before.expires_at_ms) : null,
      });
      const form = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: before.refresh_token,
        client_id: cfg.clientId,
        resource: cfg.resource,
      });
      let response;
      try {
        response = await fetchImpl(cfg.tokenEndpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
          body: form.toString(),
        });
      } catch (error) {
        safeEvent('link_oauth_refresh_failed', { reason, stage: 'transport' });
        throw new LinkOAuthRefreshError('LINK token refresh transport failed', error);
      }
      if (!response.ok) {
        safeEvent('link_oauth_refresh_failed', { reason, stage: 'http', status: response.status });
        throw new LinkOAuthRefreshError(`LINK token refresh failed with HTTP ${response.status}`);
      }
      let body;
      try {
        body = await response.json();
      } catch (error) {
        safeEvent('link_oauth_refresh_failed', { reason, stage: 'decode' });
        throw new LinkOAuthRefreshError('LINK token refresh response was not valid JSON', error);
      }
      const issuedAtMs = now();
      const after = normalizeTokenResponse(body, issuedAtMs, before);
      // One atomic caller-provided save replaces access + rotated refresh token together.
      await saveState(after);
      safeEvent('link_oauth_refresh_success', {
        reason,
        issued_at_ms: after.issued_at_ms,
        expires_at_ms: after.expires_at_ms,
        refresh_ahead_ms: refreshSkewMs,
      });
      return after;
    })();
    try {
      return await inFlightRefresh;
    } finally {
      inFlightRefresh = null;
    }
  }

  async function ensureFreshAccessToken() {
    const state = normalizeState(await loadState());
    const expiresAtMs = Number(state.expires_at_ms);
    if (!Number.isFinite(expiresAtMs)) {
      // Legacy state may not contain expiry metadata. Do not rotate a credential just to infer it.
      // The 401 recovery path remains active. The next normal token response should be adopted
      // so future requests refresh ahead of expiry.
      safeEvent('link_oauth_expiry_unknown');
      return state;
    }
    if (expiresAtMs - now() <= refreshSkewMs) return refreshNow('pre_expiry');
    return state;
  }

  async function adoptTokenResponse(tokenResponse) {
    const before = await loadState().catch(() => ({}));
    const issuedAtMs = now();
    const after = normalizeTokenResponse(tokenResponse, issuedAtMs, before || {});
    await saveState(after);
    safeEvent('link_oauth_token_adopted', {
      issued_at_ms: after.issued_at_ms,
      expires_at_ms: after.expires_at_ms,
      refresh_ahead_ms: refreshSkewMs,
    });
    return after;
  }

  async function authorizedFetch(url, init = {}) {
    if (!replayableBody(init.body)) {
      throw new TypeError('authorizedFetch requires a replayable body so a 401 can be retried safely');
    }
    let state = await ensureFreshAccessToken();
    const firstHeaders = copyHeaders(init.headers);
    firstHeaders.set('authorization', `${state.token_type || 'Bearer'} ${state.access_token}`);
    let response = await fetchImpl(url, { ...init, headers: firstHeaders });
    if (response.status !== 401) return response;

    safeEvent('link_oauth_401_recovery_start');
    state = await refreshNow('401_authentication_required');
    const retryHeaders = copyHeaders(init.headers);
    retryHeaders.set('authorization', `${state.token_type || 'Bearer'} ${state.access_token}`);
    response = await fetchImpl(url, { ...init, headers: retryHeaders });
    safeEvent('link_oauth_401_recovery_result', { status: response.status });
    return response;
  }

  return Object.freeze({
    adoptTokenResponse,
    ensureFreshAccessToken,
    refreshNow,
    authorizedFetch,
    get refreshSkewMs() { return refreshSkewMs; },
  });
}
