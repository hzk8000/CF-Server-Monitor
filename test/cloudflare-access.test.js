import assert from 'node:assert/strict';
import test, { after } from 'node:test';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { Miniflare } from 'miniflare';
import worker from '../src/index.js';
import { checkAuth, checkWebSocketAuth, generateToken } from '../src/middleware/auth.js';
import { getAccessIdentity, guardAccessRequest } from '../src/middleware/cloudflareAccess.js';
import { handleAdminAPI } from '../src/handlers/admin.js';
import { serveFrontend } from '../src/handlers/frontend.js';
import { initDatabase } from '../src/database/schema.js';
import { clearSiteSettingsCache, clearAppearanceSettingsCache, saveSiteOptions } from '../src/utils/settings.js';

const issuer = 'https://monitor-test.cloudflareaccess.com';
const audience = 'a'.repeat(64);
const host = 'monitor.example.com';
const fallback = 'monitor.example.workers.dev';
const email = 'owner@example.com';
const { privateKey, publicKey } = await generateKeyPair('RS256');
const otherKeys = await generateKeyPair('RS256');
const publicJwk = { ...await exportJWK(publicKey), kid: 'test-key', alg: 'RS256', use: 'sig' };
const originalFetch = globalThis.fetch;

globalThis.fetch = async (input, init) => {
  const url = String(input);
  if (url.endsWith('.cloudflareaccess.com/cdn-cgi/access/certs')) {
    if (url.includes('unavailable.')) throw new Error('Simulated JWKS outage');
    return Response.json({ keys: [publicJwk] });
  }
  if (url === 'https://raw.githubusercontent.com/test-owner/test-theme/main/index.html') {
    return new Response('<html><head></head><body>Access theme preview</body></html>');
  }
  if (url.includes('github.com') || url.includes('githubusercontent.com')) {
    return new Response('{}', { headers: { 'Content-Type': 'application/json' } });
  }
  return originalFetch(input, init);
};
after(() => { globalThis.fetch = originalFetch; });

function env(overrides = {}) {
  return {
    AUTH_MODE: 'cloudflare-access',
    ACCESS_TEAM_DOMAIN: issuer,
    ACCESS_AUD: audience,
    ACCESS_ALLOWED_EMAILS: email,
    ACCESS_HOSTNAME: host,
    AGENT_REPORT_HOSTNAMES: fallback,
    API_SECRET: 'test-agent-secret',
    ...overrides
  };
}

async function sign(claims = {}, signingKey = privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: issuer, aud: [audience], email, sub: 'user-id', type: 'app',
    iat: now, exp: now + 3600, ...claims
  }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).sign(signingKey);
}

function request(path = '/', { token, hostname = host, headers = {}, body, method } = {}) {
  return new Request(`https://${hostname}${path}`, {
    method: method || (body ? 'POST' : 'GET'),
    headers: {
      ...(token ? { 'Cf-Access-Jwt-Assertion': token } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
      ...headers
    },
    body: body ? JSON.stringify(body) : undefined
  });
}

test('a signed Access application identity grants browser, API and WebSocket access', async () => {
  const token = await sign();
  const bindings = env();
  for (const path of ['/', '/admin', '/api/servers', '/admin/api', '/api/ws']) {
    const req = request(path, { token });
    assert.equal(await guardAccessRequest(req, bindings), null);
    assert.equal(await checkAuth(req, bindings, {}), true);
    assert.equal(await checkWebSocketAuth(req, bindings, {}), true);
    assert.deepEqual(await getAccessIdentity(req, bindings), { email, sub: 'user-id' });
  }
});

test('invalid signatures, token claims and identities are rejected', async () => {
  const cases = [
    ['signature', await sign({}, otherKeys.privateKey)],
    ['audience', await sign({ aud: ['b'.repeat(64)] })],
    ['issuer', await sign({ iss: 'https://other.cloudflareaccess.com' })],
    ['expiry', await sign({ exp: Math.floor(Date.now() / 1000) - 10 })],
    ['future token', await sign({ nbf: Math.floor(Date.now() / 1000) + 3600 })],
    ['missing expiry', await sign({ exp: undefined })],
    ['missing identity', await sign({ sub: undefined })],
    ['missing email', await sign({ email: undefined })],
    ['service token', await sign({ type: 'service' })],
    ['another user', await sign({ email: 'other@example.com' })],
    ['malformed', 'not-a-jwt'],
    ['unsigned', 'eyJhbGciOiJub25lIn0.e30.']
  ];
  for (const [name, token] of cases) {
    const req = request('/admin/api', { token });
    assert.equal((await guardAccessRequest(req, env())).status, 403, name);
    assert.equal(await checkAuth(req, env(), { is_public: 'true' }), false, name);
  }
});

test('email headers, Access cookies and legacy sessions cannot replace a verified assertion', async () => {
  const legacyEnv = { API_SECRET: 'legacy-secret' };
  const sys = { jwt_secret: 'test-jwt-secret'.padEnd(32, 'x') };
  const token = await generateToken(legacyEnv, sys);
  const req = request(`/api/ws?token=${token}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Cookie: `cfsm_auth=${token}; CF_Authorization=${await sign()}`,
      'Cf-Access-Authenticated-User-Email': email
    }
  });
  assert.equal((await guardAccessRequest(req, env())).status, 403);
  assert.equal(await checkAuth(req, env(), sys), false);
  assert.equal(await checkWebSocketAuth(req, env(), sys), false);
});

test('all anonymous browser routes are blocked before assets and database work', async () => {
  for (const path of ['/', '/admin', '/admin/api', '/api/config', '/api/servers',
    '/api/history/all?id=server-1', '/api/ws', '/assets/app.js', '/theme', '/__do/health']) {
    const response = await worker.fetch(request(path), env(), {});
    assert.equal(response.status, 403, path);
    assert.equal(response.headers.get('Cache-Control'), 'no-store');
  }
});

test('the backup host exposes only POST /update and still checks the agent secret', async () => {
  const token = await sign();
  for (const hostname of [host, fallback]) {
    const req = request('/update', { hostname, body: { secret: 'wrong-secret' } });
    assert.equal(await guardAccessRequest(req, env()), null);
    assert.equal((await worker.fetch(req, env(), {})).status, 401);
  }
  for (const path of ['/', '/admin', '/api/config', '/api/servers', '/api/ws', '/__do/health', '/assets/app.js']) {
    assert.equal((await guardAccessRequest(request(path, { hostname: fallback, token }), env())).status, 403);
  }
  for (const [hostname, method, path] of [
    [fallback, 'GET', '/update'],
    [fallback, 'OPTIONS', '/update'],
    [fallback, 'POST', '/update/'],
    [fallback, 'POST', '/update%2fanything'],
    ['other.example.com', 'POST', '/update']
  ]) {
    assert.equal((await guardAccessRequest(request(path, { hostname, method }), env())).status, 403);
  }
});

test('missing or invalid Access configuration fails closed without a password fallback', async () => {
  for (const overrides of [
    { AUTH_MODE: 'cloudflare_access' },
    { ACCESS_AUD: '' },
    { ACCESS_ALLOWED_EMAILS: '' },
    { ACCESS_ALLOWED_EMAILS: '*' },
    { ACCESS_TEAM_DOMAIN: 'http://team.cloudflareaccess.com' },
    { ACCESS_TEAM_DOMAIN: 'https://attacker.example.com' },
    { ACCESS_TEAM_DOMAIN: `${issuer}/unexpected` },
    { ACCESS_HOSTNAME: '*' }
  ]) {
    assert.equal((await guardAccessRequest(request('/'), env(overrides))).status, 503);
  }
});

test('cross-origin browser requests and WebSocket handshakes are rejected', async () => {
  const token = await sign();
  for (const path of ['/admin/api', '/api/ws']) {
    assert.equal((await guardAccessRequest(request(path, {
      token, headers: { Origin: 'https://other.example.com' }
    }), env())).status, 403);
    assert.equal(await guardAccessRequest(request(path, {
      token, headers: { Origin: `https://${host}` }
    }), env()), null);
  }
});

test('a signing-key endpoint outage denies access', async () => {
  const unavailableIssuer = 'https://unavailable.cloudflareaccess.com';
  const token = await sign({ iss: unavailableIssuer });
  assert.equal((await guardAccessRequest(request('/', { token }), env({
    ACCESS_TEAM_DOMAIN: unavailableIssuer
  }))).status, 403);
});

test('password login cannot issue a new local session in Access mode', async () => {
  const response = await handleAdminAPI(request('/admin/api', {
    token: await sign(),
    body: { action: 'login', username: 'admin', password: 'anything' }
  }), env(), {});
  assert.equal(response.status, 403);
  assert.equal(response.headers.get('Set-Cookie'), null);
});

test('the admin API recognizes the Access identity without a local password', async () => {
  const response = await handleAdminAPI(request('/admin/api', {
    token: await sign(), body: { action: 'get_settings' }
  }), env(), {
    is_public: 'true', turnstile_enabled: 'true', turnstile_login_enabled: 'true',
    password: 'legacy-password-hash'
  });
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.settings.auth_mode, 'cloudflare-access');
  assert.equal(data.settings.access_email, email);
  assert.equal(data.settings.password_configured, false);
  assert.equal(data.settings.is_public, 'false');
  assert.equal(data.settings.turnstile_enabled, 'false');
  assert.equal(data.settings.turnstile_login_enabled, 'false');
});

test('theme preview uses the Access identity without a legacy preview cookie', async () => {
  const path = `/?theme_url=${encodeURIComponent('https://github.com/test-owner/test-theme/tree/main')}`;
  const response = await serveFrontend(request(path, { token: await sign() }), env(), {});
  assert.equal(response.status, 200);
  assert.match(await response.text(), /Access theme preview/);
  const anonymous = await serveFrontend(request(path), env(), {});
  assert.equal(anonymous.status, 401);
});

test('Access-managed settings stay private and do not restore local authentication', async () => {
  const rows = new Map([['site_options', JSON.stringify({})]]);
  const db = {
    prepare(sql) {
      const statement = {
        params: [],
        bind(...params) { statement.params = params; return statement; },
        async first() { return { value: rows.get('site_options') }; },
        async all() { return { results: [] }; },
        async run() {
          if (/INSERT INTO settings/.test(sql)) rows.set(statement.params[0], statement.params[1]);
          return { success: true };
        }
      };
      return statement;
    }
  };
  const response = await handleAdminAPI(request('/admin/api', {
    token: await sign(),
    body: { action: 'save_settings', settings: {
      is_public: 'true', username: 'new-admin', password: 'new-password',
      jwt_secret: 'new-local-secret'.padEnd(32, 'x'), turnstile_login_enabled: 'true'
    } }
  }), env({ DB: db }), { tg_notify: '0', expire_reminder: '0' });
  assert.equal(response.status, 200, await response.text());
  const saved = JSON.parse(rows.get('site_options'));
  assert.equal(saved.is_public, 'false');
  assert.equal(saved.turnstile_login_enabled, 'false');
  for (const name of ['username', 'password', 'jwt_secret']) assert.equal(Object.hasOwn(saved, name), false);
});

test('the existing password deployment remains usable before Access activation', async () => {
  const bindings = { AUTH_MODE: 'password', API_SECRET: 'legacy-agent-secret' };
  const sys = { jwt_secret: 'legacy-jwt-secret'.padEnd(32, 'x') };
  const token = await generateToken(bindings, sys);
  const req = request('/admin/api', { headers: { Authorization: `Bearer ${token}` } });
  assert.equal(await guardAccessRequest(req, bindings), null);
  assert.equal(await checkAuth(req, bindings, sys), true);
  assert.equal(await checkWebSocketAuth(req, bindings, sys), true);
});

test('legacy public and Turnstile settings cannot add a second login in Access mode', async () => {
  const miniflare = new Miniflare({
    modules: true, script: 'export default { fetch() { return new Response("ok"); } };',
    compatibilityDate: '2024-12-01', d1Databases: ['DB']
  });
  clearSiteSettingsCache();
  clearAppearanceSettingsCache();
  try {
    const db = await miniflare.getD1Database('DB');
    await initDatabase(db);
    await saveSiteOptions(db, {
      is_public: 'true', turnstile_enabled: 'true', turnstile_login_enabled: 'true'
    });
    const bindings = env({ DB: db });
    const response = await worker.fetch(request('/api/config', { token: await sign() }), bindings, {});
    assert.equal(response.status, 200);
    const config = await response.json();
    assert.equal(config.auth_mode, 'cloudflare-access');
    assert.equal(config.authorization, true);
    assert.equal(config.is_public, false);
    assert.equal(config.turnstile_enabled, false);
    assert.equal(config.turnstile_login_enabled, false);
    const apiResponse = await worker.fetch(request('/api/history/all', { token: await sign() }), bindings, {});
    assert.equal(apiResponse.status, 400);
    assert.doesNotMatch(await apiResponse.text(), /Turnstile/);
  } finally {
    clearSiteSettingsCache();
    clearAppearanceSettingsCache();
    await miniflare.dispose();
  }
});
