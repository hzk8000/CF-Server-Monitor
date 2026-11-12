import { createRemoteJWKSet, jwtVerify } from 'jose';

const keySets = new Map();
const requestIdentities = new WeakMap();
const ACCESS_MODE = 'cloudflare-access';

// An invalid nonempty mode must fail closed rather than restore password login.
export function isAccessAuthEnabled(env) {
  return Boolean(env.AUTH_MODE && env.AUTH_MODE !== 'password');
}

function parseHostname(value) {
  const host = String(value || '').trim().toLowerCase();
  if (!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]+$/.test(host)) {
    throw new Error('Invalid Access hostname');
  }
  return host;
}

function readConfig(env) {
  if (env.AUTH_MODE !== ACCESS_MODE) throw new Error('Invalid authentication mode');

  const issuer = new URL(String(env.ACCESS_TEAM_DOMAIN || ''));
  if (issuer.protocol !== 'https:' || issuer.port || issuer.username || issuer.password ||
      issuer.search || issuer.hash || issuer.pathname !== '/' ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.cloudflareaccess\.com$/.test(issuer.hostname)) {
    throw new Error('Invalid Access team domain');
  }

  const audience = String(env.ACCESS_AUD || '').trim();
  if (!/^[a-f0-9]{64}$/.test(audience)) throw new Error('Invalid Access audience');

  const emails = new Set(String(env.ACCESS_ALLOWED_EMAILS || '')
    .split(',').map(email => email.trim().toLowerCase()).filter(Boolean));
  if (!emails.size || [...emails].some(email => !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    throw new Error('Access requires an explicit email allowlist');
  }

  const hostname = parseHostname(env.ACCESS_HOSTNAME);
  const reportHosts = new Set([hostname, ...String(env.AGENT_REPORT_HOSTNAMES || '')
    .split(',').map(host => host.trim()).filter(Boolean).map(parseHostname)]);
  return { issuer: issuer.origin, audience, emails, hostname, reportHosts };
}

async function verifyIdentity(request, env) {
  try {
    const config = readConfig(env);
    if (new URL(request.url).hostname !== config.hostname) return null;

    // Trust a verified assertion, never an email header or the old app session.
    const token = request.headers.get('Cf-Access-Jwt-Assertion');
    if (!token) return null;

    let keys = keySets.get(config.issuer);
    if (!keys) {
      keys = createRemoteJWKSet(new URL(`${config.issuer}/cdn-cgi/access/certs`), {
        timeoutDuration: 5000
      });
      keySets.set(config.issuer, keys);
    }

    const { payload } = await jwtVerify(token, keys, {
      algorithms: ['RS256'],
      issuer: config.issuer,
      audience: config.audience,
      requiredClaims: ['iss', 'aud', 'exp', 'iat', 'sub', 'email', 'type']
    });
    if (payload.type !== 'app' || typeof payload.sub !== 'string' || !payload.sub ||
        typeof payload.email !== 'string' ||
        !config.emails.has(payload.email.toLowerCase())) {
      return null;
    }
    return { email: payload.email, sub: payload.sub };
  } catch (_) {
    return null;
  }
}

export function getAccessIdentity(request, env) {
  if (!isAccessAuthEnabled(env)) return Promise.resolve(null);
  const cached = requestIdentities.get(request);
  if (cached?.env === env) return cached.identity;
  const identity = verifyIdentity(request, env);
  requestIdentities.set(request, { env, identity });
  return identity;
}

function deny(status, error) {
  return new Response(JSON.stringify({ error, code: status }), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
  });
}

// Run before routing, assets, OPTIONS or database work. The only machine exception
// is POST /update on explicitly configured hosts; its API_SECRET check still runs.
export async function guardAccessRequest(request, env) {
  if (!isAccessAuthEnabled(env)) return null;
  let config;
  try {
    config = readConfig(env);
  } catch (_) {
    return deny(503, 'Access authentication is not configured');
  }

  const url = new URL(request.url);
  if (config.reportHosts.has(url.hostname) && url.pathname === '/update' &&
      request.method === 'POST') {
    return null;
  }
  if (url.hostname !== config.hostname) return deny(403, 'Forbidden');

  const origin = request.headers.get('Origin');
  if (origin && origin !== `https://${config.hostname}`) return deny(403, 'Forbidden');
  if (!await getAccessIdentity(request, env)) return deny(403, 'Access authentication required');
  return null;
}
