import express from 'express';
import { createOAuthMetadata, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { InvalidClientMetadataError, InvalidGrantError, InvalidRequestError, InvalidScopeError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { hashToken } from './oauth-store.mjs';
import { accountRequest } from './account-api.mjs';

export const SCOPES = ['countervault:read', 'countervault:write'];
const callbackHosts = new Set(['chatgpt.com', 'platform.openai.com', 'claude.ai', 'console.anthropic.com']);
export function validRedirect(value, allowLoopback = false) {
  try {
    const u = new URL(value);
    return !u.username && !u.password && !u.hash && ((u.protocol === 'https:' && !u.port && callbackHosts.has(u.hostname))
      || (allowLoopback && u.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname)));
  } catch { return false; }
}

export class CountervaultOAuth {
  constructor(store, { origin = 'https://countervault-mcp-production.up.railway.app', appOrigin = 'https://countervault.co', allowLoopback = false, requestAccount = accountRequest, reviewer } = {}) {
    this.store = store;
    this.issuer = new URL(origin).href;
    this.resource = new URL('/mcp', origin).href;
    this.appOrigin = appOrigin;
    this.requestAccount = requestAccount;
    this.reviewer = reviewer;
    this.clientsStore = {
      getClient: id => store.client(id),
      registerClient: async metadata => {
        if (metadata.token_endpoint_auth_method !== 'none') throw new InvalidClientMetadataError('Use public-client authentication with PKCE (token_endpoint_auth_method none).');
        if (!metadata.redirect_uris?.length || metadata.redirect_uris.length > 5 || !metadata.redirect_uris.every(v => validRedirect(v, allowLoopback))) throw new InvalidClientMetadataError('Only registered assistant HTTPS callback hosts are supported.');
        const client = { ...metadata, client_id: metadata.client_id || randomUUID(), client_id_issued_at: Math.floor(Date.now() / 1000),
          client_name: String(metadata.client_name || 'AI assistant').slice(0, 100), client_secret: undefined, client_secret_expires_at: undefined,
          grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] };
        return store.register(client);
      },
    };
  }
  validateResource(resource) { if (resource?.href !== this.resource) throw new InvalidRequestError('The resource must exactly match this Countervault MCP endpoint.'); }
  validateScopes(scopes = ['countervault:read']) {
    if (!scopes.length || scopes.some(s => !SCOPES.includes(s))) throw new InvalidScopeError('Unsupported Countervault scope.');
    return [...new Set(scopes)];
  }
  async authorize(client, params, res) {
    this.validateResource(params.resource);
    const scopes = this.validateScopes(params.scopes?.length ? params.scopes : ['countervault:read']);
    if (!params.codeChallenge || !/^[A-Za-z0-9_-]{43}$/.test(params.codeChallenge)) throw new InvalidRequestError('PKCE S256 is required.');
    const id = await this.store.newRequest(client.client_id, { ...params, scopes, resource: this.resource });
    const url = new URL(this.appOrigin);
    url.searchParams.set('mcp_request', id);
    res.redirect(url.href);
  }
  async challengeForAuthorizationCode(client, code) {
    const row = (await this.store.q(`SELECT challenge FROM ${this.store.schema}.codes WHERE code_hash=$1 AND client_id=$2 AND expires_at>now() AND used_at IS NULL`, [hashToken(code), client.client_id])).rows[0];
    if (!row) throw new InvalidGrantError('Authorization code expired or already used.');
    return row.challenge;
  }
  async exchangeAuthorizationCode(client, code, _verifier, redirectUri, resource) {
    this.validateResource(resource);
    return this.store.transaction(async db => {
      const row = (await db.query(`SELECT c.*,g.scopes,g.expires_at AS grant_expires_at,g.revoked_at FROM ${this.store.schema}.codes c JOIN ${this.store.schema}.grants g ON g.id=c.grant_id WHERE c.code_hash=$1 FOR UPDATE OF c`, [hashToken(code)])).rows[0];
      if (!row || row.client_id !== client.client_id || row.used_at || new Date(row.expires_at) <= new Date() || row.redirect_uri !== redirectUri || row.resource !== this.resource || row.revoked_at || new Date(row.grant_expires_at) <= new Date()) throw new InvalidGrantError('Authorization code does not match this client, redirect, resource or lifetime.');
      await db.query(`UPDATE ${this.store.schema}.codes SET used_at=now() WHERE code_hash=$1`, [hashToken(code)]);
      return this.store.issueTokens(db, { id: row.grant_id, client_id: row.client_id, scopes: row.scopes, resource: row.resource, expires_at: row.grant_expires_at });
    });
  }
  async exchangeRefreshToken(client, refresh, requestedScopes, resource) {
    this.validateResource(resource);
    // A replay revokes the whole connection. Commit that revocation before
    // returning an OAuth error, rather than rolling it back with the exchange.
    const result = await this.store.transaction(async db => {
      const row = (await db.query(`SELECT t.*,g.expires_at AS grant_expires_at,g.revoked_at AS grant_revoked FROM ${this.store.schema}.tokens t JOIN ${this.store.schema}.grants g ON g.id=t.grant_id WHERE token_hash=$1 AND kind='refresh' FOR UPDATE OF t,g`, [hashToken(refresh)])).rows[0];
      if (!row || row.client_id !== client.client_id) return { invalid: true };
      if (row.used_at) { await this.store.revoke(row.grant_id, db); return { replay: true }; }
      if (row.revoked_at || row.grant_revoked || new Date(row.expires_at) <= new Date() || new Date(row.grant_expires_at) <= new Date() || row.resource !== this.resource) return { invalid: true };
      const scopes = requestedScopes ? this.validateScopes(requestedScopes) : row.scopes;
      if (scopes.some(s => !row.scopes.includes(s))) return { invalid: true };
      await db.query(`UPDATE ${this.store.schema}.tokens SET used_at=now() WHERE token_hash=$1`, [hashToken(refresh)]);
      return this.store.issueTokens(db, { id: row.grant_id, client_id: row.client_id, resource: row.resource, scopes, expires_at: row.grant_expires_at });
    });
    if (result.invalid || result.replay) throw new InvalidGrantError(result.replay ? 'Refresh token replay detected. Reconnect Countervault.' : 'Refresh token expired or invalid.');
    return result;
  }
  async verifyAccessToken(token) {
    const row = await this.store.resolveAccess(token);
    if (!row || row.resource !== this.resource) throw new InvalidTokenError('Countervault access token expired or revoked.');
    return { token, clientId: row.client_id, scopes: row.scopes, resource: new URL(row.resource), expiresAt: new Date(row.expires_at).getTime() / 1000,
      extra: { grantId: row.grant_id, accountId: row.account_id, userId: row.user_id } };
  }
  async backendSession(auth) {
    const row = await this.store.resolveAccess(auth.token);
    if (!row || row.grant_id !== auth.extra?.grantId) throw new InvalidTokenError('Connection expired or revoked.');
    return this.store.box.decrypt(row.encrypted_session);
  }
  async revokeToken(client, { token }) {
    await this.store.transaction(async db => {
      const row = (await db.query(`SELECT grant_id FROM ${this.store.schema}.tokens WHERE token_hash=$1 AND client_id=$2`, [hashToken(token), client.client_id])).rows[0];
      if (row) await this.store.revoke(row.grant_id, db);
    });
  }
}

export function installOAuth(app, provider) {
  const metadata = createOAuthMetadata({ provider, issuerUrl: new URL(provider.issuer), scopesSupported: SCOPES });
  metadata.token_endpoint_auth_methods_supported = ['none'];
  metadata.authorization_response_iss_parameter_supported = true;
  // The SDK also redirects OAuth errors after validating the client callback.
  // Include issuer identification on those responses as advertised above.
  app.use('/authorize', (_req, res, next) => {
    const original = res.redirect.bind(res);
    res.redirect = function (statusOrUrl, maybeUrl) {
      const value = typeof statusOrUrl === 'string' ? statusOrUrl : maybeUrl;
      const url = new URL(value);
      if (url.searchParams.has('error') || url.searchParams.has('code')) url.searchParams.set('iss', provider.issuer);
      return typeof statusOrUrl === 'string' ? original(url.href) : original(statusOrUrl, url.href);
    };
    next();
  });
  app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json(metadata));
  const protectedMetadata = { resource: provider.resource, authorization_servers: [provider.issuer], scopes_supported: SCOPES, resource_name: 'Countervault', resource_documentation: 'https://countervault.co' };
  app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json(protectedMetadata));
  app.use(mcpAuthRouter({ provider, issuerUrl: new URL(provider.issuer), resourceServerUrl: new URL(provider.resource), scopesSupported: SCOPES, resourceName: 'Countervault' }));

  const ui = express.Router();
  ui.use((req, res, next) => {
    if (req.headers.origin !== provider.appOrigin) return res.status(403).json({ error: 'Open this connection from Countervault.' });
    res.set('Access-Control-Allow-Origin', provider.appOrigin).set('Vary', 'Origin');
    res.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    res.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });
  ui.use(express.json({ limit: '8kb' }));
  const route = (method, path, run) => ui[method](path, (req, res, next) => run(req, res).catch(next));
  const identity = async req => {
    const token = /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization || '')?.[1];
    if (!token) throw Object.assign(new Error('Sign in to Countervault first.'), { status: 401 });
    const info = await provider.requestAccount(token, '/api/auth/session');
    if (!info.user?.id || !info.account?.id || info.auth_mode !== 'passwordless') throw Object.assign(new Error('A signed-in Countervault account is required.'), { status: 401 });
    return info;
  };
  const reviewAttempts = new Map();
  route('post', '/reviewer-session', async (req, res) => {
    if (!provider.reviewer?.secret || !provider.reviewer.userId || !provider.reviewer.accountId) return res.status(404).json({ error: 'Directory review access is not enabled.' });
    const now = Date.now();
    for (const [key, value] of reviewAttempts) if (now - value.start > 60000) reviewAttempts.delete(key);
    const ip = req.socket.remoteAddress;
    const attempt = reviewAttempts.get(ip) || { start: now, count: 0 };
    if (++attempt.count > 6 || reviewAttempts.size > 10000) return res.status(429).json({ error: 'Please wait one minute before trying reviewer access again.' });
    reviewAttempts.set(ip, attempt);
    const provided = Buffer.from(hashToken(String(req.body?.access_code || '').slice(0, 200)), 'hex');
    const expected = Buffer.from(hashToken(provider.reviewer.secret), 'hex');
    if (!timingSafeEqual(provided, expected)) return res.status(401).json({ error: 'Invalid reviewer access code.' });
    res.json(await provider.store.reviewerSession(provider.reviewer.userId, provider.reviewer.accountId));
  });
  route('get', '/requests/:id', async (req, res) => {
    const row = await provider.store.pending(String(req.params.id));
    if (!row) return res.status(404).json({ error: 'This connection request expired. Start again from your assistant.' });
    res.json({ client_name: row.client.client_name, redirect_origin: new URL(row.params.redirectUri).origin, scopes: row.params.scopes, expires_at: row.expires_at });
  });
  route('post', '/requests/:id/approve', async (req, res) => {
    const user = await identity(req);
    const { code, params } = await provider.store.approve(String(req.params.id), user);
    const redirect = new URL(params.redirectUri);
    redirect.searchParams.set('code', code); redirect.searchParams.set('iss', provider.issuer);
    if (params.state) redirect.searchParams.set('state', params.state);
    res.json({ redirect_url: redirect.href });
  });
  route('post', '/requests/:id/deny', async (req, res) => {
    await identity(req);
    const row = (await provider.store.q(`DELETE FROM ${provider.store.schema}.requests WHERE id=$1 RETURNING params`, [String(req.params.id)])).rows[0];
    if (!row) return res.status(404).json({ error: 'Connection request expired.' });
    const redirect = new URL(row.params.redirectUri);
    redirect.searchParams.set('error', 'access_denied'); redirect.searchParams.set('iss', provider.issuer);
    if (row.params.state) redirect.searchParams.set('state', row.params.state);
    res.json({ redirect_url: redirect.href });
  });
  route('get', '/connections', async (req, res) => {
    const user = await identity(req);
    const rows = (await provider.store.q(`SELECT g.id,c.metadata->>'client_name' AS client_name,g.scopes,g.created_at,g.expires_at FROM ${provider.store.schema}.grants g JOIN ${provider.store.schema}.clients c USING(client_id) WHERE g.user_id=$1 AND g.account_id=$2 AND g.revoked_at IS NULL AND g.expires_at>now() ORDER BY g.created_at DESC`, [user.user.id, user.account.id])).rows;
    res.json({ connections: rows });
  });
  route('post', '/connections/:id/revoke', async (req, res) => {
    const user = await identity(req);
    if (!/^[a-f0-9-]{36}$/.test(String(req.params.id))) return res.status(400).json({ error: 'Invalid connection.' });
    await provider.store.transaction(async db => {
      const row = (await db.query(`SELECT id FROM ${provider.store.schema}.grants WHERE id=$1 AND user_id=$2 AND account_id=$3 FOR UPDATE`, [String(req.params.id), user.user.id, user.account.id])).rows[0];
      if (row) await provider.store.revoke(row.id, db);
    });
    res.json({ revoked: true });
  });
  app.use('/account-link', ui);
}
