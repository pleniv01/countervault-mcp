import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { secretBox } from './oauth-store.mjs';
import { validRedirect, CountervaultOAuth } from './oauth.mjs';
import { createApp } from './index.mjs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

test('Connection credentials are authenticated encryption, not plaintext or unauthenticated ciphertext', () => {
  const box = secretBox(randomBytes(32).toString('base64'));
  const encrypted = box.encrypt('session_test_private');
  assert.ok(!encrypted.includes('session_test_private'));
  assert.equal(box.decrypt(encrypted), 'session_test_private');
  const modified = Buffer.from(encrypted, 'base64'); modified[modified.length - 1] ^= 1;
  assert.throws(() => box.decrypt(modified.toString('base64')));
  assert.throws(() => secretBox('invalid'));
});

test('Callbacks and resource/scopes cannot be changed to arbitrary sites or services', () => {
  for (const url of ['https://chatgpt.com/connector_platform_oauth_redirect', 'https://claude.ai/api/mcp/auth_callback']) assert.equal(validRedirect(url), true);
  for (const url of ['http://chatgpt.com/callback', 'https://chatgpt.com.evil.example/callback', 'https://example.com/callback', 'https://u:p@claude.ai/callback', 'https://claude.ai:444/callback', 'http://localhost:8080/callback']) assert.equal(validRedirect(url), false);
  const provider = new CountervaultOAuth({});
  assert.throws(() => provider.validateResource(new URL('https://api.countervault.co')));
  assert.throws(() => provider.validateResource(undefined));
  assert.throws(() => provider.validateScopes(['countervault:admin']));
});

test('Private MCP tools require account consent and write scope, even when public tools are available', async () => {
  let accountCalls = 0;
  const provider = {
    issuer: 'https://countervault-mcp-production.up.railway.app/', resource: 'https://countervault-mcp-production.up.railway.app/mcp',
    clientsStore: { getClient() {} },
    async verifyAccessToken(token) {
      if (token !== 'access_read_fixture') throw new Error('invalid');
      return { token, scopes: ['countervault:read'], clientId: 'fixture', resource: new URL(this.resource), expiresAt: Date.now() / 1000 + 60, extra: { grantId: 'fixture' } };
    },
    async backendSession() { return 'fixture_backend_session'; },
    async requestAccount() { accountCalls++; return { folders: [] }; },
  };
  const listener = createApp({ provider }).listen(0, '127.0.0.1');
  await new Promise(resolve => listener.once('listening', resolve));
  const url = new URL(`http://127.0.0.1:${listener.address().port}/mcp`);
  const anonymous = new Client({ name: 'anonymous-test', version: '1' });
  const reader = new Client({ name: 'reader-test', version: '1' });
  try {
    await anonymous.connect(new StreamableHTTPClientTransport(url));
    assert.equal((await anonymous.listTools()).tools.length, 9);
    const challenge = await anonymous.callTool({ name: 'list_folders', arguments: {} });
    assert.equal(challenge.isError, true);
    assert.ok(challenge._meta['mcp/www_authenticate'][0].includes('countervault:read'));
    assert.equal(accountCalls, 0);
    await reader.connect(new StreamableHTTPClientTransport(url, { requestInit: { headers: { Authorization: 'Bearer access_read_fixture' } } }));
    assert.deepEqual((await reader.callTool({ name: 'list_folders', arguments: {} })).structuredContent.folders, []);
    assert.equal(accountCalls, 1);
    const denied = await reader.callTool({ name: 'create_folder', arguments: { title: 'Fixture', request_id: 'fixture_123' } });
    assert.equal(denied.isError, true);
    assert.equal(accountCalls, 1);
    const invalid = await fetch(url, { method: 'POST', headers: { Authorization: 'Bearer invalid' } });
    assert.equal(invalid.status, 401);
    assert.ok(invalid.headers.get('www-authenticate').includes('resource_metadata'));
  } finally { await anonymous.close(); await reader.close(); await new Promise(resolve => listener.close(resolve)); }
});
