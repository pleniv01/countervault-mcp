import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes, createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const origin = 'https://countervault-mcp-production.up.railway.app';
const reviewer = JSON.parse(await readFile(new URL('../.env.review.local', import.meta.url), 'utf8'));
const report = { checked_at: new Date().toISOString(), synthetic_account_only: true, calls: [] };
const inspectorIndex = process.argv.indexOf('--inspector-cli');
const inspectorPath = inspectorIndex >= 0 ? process.argv[inspectorIndex + 1] : null;
const execFileAsync = promisify(execFile);
const client = new Client({ name: 'countervault-connected-release-check', version: '0.2.0' });
let access;
let clientId;
async function jsonResponse(response) {
  const data = await response.json();
  if (!response.ok) throw new Error('Verification step failed (' + response.status + '): ' + String(data.error_description || data.error || 'request failed'));
  return data;
}
try {
  const metadata = await jsonResponse(await fetch(origin + '/.well-known/oauth-authorization-server'));
  const registration = await jsonResponse(await fetch(metadata.registration_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_name: 'Countervault synthetic release check', redirect_uris: ['https://chatgpt.com/connector_platform_oauth_redirect'], token_endpoint_auth_method: 'none' }) }));
  clientId = registration.client_id;
  const verifier = randomBytes(32).toString('base64url');
  const params = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: registration.redirect_uris[0],
    code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', resource: origin + '/mcp', scope: 'countervault:read countervault:write', state: 'synthetic-release-check' });
  const authorization = await fetch(metadata.authorization_endpoint + '?' + params, { redirect: 'manual' });
  assert.equal(authorization.status, 302);
  const requestId = new URL(authorization.headers.get('location')).searchParams.get('mcp_request');
  assert.ok(requestId);
  const reviewerSession = await jsonResponse(await fetch(origin + '/account-link/reviewer-session', {
    method: 'POST', headers: { Origin: 'https://countervault.co', 'Content-Type': 'application/json' }, body: JSON.stringify({ access_code: reviewer.REVIEWER_ACCESS_CODE }) }));
  assert.equal(reviewerSession.synthetic_account, true);
  const approved = await jsonResponse(await fetch(`${origin}/account-link/requests/${requestId}/approve`, {
    method: 'POST', headers: { Origin: 'https://countervault.co', 'Content-Type': 'application/json', Authorization: 'Bearer ' + reviewerSession.session_token }, body: '{}' }));
  const callback = new URL(approved.redirect_url);
  assert.equal(callback.searchParams.get('state'), 'synthetic-release-check');
  assert.equal(callback.searchParams.get('iss'), metadata.issuer);
  const tokens = await jsonResponse(await fetch(metadata.token_endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', client_id: clientId, code: callback.searchParams.get('code'), redirect_uri: registration.redirect_uris[0], code_verifier: verifier, resource: origin + '/mcp' }) }));
  access = tokens.access_token;
  await client.connect(new StreamableHTTPClientTransport(new URL(origin + '/mcp'), { requestInit: { headers: { Authorization: 'Bearer ' + access } } }));
  assert.equal((await client.listTools()).tools.length, 8);
  async function call(name, args = {}) {
    let result;
    if (inspectorPath) {
      try {
        const checked = await execFileAsync(process.execPath, [inspectorPath, '--cli', origin + '/mcp', '--method', 'tools/call', '--tool-name', name,
          '--tool-args-json', JSON.stringify(args), '--header', 'Authorization: Bearer ' + access, '--format', 'json', '--quiet', '--stored-auth-only'], { timeout: 45000, maxBuffer: 3 * 1024 * 1024 });
        result = JSON.parse(checked.stdout).result;
      } catch { throw new Error(name + ': Inspector call failed; credentials and subprocess arguments were not printed.'); }
    } else result = await client.callTool({ name, arguments: args });
    if (result.isError) throw new Error(name + ': ' + result.content.find(c => c.type === 'text')?.text);
    report.calls.push(name);
    return result.structuredContent;
  }
  await call('verify_public_receipt', { receipt_url: 'demo' });
  const comparison = await call('compare_receipt_fingerprint', { receipt_url: 'demo', sha256: '2860da7c2b76bd1c1b496c089d4fcf033499bf3c38e3efafc062f316cdc78d5f' });
  assert.equal(comparison.fingerprint_matches, true);
  const status = await call('get_account_status');
  assert.equal(status.account.id, reviewer.REVIEWER_ACCOUNT_ID);
  assert.equal(status.billing.complimentary, true);
  assert.equal(status.billing.write_access, true);
  assert.ok(status.subscription_url.startsWith('https://countervault.co/'));
  await call('list_folders', {});
  const prefix = 'release_' + randomBytes(8).toString('hex');
  const created = await call('create_folder', { title: 'Synthetic reviewer example', context: 'Fictional integration verification. No customer records.', request_id: prefix + '_folder' });
  assert.equal(created.private, true);
  const folderId = created.folder.id;
  const noteArgs = { folder_id: folderId, title: 'Fictional delivery', text: 'The fictional parcel arrived at noon. This is synthetic directory-review data.', request_id: prefix + '_note' };
  const saved = await call('save_note', noteArgs);
  assert.equal(saved.saved, true);
  const repeated = await call('save_note', noteArgs);
  assert.equal(repeated.record.id, saved.record.id);
  assert.equal(repeated.repeated_request, true);
  const folder = await call('get_folder', { folder_id: folderId });
  assert.equal(folder.folder.public_verification_enabled, false);
  assert.equal(folder.records.filter(r => r.id === saved.record.id).length, 1);
  const receipt = await call('create_receipt', { folder_id: folderId, request_id: prefix + '_receipt' });
  assert.equal(receipt.created, true);
  assert.equal(receipt.receipt.access_policy, 'private');
  assert.equal(receipt.receipt.anchor_status, 'not_requested');
  await jsonResponse(await fetch(origin + '/revoke', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, token: access }) }));
  const revoked = await fetch(origin + '/mcp', { method: 'POST', headers: { Authorization: 'Bearer ' + access, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(revoked.status, 401);
  report.oauth_pkce = 'passed'; report.note_retry_no_duplicate = 'passed'; report.private_receipt_no_timestamp = 'passed'; report.revocation = 'passed';
  report.status = 'passed';
  if (inspectorPath) report.client = 'Official MCP Inspector CLI';
  console.log('PASS: live OAuth account linking, subscription/complimentary access, folder reading/creation, note saving/retry, private receipt creation and revocation. Fictional reviewer account only; no purchase or customer-data access.');
} catch (error) { report.status = 'failed'; report.error = error.message; process.exitCode = 1; console.error(error.message); }
finally {
  await client.close();
  // Revoke an unfinished test connection too, if token issuance succeeded.
  if (access && clientId) await fetch(origin + '/revoke', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: clientId, token: access }) }).catch(() => {});
}
await writeFile(new URL(inspectorPath ? '../INSPECTOR-VERIFICATION.json' : '../CONNECTED-VERIFICATION.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
