import test from 'node:test';
import assert from 'node:assert/strict';
import { receiptToken, manifestHash, demoReceipt, verifyReceipt, checkPublicReceipt } from './verification.mjs';
import { createApp } from './index.mjs';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

test('Only canonical public receipt hosts and paths can be fetched', () => {
  const token = 'verify_' + 'a'.repeat(32);
  assert.equal(receiptToken(`https://countervault.co/verify/${token}`), token);
  for (const url of [`https://evil.example/verify/${token}`, `https://countervault.co.evil.example/verify/${token}`,
    `https://countervault.co/api/verify/${token}`, `https://countervault.co/verify/${token}?secret=1`,
    `https://u:p@countervault.co/verify/${token}`, `http://countervault.co/verify/${token}`, `https://countervault.co:999/verify/${token}`,
    'https://countervault.co/account', `https://api.countervault.co/api/verify/${token}/proof-bundle`]) assert.throws(() => receiptToken(url));
});

test('All manifest versions use the application format, including unicode and source evidence', () => {
  for (const v of [1, 2, 3]) {
    const fixture = demoReceipt();
    fixture.receipt.title = 'Receipt | café 🗂';
    fixture.records[0].attested_at = '2026-01-01T11:00:00.000Z';
    fixture.records[0].attestation_source = 'fixture';
    fixture.records[0].evidence_sha256 = 'f'.repeat(64);
    fixture.receipt.manifest_hash = manifestHash(v, fixture.receipt.title, fixture.receipt.context, fixture.records);
    assert.equal(verifyReceipt(fixture).manifest_version, v);
    fixture.records[0].sha256 = '0'.repeat(64);
    assert.throws(() => verifyReceipt(fixture), /mismatch/);
  }
});

test('Fingerprint matches and misses are distinct from original-file or timestamp verification', async () => {
  const fixture = demoReceipt();
  const match = await checkPublicReceipt('demo', fixture.records[0].sha256);
  assert.equal(match.fingerprint_matches, true);
  assert.equal(match.synthetic, true);
  assert.equal(match.timestamp_independently_verified, false);
  assert.equal(match.manifest_hash, fixture.receipt.manifest_hash);
  assert.equal((await checkPublicReceipt('demo', '0'.repeat(64))).fingerprint_matches, false);
  fixture.receipt.status = 'Revoked';
  assert.throws(() => verifyReceipt(fixture), /inactive or revoked/);
});

test('Requests are fixed-host GET without cookies, credentials or redirects; access failures stay failures', async () => {
  const token = 'verify_' + 'b'.repeat(32);
  const fixture = demoReceipt();
  fixture.synthetic = false;
  const result = await checkPublicReceipt(`https://countervault.co/verify/${token}`, undefined, async (url, options) => {
    assert.equal(url, `https://api.countervault.co/api/verify/${token}`);
    assert.equal(options.redirect, 'error');
    assert.deepEqual(options.headers, { Accept: 'application/json' });
    return new Response(JSON.stringify(fixture), { headers: { 'content-type': 'application/json' } });
  });
  assert.equal(result.synthetic, false);
  for (const status of [401, 403, 404, 502]) {
    await assert.rejects(checkPublicReceipt(`https://countervault.co/verify/${token}`, undefined, async () => new Response('', { status })));
  }
});

test('Official MCP SDK discovers both tools and receives full text and structured results', async () => {
  const listener = createApp().listen(0, '127.0.0.1');
  await new Promise(resolve => listener.once('listening', resolve));
  const url = `http://127.0.0.1:${listener.address().port}/mcp`;
  const client = new Client({ name: 'countervault-test', version: '1.0.0' });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL(url)));
    assert.deepEqual((await client.listTools()).tools.map(t => t.name), ['verify_public_receipt', 'compare_receipt_fingerprint']);
    const result = await client.callTool({ name: 'verify_public_receipt', arguments: { receipt_url: 'demo' } });
    assert.equal(result.isError, undefined);
    assert.equal(result.structuredContent.manifest_matches, true);
    assert.deepEqual(JSON.parse(result.content[0].text), result.structuredContent);
    const blocked = await client.callTool({ name: 'verify_public_receipt', arguments: { receipt_url: 'https://example.com/private' } });
    assert.equal(blocked.isError, true);
    const denied = await fetch(url, { method: 'POST', headers: { Origin: 'https://evil.example', 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(denied.status, 403);
  } finally { await client.close(); await new Promise(resolve => listener.close(resolve)); }
});
