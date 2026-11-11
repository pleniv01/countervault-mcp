import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { demoReceipt } from '../server/verification.mjs';

const url = 'https://countervault-mcp-production.up.railway.app/mcp';
const client = new Client({ name: 'countervault-release-check', version: '0.1.0' });
const report = { checked_at: new Date().toISOString(), url, synthetic: true, calls: [] };
try {
  await client.connect(new StreamableHTTPClientTransport(new URL(url)));
  report.tools = (await client.listTools()).tools.map(tool => tool.name);
  assert.ok(report.tools.includes('verify_public_receipt') && report.tools.includes('compare_receipt_fingerprint'));
  for (const [name, args, field, expected] of [
    ['verify_public_receipt', { receipt_url: 'demo' }, 'manifest_matches', true],
    ['compare_receipt_fingerprint', { receipt_url: 'demo', sha256: demoReceipt().records[0].sha256 }, 'fingerprint_matches', true],
    ['compare_receipt_fingerprint', { receipt_url: 'demo', sha256: '0'.repeat(64) }, 'fingerprint_matches', false],
  ]) {
    const response = await client.callTool({ name, arguments: args });
    assert.ok(!response.isError);
    assert.equal(response.structuredContent[field], expected);
    assert.equal(response.structuredContent.synthetic, true);
    assert.equal(response.structuredContent.timestamp_independently_verified, false);
    assert.deepEqual(JSON.parse(response.content[0].text), response.structuredContent);
    report.calls.push({ tool: name, check: field, expected, passed: true });
  }
  const rejected = await client.callTool({ name: 'verify_public_receipt', arguments: { receipt_url: 'https://example.com/private' } });
  assert.equal(rejected.isError, true);
  report.unsupported_host_rejected = true;
  report.status = 'passed';
} catch (error) { report.status = 'failed'; report.error = error.message; process.exitCode = 1; }
finally { await client.close(); }
await writeFile(new URL('../LIVE-VERIFICATION.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify(report, null, 2));
