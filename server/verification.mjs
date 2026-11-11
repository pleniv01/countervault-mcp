import { createHash } from 'node:crypto';

export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export const LIMITS = 'A matching fingerprint supports byte integrity only. A receipt does not establish truth, authorship, identity, ownership, original creation date or legal admissibility. An anchor status reported by the API is not independent cryptographic timestamp verification.';
const shaPattern = /^[a-f0-9]{64}$/;
const tokenPattern = /^verify_[a-f0-9]{16,48}$/;

export function receiptToken(input) {
  if (input === 'demo') return 'demo';
  let url;
  try { url = new URL(input); } catch { throw new Error('Use a Countervault public receipt URL, or "demo" for the synthetic example.'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search || url.hash) throw new Error('Use an unmodified HTTPS Countervault receipt URL without credentials or query parameters.');
  const prefix = url.hostname === 'countervault.co' ? '/verify/' : url.hostname === 'api.countervault.co' ? '/api/verify/' : null;
  const token = prefix && url.pathname.startsWith(prefix) ? url.pathname.slice(prefix.length).replace(/\/$/, '') : '';
  if (!tokenPattern.test(token)) throw new Error('Only public receipts on countervault.co or api.countervault.co are supported. Private account links and other hosts are not fetched.');
  return token;
}

export function manifestHash(version, title, context, records) {
  const data = version === 1 ? [title, context, ...records.map(r => r.sha256)].join('|') : JSON.stringify([version, title, context, records.map(r => [
    r.original_filename, r.mime_type, String(r.byte_size), r.sha256, r.source_type, r.intake_mode,
    r.captured_at, r.received_at, r.created_at,
    ...(version === 3 ? [r.attested_at ?? null, r.attestation_source ?? null, r.evidence_sha256 ?? null] : []),
  ])]);
  return digest(Buffer.from(data, 'utf8'));
}

export function demoReceipt() {
  const records = [{ original_filename: 'fictional-delivery.txt', mime_type: 'text/plain', byte_size: '19',
    sha256: digest('Fictional delivery\n'), source_type: 'uploaded_file', intake_mode: 'manual',
    captured_at: '2026-01-01T12:00:00.000Z', received_at: '2026-01-02T12:00:00.000Z', created_at: '2026-01-02T12:00:00.000Z' }];
  const title = 'Synthetic reviewer example';
  const context = 'Fictional data; not saved to a Countervault account.';
  return { synthetic: true, receipt: { receipt_number: 'DEMO-NOT-A-SAVED-RECEIPT', title, context,
    manifest_hash: manifestHash(2, title, context, records), status: 'Active', revoked_at: null,
    generated_at: '2026-01-02T12:01:00.000Z', anchor_status: 'not_requested' }, records };
}

export async function fetchReceipt(token, fetcher = fetch) {
  if (token === 'demo') return demoReceipt();
  if (!tokenPattern.test(token)) throw new Error('Invalid public receipt reference.');
  let response;
  try {
    response = await fetcher(`https://api.countervault.co/api/verify/${token}`, {
      headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(15000),
    });
  } catch { throw new Error('Countervault could not be reached. No verification was completed.'); }
  if (response.status === 403 || response.status === 401) throw new Error('Receipt unavailable: it may be private, inactive or revoked. No access control was bypassed and no match was certified.');
  if (response.status === 404) throw new Error('Public receipt not found. No match was certified.');
  if (!response.ok) throw new Error('Countervault is temporarily unavailable. No match was certified.');
  if (!/^application\/json\b/i.test(response.headers.get('content-type') || '')) throw new Error('Countervault returned an unexpected response.');
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > 2 * 1024 * 1024) throw new Error('Receipt exceeds the connector response limit. Use Countervault directly.');
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new Error('Countervault returned an unreadable receipt.'); }
}

export function verifyReceipt(data, sha256) {
  const r = data?.receipt;
  if (!r || typeof r.title !== 'string' || typeof r.context !== 'string' || !shaPattern.test(r.manifest_hash) || !Array.isArray(data.records) || data.records.length > 10000) throw new Error('Invalid receipt response. No match was certified.');
  if (r.status !== 'Active' || r.revoked_at) throw new Error('Receipt is inactive or revoked. No match was certified.');
  for (const entry of data.records) {
    if (!entry || !shaPattern.test(entry.sha256) || typeof entry.original_filename !== 'string' || typeof entry.mime_type !== 'string'
      || !/^\d+$/.test(String(entry.byte_size)) || typeof entry.source_type !== 'string' || typeof entry.intake_mode !== 'string'
      || !['captured_at', 'received_at', 'created_at'].every(key => typeof entry[key] === 'string' || entry[key] === null)) throw new Error('Receipt contains an invalid entry. No match was certified.');
  }
  if (sha256 !== undefined && !shaPattern.test(sha256)) throw new Error('Supply a lowercase 64-character SHA-256 fingerprint; never upload the original file to this connector.');
  const version = [3, 2, 1].find(v => manifestHash(v, r.title, r.context, data.records) === r.manifest_hash);
  if (!version) throw new Error('Receipt manifest mismatch or unsupported format. No match was certified.');
  const result = {
    synthetic: data.synthetic === true,
    ...(data.synthetic ? { example_notice: 'Synthetic fixture, not an actual Countervault saved receipt or timestamp.' } : {}),
    receipt_number: r.receipt_number, status: r.status, manifest_hash: r.manifest_hash, manifest_matches: true,
    manifest_version: version, record_count: data.records.length, saved_at: r.generated_at,
    anchor_status_reported: r.anchor_status ?? 'unknown', timestamp_independently_verified: false,
    limits: LIMITS,
    date_meanings: { claimed: 'User-supplied date, not independently established.', attested: 'Source-specific assertion; inspect its evidence separately.', saved: 'Countervault receipt save time; not original creation time.' },
    ...(version === 1 ? { legacy_warning: 'Legacy v1 binds ordered hashes and title/context with an ambiguous delimiter format; entry metadata is not independently bound.' } : {}),
  };
  if (sha256 !== undefined) {
    result.compared_sha256 = sha256;
    result.matching_entry_numbers = data.records.flatMap((entry, i) => entry.sha256 === sha256 ? [i + 1] : []);
    result.fingerprint_matches = result.matching_entry_numbers.length > 0;
    result.comparison_meaning = result.fingerprint_matches ? 'Supplied digest appears in this sealed receipt. The connector did not read or hash your original file.' : 'Supplied digest does not appear in this receipt. This alone does not establish fraud or explain the difference.';
  }
  return result;
}

export async function checkPublicReceipt(input, sha256, fetcher) {
  const token = receiptToken(input);
  return verifyReceipt(await fetchReceipt(token, fetcher), sha256);
}
