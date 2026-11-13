import { recordOrigin } from './record-origin.mjs';
import { z } from 'zod';
import { hashToken } from './oauth-store.mjs';

const uuid = z.string().uuid();
const requestId = z.string().regex(/^[A-Za-z0-9_-]{8,100}$/).describe('Unique operation ID. Reuse the same ID for an identical retry; never mint a new ID merely because a response timed out.');
const versionFields=r=>({version_id:r.id,item_id:r.version_root_id||r.item_id||r.id,version_no:r.version_no||1,supersedes_record_id:r.supersedes_record_id||null,...(typeof r.is_current==='boolean'?{is_current:r.is_current}:{})});
const cleanReceipt = r => ({ id: r.id, receipt_number: r.receipt_number, manifest_hash: r.manifest_hash, status: r.status,
  access_policy: r.access_policy, generated_at: r.generated_at, anchor_status: r.anchor_status });
const cleanFolder = f => ({ id: f.id, title: f.title, context: f.context, permission_level: f.permission_level,
  public_verification_enabled: f.public_verification_enabled, updated_at: f.updated_at, record_count: f.record_count, receipt_count: f.receipt_count });

export async function runOnce(provider, auth, id, operation, payload, run) {
  const { store } = provider;
  const payloadHash = hashToken(JSON.stringify(payload));
  const inserted = await store.q(`INSERT INTO ${store.schema}.operations(grant_id,request_id,operation,payload_hash) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING request_id`,
    [auth.extra.grantId, id, operation, payloadHash]);
  if (!inserted.rowCount) {
    const previous = (await store.q(`SELECT * FROM ${store.schema}.operations WHERE grant_id=$1 AND request_id=$2`, [auth.extra.grantId, id])).rows[0];
    if (previous.operation !== operation || previous.payload_hash !== payloadHash) throw new Error('This request ID belongs to different content. Review the intended action before starting a new operation.');
    if (previous.status === 'complete') return { ...previous.result, repeated_request: true };
    throw new Error('This operation is in progress or its outcome is uncertain. Inspect the folder in Countervault before creating a new request. No automatic retry was performed.');
  }
  try {
    const result = await run();
    await store.q(`UPDATE ${store.schema}.operations SET status='complete',result=$3 WHERE grant_id=$1 AND request_id=$2`, [auth.extra.grantId, id, result]);
    return result;
  } catch (error) {
    // HTTP errors known to precede a write (auth, permission, validation, billing)
    // may be retried with the same operation ID after the cause is addressed.
    if ([400, 401, 402, 403, 404, 413, 429].includes(error.status)) await store.q(`DELETE FROM ${store.schema}.operations WHERE grant_id=$1 AND request_id=$2`, [auth.extra.grantId, id]);
    throw error;
  }
}

export function registerAccountTools(server, provider, auth) {
  const register = (name, title, description, schema, write, run) => server.registerTool(name, {
    title, description, inputSchema: schema,
    annotations: { title, readOnlyHint: !write, destructiveHint: false, idempotentHint: !write, openWorldHint: false },
    _meta: { securitySchemes: [{ type: 'oauth2', scopes: write ? ['countervault:read', 'countervault:write'] : ['countervault:read'] }] },
  }, async input => {
    const required = write ? ['countervault:read', 'countervault:write'] : ['countervault:read'];
    if (!auth || required.some(scope => !auth.scopes.includes(scope))) {
      return { isError: true, content: [{ type: 'text', text: 'Connect your Countervault account and approve the required access. No account action was performed.' }],
        _meta: { 'mcp/www_authenticate': [`Bearer resource_metadata="${new URL('/.well-known/oauth-protected-resource/mcp', provider.issuer).href}", scope="${required.join(' ')}"`] } };
    }
    try {
      const session = await provider.backendSession(auth);
      const data = await run(input, (path, options) => provider.requestAccount(session, path, options));
      return { content: [{ type: 'text', text: JSON.stringify(data) }], structuredContent: data };
    } catch (error) {
      return { isError: true, content: [{ type: 'text', text: JSON.stringify({ completed: false, error: error.message }) }] };
    }
  });
  register('get_account_status', 'Check your Countervault account',
    'Check the connected account, current subscription and write access. Returns an external subscription/manage-billing link; does not create checkout sessions, charge or change billing.', {}, false,
    async (_input, call) => {
      const [identity, billing] = await Promise.all([call('/api/auth/session'), call('/api/billing')]);
      return { user: { display_name: identity.user.display_name }, account: identity.account,
        billing: { available: billing.available, write_access: billing.writeAccess, complimentary: billing.complimentary,
          subscription_status: billing.subscription?.subscription_status || 'none', paid_through: billing.subscription?.paid_through || null,
          monthly_price_cents: billing.monthlyPriceCents, currency: billing.currency, tax_added_separately: !billing.taxesIncluded,
          retention_days_after_paid_period: billing.retentionDays },
        subscription_url: 'https://countervault.co/?billing=required', payments_handled_in: 'Countervault website checkout; never in the assistant.' };
    });
  register('list_folders', 'Find your Countervault folders',
    'List folders visible to the connected user within their Countervault account, optionally filtering titles. Does not expose other accounts, public sharing references, participant lists or original files.',
    { query: z.string().max(200).optional(), offset: z.number().int().min(0).max(10000).default(0), limit: z.number().int().min(1).max(50).default(20) }, false,
    async ({ query, offset, limit }, call) => {
      const result = await call('/api/folders');
      const folders = result.folders.filter(f => !query || f.title.toLowerCase().includes(query.toLowerCase()));
      return { folders: folders.slice(offset, offset + limit).map(cleanFolder), total: folders.length,
        next_offset: offset + limit < folders.length ? offset + limit : null };
    });
  register('get_folder', 'Read a Countervault folder',
    'Read current versions in a selected account folder; use get_record_history for superseded versions, its note text/entry metadata and receipt summaries under existing access permissions. Use a folder ID returned by list_folders or create_folder. Preserve tier and content_origin: user_authored records are user statements, not independently established facts. Does not download original files or expose participant emails or sharing tokens.',
    { folder_id: uuid, offset: z.number().int().min(0).max(10000).default(0), limit: z.number().int().min(1).max(50).default(20) }, false,
    async ({ folder_id, offset, limit }, call) => {
      const result = await call('/api/folders/' + folder_id);
      const records=result.records.filter(record=>record.is_current!==false);
      return { folder: cleanFolder(result.folder), records: records.slice(offset, offset + limit).map(r => ({ id: r.id, ...recordOrigin(r), ...versionFields(r),
        title: r.metadata?.title || r.original_filename, sha256: r.sha256, byte_size: r.byte_size, source_type: r.source_type,
        claimed_at: r.captured_at, attested_at: r.attested_at, saved_at: r.created_at,
        ...(r.source_type === 'typed_note' ? { note_text: String(r.metadata?.text || '').slice(0, 20000), note_truncated: String(r.metadata?.text || '').length > 20000 } : {}) })),
        record_count: records.length, next_offset: offset + limit < records.length ? offset + limit : null,
        receipts: result.receipts.slice(0, 20).map(cleanReceipt) };
    });
  register('get_record_history','Read an entry’s version history',
    'Read saved versions of a selected entry under the same folder permissions. Earlier notes and receipts are preserved. Preserve source labels; a correction does not establish truth. Returns private note text, truncated explicitly when necessary; does not download original files.',
    {folder_id:uuid,record_id:uuid,before_version:z.number().int().min(1).max(2147483647).optional()},false,async({folder_id,record_id,before_version},call)=>{
      const result=await call(`/api/folders/${folder_id}/records/${record_id}/history${before_version?'/'+before_version:''}`);
      return {item_id:result.item_id,current_version_id:result.current_version_id,total_versions:result.total_versions,next_before_version:result.next_before_version,versions:result.versions.map(r=>({id:r.id,...recordOrigin(r),...versionFields(r),title:r.metadata?.title||r.original_filename,sha256:r.sha256,source_type:r.source_type,reason:r.reason,saved_at:r.created_at,can_correct:r.can_correct,
        ...(r.source_type==='typed_note'?{note_text:String(r.metadata?.text||'').slice(0,20000),note_truncated:Boolean(r.note_truncated)||String(r.metadata?.text||'').length>20000}:{})}))};
    });
  register('create_folder', 'Create a private Countervault folder',
    'Create a new private folder only when the user asks to save a collection. Confirm the title and context if ambiguous. Requires a subscription and write scope. Never enables public verification, sharing, invitations or anchoring. Retry identical content with the same request_id.',
    { title: z.string().trim().min(1).max(200), context: z.string().max(2000).default(''), request_id: requestId }, true,
    async ({ title, context, request_id }, call) => runOnce(provider, auth, request_id, 'create_folder', { title, context }, async () => {
      const result = await call('/api/folders', { method: 'POST', body: { title, context, publicVerificationEnabled: false, collaborationStatus: 'private' } });
      return { folder: cleanFolder(result.folder), saved: true, private: true };
    }));
  register('save_note', 'Save a note in Countervault',
    'Save user-authored text verbatim in a selected folder, only when the user asks. Declare text_origin explicitly. For a user-requested correction, provide correction_of_record_id and correction_reason together; a new immutable version is appended. Review history if a newer version exists. Host-assistant drafts and analysis are not saved through this tool; they require an agent_interpretation save path, which is not available yet. Do not save an entire chat, inferred claims or a draft the user has not asked to preserve. Requires paid write access and folder upload permission. Claimed event time is optional and user-supplied. Reuse request_id for an identical retry.',
    { text_origin: z.enum(['user_authored','host_assistant']).describe('Who composed the text: the user or host assistant. User approval of an AI draft does not change its origin.'), folder_id: uuid, title: z.string().trim().min(1).max(140), text: z.string().min(1).max(20000).refine(value=>Boolean(value.trim()),'Write a note before saving.'),
      correction_of_record_id:uuid.optional(), correction_reason:z.string().trim().min(1).max(2000).optional(),
      occurred_at: z.string().datetime({ offset: true }).optional(), request_id: requestId }, true,
    async ({ text_origin, folder_id, title, text, occurred_at, request_id, correction_of_record_id, correction_reason }, call) => {
      if(text_origin==='host_assistant') return {saved:false,tier:'agent_interpretation',agent:{key:'host_assistant',version:'unspecified',operator:'user_connected'},reason:'Saving assistant interpretations is not available yet. Nothing was saved or converted into a user-authored note.',countervault_url:'https://countervault.co'};
      if(Boolean(correction_of_record_id)!==Boolean(correction_reason))throw new Error('Provide both the entry to correct and a reason. Nothing was saved.');
      const payload={folder_id,title,text,occurred_at,...(correction_of_record_id?{correction_of_record_id,correction_reason}:{})};
      const saved=await runOnce(provider, auth, request_id, correction_of_record_id?'correct_note':'save_note', payload, async () => {
      const path=correction_of_record_id?`/api/folders/${folder_id}/records/${correction_of_record_id}/corrections`:`/api/folders/${folder_id}/notes`;
      const result = await call(path, { method: 'POST', body: { title, text, occurredAt: occurred_at ?? null, requestId: request_id, contentOrigin: 'user_authored',...(correction_of_record_id?{reason:correction_reason}:{}) } });
      return { saved: true, folder_id, record: { id: result.record.id, ...recordOrigin(result.record), ...versionFields(result.record), title: result.record.metadata?.title,
        sha256: result.record.sha256, claimed_at: result.record.captured_at, saved_at: result.record.created_at } };
      });
      // Cached pre-provenance saves retain their existing operation identity.
      return {...saved,record:{...saved.record,...versionFields(saved.record),...recordOrigin({source_type:'typed_note',...saved.record})}};
    });
  register('create_receipt', 'Generate a Countervault receipt',
    'Generate a dated receipt for existing entries only when the user requests it. Existing folder sharing is preserved. If the folder is public, obtain explicit confirmation before setting public_visibility_confirmed true. Does not request blockchain timestamping, certify truth or notarize. Reuse request_id for an identical retry.',
    { folder_id: uuid, request_id: requestId, public_visibility_confirmed: z.boolean().default(false) }, true,
    async ({ folder_id, request_id, public_visibility_confirmed }, call) => {
      const { folder } = await call('/api/folders/' + folder_id);
      if (folder.public_verification_enabled && !public_visibility_confirmed) throw new Error('This folder has public verification enabled. Explain the visibility and obtain explicit confirmation, or use a private folder. No receipt was created.');
      return runOnce(provider, auth, request_id, 'create_receipt', { folder_id, public_visibility_confirmed }, async () => {
        const result = await call(`/api/folders/${folder_id}/receipts`, { method: 'POST', body: { requestBlockchainAnchor: false } });
        return { created: true, folder_id, receipt: cleanReceipt(result.receipt),
          limits: 'Receipt save time is not original creation time. Integrity does not establish truth, authorship, ownership or legal notarization. No blockchain timestamp was requested.' };
      });
    });
}
