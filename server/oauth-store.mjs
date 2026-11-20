import {brokerAudit} from './broker-audit.mjs';
import {CONNECTION_NOTICE_VERSION} from './connection-notice.mjs';
import pg from 'pg';
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';

export const hashToken = value => createHash('sha256').update(value).digest('hex');
export const randomToken = prefix => prefix + '_' + randomBytes(32).toString('base64url');
export const REQUEST_TTL = 10 * 60 * 1000;
export const GRANT_TTL = 30 * 24 * 60 * 60 * 1000;
export const ACCESS_TTL = 60 * 60;

export function secretBox(encodedKey) {
  const key = Buffer.from(encodedKey || '', 'base64');
  if (key.length !== 32) throw new Error('A 32-byte OAuth encryption key is required.');
  return {
    encrypt(value) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
    },
    decrypt(value) {
      const bytes = Buffer.from(value, 'base64');
      const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(0, 12));
      decipher.setAuthTag(bytes.subarray(12, 28));
      return Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8');
    },
  };
}

export async function createOAuthStore({ connectionString = process.env.DATABASE_URL, encryptionKey = process.env.OAUTH_TOKEN_ENCRYPTION_KEY,
  schema = 'countervault_mcp', accountSchema = 'notary_v2', pool: providedPool } = {}) {
  if (![schema, accountSchema].every(s => /^[a-z][a-z0-9_]*$/.test(s))) throw new Error('Invalid OAuth schema.');
  const pool = providedPool || new pg.Pool({ connectionString, max: 6, ssl: connectionString?.includes('railway') ? { rejectUnauthorized: false } : undefined });
  const box = secretBox(encryptionKey);
  await pool.query(`CREATE SCHEMA IF NOT EXISTS ${schema};
    CREATE TABLE IF NOT EXISTS ${schema}.clients(client_id text PRIMARY KEY, metadata jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS ${schema}.requests(id text PRIMARY KEY, client_id text NOT NULL REFERENCES ${schema}.clients(client_id), params jsonb NOT NULL, expires_at timestamptz NOT NULL);
    CREATE TABLE IF NOT EXISTS ${schema}.grants(id uuid PRIMARY KEY, client_id text NOT NULL REFERENCES ${schema}.clients(client_id),
      user_id uuid NOT NULL REFERENCES ${accountSchema}.users(id) ON DELETE CASCADE, account_id uuid NOT NULL REFERENCES ${accountSchema}.accounts(id) ON DELETE CASCADE,
      backend_session_id uuid NOT NULL REFERENCES ${accountSchema}.auth_sessions(id) ON DELETE CASCADE, encrypted_session text NOT NULL,
      scopes text[] NOT NULL, resource text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL, revoked_at timestamptz);
    CREATE TABLE IF NOT EXISTS ${schema}.codes(code_hash text PRIMARY KEY, client_id text NOT NULL, grant_id uuid NOT NULL REFERENCES ${schema}.grants(id) ON DELETE CASCADE,
      challenge text NOT NULL, redirect_uri text NOT NULL, resource text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
    CREATE TABLE IF NOT EXISTS ${schema}.tokens(token_hash text PRIMARY KEY, kind text NOT NULL CHECK(kind IN ('access','refresh')), client_id text NOT NULL,
      grant_id uuid NOT NULL REFERENCES ${schema}.grants(id) ON DELETE CASCADE, scopes text[] NOT NULL, resource text NOT NULL, expires_at timestamptz NOT NULL,
      used_at timestamptz, revoked_at timestamptz);
    CREATE INDEX IF NOT EXISTS tokens_grant_idx ON ${schema}.tokens(grant_id);
    CREATE TABLE IF NOT EXISTS ${schema}.operations(grant_id uuid NOT NULL REFERENCES ${schema}.grants(id) ON DELETE CASCADE,
      request_id text NOT NULL, operation text NOT NULL, payload_hash text NOT NULL, result jsonb, status text NOT NULL DEFAULT 'started',
      created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(grant_id,request_id));`);
  await pool.query(`SELECT actor_kind,principal_id,authorization_grant_id FROM ${accountSchema}.auth_sessions LIMIT 0`);
  await pool.query(`SELECT sequence FROM ${accountSchema}.audit_chains LIMIT 0`);
  const supported=(await pool.query("SELECT 1 FROM pg_constraint WHERE conrelid=$1::regclass AND pg_get_constraintdef(oid) LIKE '%session_started%'",[accountSchema+'.audit_chain_events'])).rowCount;
  if(!supported)throw new Error('Apply paired Countervault audit migrations through 0030 before starting this broker.');
  await pool.query(`ALTER TABLE ${schema}.requests ADD COLUMN IF NOT EXISTS audit_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE`);
  try{await pool.query(`SELECT deletion_epoch FROM ${accountSchema}.accounts LIMIT 0`);}catch(error){if(error.code==='42703')throw new Error('Apply paired Countervault item erasure migration 0034 before starting this broker.');throw error;}
  await pool.query(`ALTER TABLE ${schema}.operations ADD COLUMN IF NOT EXISTS result_epoch bigint NOT NULL DEFAULT 0`);
  const audit=brokerAudit(pool,schema,accountSchema);
  const q = (text, values = []) => pool.query(text, values);
  async function transaction(run) {
    const db = await pool.connect();
    try { await db.query('BEGIN'); const result = await run(db); await db.query('COMMIT'); return result; }
    catch (error) { await db.query('ROLLBACK'); throw error; }
    finally { db.release(); }
  }
  async function revoke(grantId,db,context){
    if(!context||!['browser','protocol','replay','cleanup'].includes(context.kind))throw new Error('A validated revocation authority is required.');
    if(!db)return transaction(client=>revoke(grantId,client,context));
    let actor;
    if(context.kind==='browser'){
      actor=await audit.browser(db,context.identity);
      if(!(await db.query(`SELECT id FROM ${schema}.grants WHERE id=$1 AND user_id=$2 AND account_id=$3`,[grantId,actor.userId,actor.accountId])).rowCount)return false;
    }
    const location=await audit.grantAccount(db,grantId);if(!location)return false;
    await db.query(`SELECT id FROM ${accountSchema}.authorization_grants WHERE id=$1 FOR UPDATE`,[grantId]);
    const grant=(await db.query(`SELECT *,expires_at<=clock_timestamp() OR revoked_at<clock_timestamp()-interval '1 day' AS cleanup_due FROM ${schema}.grants WHERE id=$1 FOR UPDATE`,[grantId])).rows[0];
    if(!grant||context.kind==='cleanup'&&!grant.cleanup_due)return false;
    const canonical=await db.query(`UPDATE ${accountSchema}.authorization_grants SET enabled=false WHERE id=$1 AND grantee_type='assistant' AND account_id=$2 AND owner_user_id=$3 AND (enabled OR revoked_at IS NULL) RETURNING id`,[grantId,grant.account_id,grant.user_id]);
    const protocol=await db.query(`UPDATE ${schema}.grants SET revoked_at=COALESCE(revoked_at,clock_timestamp()),encrypted_session='' WHERE id=$1 AND (revoked_at IS NULL OR encrypted_session<>'') RETURNING id`,[grantId]);
    const backend=await db.query(`UPDATE ${accountSchema}.auth_sessions SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL RETURNING id`,[grant.backend_session_id]);
    const tokens=await db.query(`UPDATE ${schema}.tokens SET revoked_at=clock_timestamp() WHERE grant_id=$1 AND revoked_at IS NULL RETURNING token_hash`,[grantId]);
    const changed=Boolean(canonical.rowCount||protocol.rowCount||backend.rowCount||tokens.rowCount);
    if(changed)await audit.append(db,actor||{...audit.system(grant.account_id),surface:context.kind==='cleanup'?'system':'api'},'connection_changed','authorization_grant',grantId);
    return changed;
  }
  return {
    pool, box, schema, accountSchema, q, transaction, lockGrantAccount:audit.grantAccount,
    async client(id) { return (await q(`SELECT metadata FROM ${schema}.clients WHERE client_id=$1`, [id])).rows[0]?.metadata; },
    async register(client) { await q(`INSERT INTO ${schema}.clients(client_id,metadata) VALUES($1,$2)`, [client.client_id, client]); return client; },
    async pending(id) { return (await q(`SELECT r.*,c.metadata AS client FROM ${schema}.requests r JOIN ${schema}.clients c USING(client_id) WHERE r.id=$1 AND r.expires_at>now()`, [id])).rows[0]; },
    async reviewerSession(userId,accountId){return transaction(async db=>{
      await audit.account(db,accountId);
      const member=(await db.query(`SELECT u.display_name FROM ${accountSchema}.users u JOIN ${accountSchema}.account_memberships m ON m.user_id=u.id WHERE u.id=$1 AND m.account_id=$2 AND u.status='active' AND m.status='active' FOR SHARE OF u,m`,[userId,accountId])).rows[0];
      if(!member)throw new Error('Directory review access is not configured.');
      const token=randomToken('session'),row=(await db.query(`INSERT INTO ${accountSchema}.auth_sessions(user_id,account_id,token_hash,expires_at,last_seen_at) VALUES($1,$2,$3,$4,now()) RETURNING id`,[userId,accountId,hashToken(token),new Date(Date.now()+60*60*1000)])).rows[0];
      await audit.append(db,audit.system(accountId),'session_started','auth_session',row.id);
      return {session_token:token,display_name:member.display_name,synthetic_account:true};
    });},
    async newRequest(clientId, params) { const id = randomToken('request'); await q(`INSERT INTO ${schema}.requests(id,client_id,params,expires_at) VALUES($1,$2,$3,$4)`, [id, clientId, params, new Date(Date.now() + REQUEST_TTL)]); return id; },
    revoke,
    async cleanup(){
      // Unbound request GC commits separately: it must never hold request locks
      // while waiting for an account held by an approval transaction.
      await q(`DELETE FROM ${schema}.requests WHERE expires_at<clock_timestamp()`);
      await transaction(async db=>{
        const accounts=(await db.query(`SELECT DISTINCT g.account_id FROM ${schema}.grants g WHERE g.expires_at<clock_timestamp() OR g.revoked_at<clock_timestamp()-interval '1 day' OR EXISTS(SELECT 1 FROM ${schema}.codes c WHERE c.grant_id=g.id AND c.expires_at<clock_timestamp()) OR EXISTS(SELECT 1 FROM ${schema}.tokens t WHERE t.grant_id=g.id AND t.expires_at<clock_timestamp()) ORDER BY g.account_id`)).rows.map(r=>r.account_id);
        for(const id of accounts)await audit.account(db,id);
        const codes=(await db.query(`DELETE FROM ${schema}.codes c USING ${schema}.grants g WHERE c.grant_id=g.id AND g.account_id=ANY($1::uuid[]) AND c.expires_at<clock_timestamp() RETURNING g.account_id,g.id AS grant_id`,[accounts])).rows;
        const tokens=(await db.query(`DELETE FROM ${schema}.tokens t USING ${schema}.grants g WHERE t.grant_id=g.id AND g.account_id=ANY($1::uuid[]) AND t.expires_at<clock_timestamp() RETURNING g.account_id,g.id AS grant_id`,[accounts])).rows;
        const purged=new Map();for(const row of [...codes,...tokens])purged.set(row.grant_id,row.account_id);
        for(const [id,accountId]of purged)await audit.append(db,{...audit.system(accountId),surface:'system'},'retention_purged','authorization_grant',id);
        const expired=(await db.query(`SELECT id,account_id,backend_session_id FROM ${schema}.grants WHERE account_id=ANY($1::uuid[]) AND (expires_at<clock_timestamp() OR revoked_at<clock_timestamp()-interval '1 day') ORDER BY account_id,id`,[accounts])).rows;
        for(const row of expired){await revoke(row.id,db,{kind:'cleanup'});const removed=await db.query(`DELETE FROM ${accountSchema}.auth_sessions s USING ${schema}.grants g WHERE s.id=$1 AND g.id=$2 AND g.backend_session_id=s.id AND (g.expires_at<clock_timestamp() OR g.revoked_at<clock_timestamp()-interval '1 day') RETURNING s.id`,[row.backend_session_id,row.id]);if(removed.rowCount)await audit.append(db,{...audit.system(row.account_id),surface:'system'},'retention_purged','auth_session',row.backend_session_id);}
      });
    },
    async deny(requestId,identity){return transaction(async db=>{
      const actor=await audit.browser(db,identity),row=(await db.query(`DELETE FROM ${schema}.requests WHERE id=$1 AND expires_at>clock_timestamp() RETURNING audit_id,params`,[requestId])).rows[0];
      if(row)await audit.append(db,actor,'connection_changed','request',row.audit_id);return row;
    });},
    async approve(requestId, identity) {
      return transaction(async db => {
        const actor=await audit.browser(db,identity);
        const request = (await db.query(`DELETE FROM ${schema}.requests WHERE id=$1 AND expires_at>clock_timestamp() RETURNING *`, [requestId])).rows[0];
        if (!request) throw new Error('This connection request expired or was already used. Start again from your assistant.');
        if(identity.principal?.kind!=='person'||identity.auth_mode!=='passwordless')throw new Error('Approve this connection while signed in directly to Countervault.');
        const id=randomUUID(),session=randomToken('session'),expires=new Date(Date.now()+GRANT_TTL);
        const scopes=request.params.scopes;
        if(!Array.isArray(scopes)||!scopes.includes('countervault:read')||scopes.some(scope=>!['countervault:read','countervault:write'].includes(scope)))throw new Error('Invalid connection scopes.');
        const actions=['read_account','read',...(scopes.includes('countervault:write')?['create_folder','write_user_note','correct_user_note','create_receipt']:[])];
        const host=new URL(request.params.redirectUri).hostname;
        const surface=['chatgpt.com','platform.openai.com'].includes(host)?'chatgpt':['claude.ai','console.anthropic.com'].includes(host)?'claude':'api';
        const consent=(await db.query(`INSERT INTO ${accountSchema}.consent_events(account_id,user_id,kind,doc_version,subject_id,accepted,surface)
          VALUES($1,$2,'connect_agent',$3,$4,true,'web') RETURNING id`,[identity.account.id,identity.user.id,CONNECTION_NOTICE_VERSION,id])).rows[0];
        await db.query(`INSERT INTO ${accountSchema}.authorization_grants(id,account_id,owner_user_id,grantee_type,grantee_id,all_projects,tiers,actions,exclude_restricted,consent_event_id,enabled,expires_at)
          VALUES($1,$2,$3,'assistant',$1,true,ARRAY['record','agent_interpretation'],$4,true,$5,true,$6)`,[id,identity.account.id,identity.user.id,actions,consent.id,expires]);
        const backend=(await db.query(`INSERT INTO ${accountSchema}.auth_sessions(user_id,account_id,token_hash,expires_at,last_seen_at,actor_kind,actor_surface,principal_id,authorization_grant_id)
          VALUES($1,$2,$3,$4,now(),'assistant',$5,$6,$6) RETURNING id`,[identity.user.id,identity.account.id,hashToken(session),expires,surface,id])).rows[0];
        await db.query(`INSERT INTO ${schema}.grants(id,client_id,user_id,account_id,backend_session_id,encrypted_session,scopes,resource,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [id, request.client_id, identity.user.id, identity.account.id, backend.id, box.encrypt(session), request.params.scopes, request.params.resource, expires]);
        const code = randomToken('code');
        await db.query(`INSERT INTO ${schema}.codes(code_hash,client_id,grant_id,challenge,redirect_uri,resource,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
          [hashToken(code), request.client_id, id, request.params.codeChallenge, request.params.redirectUri, request.params.resource, new Date(Date.now() + 60000)]);
        await audit.append(db,actor,'connection_changed','authorization_grant',id);
        return { code, params: request.params };
      });
    },
    async issueTokens(db, grant, scopes = grant.scopes) {
      await audit.grantAccount(db,grant.id);
      await audit.currentGrant(db,grant.id);
      const access = randomToken('access');
      const refresh = randomToken('refresh');
      await db.query(`INSERT INTO ${schema}.tokens(token_hash,kind,client_id,grant_id,scopes,resource,expires_at) VALUES($1,'access',$2,$3,$4,$5,$6),($7,'refresh',$2,$3,$4,$5,$8)`,
        [hashToken(access), grant.client_id, grant.id, scopes, grant.resource, new Date(Date.now() + ACCESS_TTL * 1000), hashToken(refresh), grant.expires_at]);
      const binding=(await db.query(`SELECT account_id FROM ${schema}.grants WHERE id=$1`,[grant.id])).rows[0];
      await audit.append(db,audit.system(binding.account_id),'connection_changed','authorization_grant',grant.id);
      return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token: refresh, scope: scopes.join(' ') };
    },
    async resolveAccess(token) {
      return (await q(`SELECT t.*,g.user_id,g.account_id,g.encrypted_session,g.expires_at AS grant_expires_at FROM ${schema}.tokens t JOIN ${schema}.grants g ON g.id=t.grant_id
        JOIN ${accountSchema}.auth_sessions s ON s.id=g.backend_session_id AND s.actor_kind='assistant' AND s.principal_id=g.id
        JOIN ${accountSchema}.authorization_grants ag ON ag.id=s.authorization_grant_id AND ag.grantee_id=g.id AND ag.account_id=g.account_id AND ag.owner_user_id=g.user_id AND ag.enabled AND ag.revoked_at IS NULL AND (ag.expires_at IS NULL OR ag.expires_at>now())
        JOIN LATERAL(SELECT id,accepted FROM ${accountSchema}.consent_events ce WHERE ce.account_id=g.account_id AND ce.user_id=g.user_id AND ce.kind='connect_agent' AND ce.subject_id=g.id ORDER BY ce.event_sequence DESC LIMIT 1) ce ON ce.id=ag.consent_event_id AND ce.accepted JOIN ${accountSchema}.users u ON u.id=g.user_id
        JOIN ${accountSchema}.account_memberships m ON m.account_id=g.account_id AND m.user_id=g.user_id AND m.status='active'
        WHERE t.token_hash=$1 AND t.kind='access' AND t.revoked_at IS NULL AND t.expires_at>now() AND g.revoked_at IS NULL AND g.expires_at>now()
          AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'`, [hashToken(token)])).rows[0];
    },
  };
}
