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
  const q = (text, values = []) => pool.query(text, values);
  async function transaction(run) {
    const db = await pool.connect();
    try { await db.query('BEGIN'); const result = await run(db); await db.query('COMMIT'); return result; }
    catch (error) { await db.query('ROLLBACK'); throw error; }
    finally { db.release(); }
  }
  return {
    pool, box, schema, accountSchema, q, transaction,
    async client(id) { return (await q(`SELECT metadata FROM ${schema}.clients WHERE client_id=$1`, [id])).rows[0]?.metadata; },
    async register(client) { await q(`INSERT INTO ${schema}.clients(client_id,metadata) VALUES($1,$2)`, [client.client_id, client]); return client; },
    async pending(id) { return (await q(`SELECT r.*,c.metadata AS client FROM ${schema}.requests r JOIN ${schema}.clients c USING(client_id) WHERE r.id=$1 AND r.expires_at>now()`, [id])).rows[0]; },
    async reviewerSession(userId, accountId) {
      const member = (await q(`SELECT u.display_name FROM ${accountSchema}.users u JOIN ${accountSchema}.account_memberships m ON m.user_id=u.id
        WHERE u.id=$1 AND m.account_id=$2 AND u.status='active' AND m.status='active'`, [userId, accountId])).rows[0];
      if (!member) throw new Error('Directory review access is not configured.');
      const token = randomToken('session');
      await q(`INSERT INTO ${accountSchema}.auth_sessions(user_id,account_id,token_hash,expires_at,last_seen_at) VALUES($1,$2,$3,$4,now())`,
        [userId, accountId, hashToken(token), new Date(Date.now() + 60 * 60 * 1000)]);
      return { session_token: token, display_name: member.display_name, synthetic_account: true };
    },
    async newRequest(clientId, params) { const id = randomToken('request'); await q(`INSERT INTO ${schema}.requests VALUES($1,$2,$3,$4)`, [id, clientId, params, new Date(Date.now() + REQUEST_TTL)]); return id; },
    async revoke(grantId, db = pool) {
      await db.query(`UPDATE ${schema}.grants SET revoked_at=now(),encrypted_session='' WHERE id=$1`, [grantId]);
      await db.query(`UPDATE ${accountSchema}.auth_sessions SET revoked_at=now() WHERE id=(SELECT backend_session_id FROM ${schema}.grants WHERE id=$1)`, [grantId]);
      await db.query(`UPDATE ${schema}.tokens SET revoked_at=now() WHERE grant_id=$1`, [grantId]);
    },
    async cleanup() {
      await transaction(async db => {
        await db.query(`DELETE FROM ${schema}.requests WHERE expires_at<now()`);
        await db.query(`DELETE FROM ${schema}.codes WHERE expires_at<now()`);
        await db.query(`DELETE FROM ${schema}.tokens WHERE expires_at<now()`);
        await db.query(`DELETE FROM ${accountSchema}.auth_sessions WHERE id IN
          (SELECT backend_session_id FROM ${schema}.grants WHERE expires_at<now() OR revoked_at<now()-interval '1 day')`);
      });
    },
    async approve(requestId, identity) {
      return transaction(async db => {
        const request = (await db.query(`DELETE FROM ${schema}.requests WHERE id=$1 AND expires_at>now() RETURNING *`, [requestId])).rows[0];
        if (!request) throw new Error('This connection request expired or was already used. Start again from your assistant.');
        const session = randomToken('session');
        const expires = new Date(Date.now() + GRANT_TTL);
        const backend = (await db.query(`INSERT INTO ${accountSchema}.auth_sessions(user_id,account_id,token_hash,expires_at,last_seen_at) VALUES($1,$2,$3,$4,now()) RETURNING id`,
          [identity.user.id, identity.account.id, hashToken(session), expires])).rows[0];
        const id = randomUUID();
        await db.query(`INSERT INTO ${schema}.grants(id,client_id,user_id,account_id,backend_session_id,encrypted_session,scopes,resource,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [id, request.client_id, identity.user.id, identity.account.id, backend.id, box.encrypt(session), request.params.scopes, request.params.resource, expires]);
        const code = randomToken('code');
        await db.query(`INSERT INTO ${schema}.codes(code_hash,client_id,grant_id,challenge,redirect_uri,resource,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
          [hashToken(code), request.client_id, id, request.params.codeChallenge, request.params.redirectUri, request.params.resource, new Date(Date.now() + 60000)]);
        return { code, params: request.params };
      });
    },
    async issueTokens(db, grant, scopes = grant.scopes) {
      const access = randomToken('access');
      const refresh = randomToken('refresh');
      await db.query(`INSERT INTO ${schema}.tokens(token_hash,kind,client_id,grant_id,scopes,resource,expires_at) VALUES($1,'access',$2,$3,$4,$5,$6),($7,'refresh',$2,$3,$4,$5,$8)`,
        [hashToken(access), grant.client_id, grant.id, scopes, grant.resource, new Date(Date.now() + ACCESS_TTL * 1000), hashToken(refresh), grant.expires_at]);
      return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL, refresh_token: refresh, scope: scopes.join(' ') };
    },
    async resolveAccess(token) {
      return (await q(`SELECT t.*,g.user_id,g.account_id,g.encrypted_session,g.expires_at AS grant_expires_at FROM ${schema}.tokens t JOIN ${schema}.grants g ON g.id=t.grant_id
        JOIN ${accountSchema}.auth_sessions s ON s.id=g.backend_session_id JOIN ${accountSchema}.users u ON u.id=g.user_id
        JOIN ${accountSchema}.account_memberships m ON m.account_id=g.account_id AND m.user_id=g.user_id AND m.status='active'
        WHERE t.token_hash=$1 AND t.kind='access' AND t.revoked_at IS NULL AND t.expires_at>now() AND g.revoked_at IS NULL AND g.expires_at>now()
          AND s.revoked_at IS NULL AND s.expires_at>now() AND u.status='active'`, [hashToken(token)])).rows[0];
    },
  };
}
