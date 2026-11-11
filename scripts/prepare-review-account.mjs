import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile, chmod } from 'node:fs/promises';

// Creates one dedicated synthetic directory account. No customer account is
// modified and no email is sent. Access code stays in an ignored local file.
const databaseUrl = process.env.DATABASE_PUBLIC_URL || process.env.DATABASE_URL;
if (!databaseUrl) throw new Error('Database configuration required.');
const pool = new pg.Pool({ connectionString: databaseUrl, ssl: databaseUrl.includes('railway') ? { rejectUnauthorized: false } : undefined });
const path = new URL('../.env.review.local', import.meta.url);
let existing = {};
try { existing = JSON.parse(await readFile(path, 'utf8')); } catch (error) { if (error.code !== 'ENOENT') throw error; }
const db = await pool.connect();
try {
  await db.query('BEGIN');
  const user = (await db.query(`INSERT INTO notary_v2.users(email,display_name,auth_provider,auth_subject)
    VALUES('countervault-directory-review@example.invalid','Countervault Directory Reviewer','directory-review','synthetic-reviewer')
    ON CONFLICT(email) DO UPDATE SET email=EXCLUDED.email RETURNING id,auth_provider`)).rows[0];
  if (user.auth_provider !== 'directory-review') throw new Error('The reserved reviewer identity is already used by another account.');
  let account = (await db.query(`SELECT a.id FROM notary_v2.accounts a JOIN notary_v2.account_memberships m ON m.account_id=a.id
    WHERE m.user_id=$1 AND a.name='Countervault Directory Review' AND m.role='owner'`, [user.id])).rows[0];
  if (!account) {
    account = (await db.query(`INSERT INTO notary_v2.accounts(name) VALUES('Countervault Directory Review') RETURNING id`)).rows[0];
    await db.query(`INSERT INTO notary_v2.account_memberships(user_id,account_id,role,status) VALUES($1,$2,'owner','active')`, [user.id, account.id]);
  }
  const config = { REVIEWER_USER_ID: user.id, REVIEWER_ACCOUNT_ID: account.id, REVIEWER_ACCESS_CODE: existing.REVIEWER_ACCESS_CODE || randomBytes(32).toString('base64url') };
  await writeFile(path, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  await chmod(path, 0o600);
  await db.query('COMMIT');
  console.log('Prepared the dedicated fictional directory review account. Credentials saved privately; none printed.');
} catch (error) { await db.query('ROLLBACK'); throw error; }
finally { db.release(); await pool.end(); }
