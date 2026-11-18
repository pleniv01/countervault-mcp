import {createHash} from 'node:crypto';
const browserProofs=new WeakMap();
const changed=()=>Object.assign(new Error('Your Countervault sign-in changed. Sign in again before managing this assistant connection.'),{status:401});
// Only the HTTP identity bridge calls this after a trusted backend identity read.
// The proof never becomes JSON and cannot be supplied as an actor/body field.
export function bindBrowserIdentity(info,token){
 const identity={...info};browserProofs.set(identity,Object.freeze({digest:createHash('sha256').update(token).digest('hex'),accountId:info.account?.id,userId:info.user?.id}));return identity;
}
export function brokerAudit(pool,schema,accountSchema){
 const append=async(db,actor,action,type,id)=>{await db.query(`SELECT ${accountSchema}.audit_append_event($1,$2,$3,$4,$5,$6,$7,NULL,NULL,NULL,NULL)`,[actor.accountId,actor.actorType,actor.actorId,actor.surface,action,type,id]);};
 const system=accountId=>({accountId,actorType:'system',actorId:null,surface:'api'});
 const account=async(db,id)=>db.query(`SELECT id FROM ${accountSchema}.accounts WHERE id=$1 FOR UPDATE`,[id]);
 async function browser(db,identity){
  const p=browserProofs.get(identity);if(!p||identity.user?.id!==p.userId||identity.account?.id!==p.accountId||identity.principal?.kind!=='person'||identity.auth_mode!=='passwordless')throw changed();
  await account(db,p.accountId);
  const row=(await db.query(`SELECT s.id,s.actor_surface FROM ${accountSchema}.auth_sessions s JOIN ${accountSchema}.users u ON u.id=s.user_id AND u.status='active'
   JOIN ${accountSchema}.account_memberships m ON m.user_id=s.user_id AND m.account_id=s.account_id AND m.status='active'
   WHERE s.token_hash=$1 AND s.account_id=$2 AND s.user_id=$3 AND s.actor_kind='person' AND s.principal_id IS NULL AND s.authorization_grant_id IS NULL
   AND s.actor_surface IN ('web','api') AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() FOR SHARE OF s,u,m`,[p.digest,p.accountId,p.userId])).rows[0];
  if(!row)throw changed();
  const refs=(await db.query(`SELECT DISTINCT quote_ident(n.nspname)||'.'||quote_ident(r.relname) AS relation FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=ANY(c.conkey)
   WHERE c.contype='f' AND c.confrelid=$1::regclass AND r.relname='grants' AND a.attname='backend_session_id'`,[accountSchema+'.auth_sessions'])).rows;
  for(const ref of refs)if((await db.query('SELECT 1 FROM '+ref.relation+' WHERE backend_session_id=$1 LIMIT 1',[row.id])).rowCount)throw changed();
  return {accountId:p.accountId,userId:p.userId,actorType:'person',actorId:p.userId,surface:row.actor_surface};
 }
 async function grantAccount(db,id){const row=(await db.query(`SELECT account_id,user_id FROM ${schema}.grants WHERE id=$1`,[id])).rows[0];if(row)await account(db,row.account_id);return row;}
 async function currentGrant(db,id){
  const row=(await db.query(`SELECT g.* FROM ${schema}.grants g JOIN ${accountSchema}.auth_sessions s ON s.id=g.backend_session_id AND s.account_id=g.account_id AND s.user_id=g.user_id AND s.actor_kind='assistant' AND s.principal_id=g.id
   JOIN ${accountSchema}.authorization_grants a ON a.id=s.authorization_grant_id AND a.id=g.id AND a.grantee_type='assistant' AND a.grantee_id=g.id AND a.account_id=g.account_id AND a.owner_user_id=g.user_id AND a.enabled AND a.revoked_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp())
   JOIN LATERAL(SELECT c.id,c.accepted FROM ${accountSchema}.consent_events c WHERE c.account_id=g.account_id AND c.user_id=g.user_id AND c.kind='connect_agent' AND c.subject_id=g.id ORDER BY c.event_sequence DESC LIMIT 1) c ON c.id=a.consent_event_id AND c.accepted
   JOIN ${accountSchema}.users u ON u.id=g.user_id AND u.status='active' JOIN ${accountSchema}.account_memberships m ON m.user_id=g.user_id AND m.account_id=g.account_id AND m.status='active'
   WHERE g.id=$1 AND g.revoked_at IS NULL AND g.expires_at>clock_timestamp() AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() FOR SHARE OF a,s,u,m,g`,[id])).rows[0];
  if(!row)throw new Error('Assistant authorization changed. Reconnect Countervault.');return row;
 }
 return {append,system,account,browser,grantAccount,currentGrant};
}
