import {hashToken} from './oauth-store.mjs';
const removed=()=>Object.assign(new Error('This saved action result was cleared when records were deleted. Review Countervault; do not repeat the action with a new request ID.'),{operationCompleted:true});
export const erasedOperationKey=id=>'!erased:'+hashToken(id);
async function epoch(store,db,grantId){
 const grant=await store.lockGrantAccount(db,grantId);if(!grant)throw removed();
 const row=(await db.query(`SELECT deletion_epoch::text AS epoch FROM ${store.accountSchema}.accounts WHERE id=$1`,[grant.account_id])).rows[0];
 if(!row)throw removed();return row.epoch;
}
export async function beginOperation(store,grantId,id,operation,payloadHash){return store.transaction(async db=>{
 const current=await epoch(store,db,grantId);
 const previous=(await db.query(`SELECT * FROM ${store.schema}.operations WHERE grant_id=$1 AND request_id=ANY($2::text[]) FOR UPDATE`,[grantId,[id,erasedOperationKey(id)]])).rows[0];
 if(previous){
  if(previous.status==='erased'||String(previous.result_epoch)!==current)throw removed();
  if(previous.operation!==operation||previous.payload_hash!==payloadHash)throw Error('This request ID belongs to different content. Review the intended action before starting a new operation.');
  if(previous.status==='complete')return previous.result;
  throw Error('This operation is in progress or its outcome is uncertain. Inspect the folder in Countervault before creating a new request. No automatic retry was performed.');
 }
 await db.query(`INSERT INTO ${store.schema}.operations(grant_id,request_id,operation,payload_hash,result_epoch) VALUES($1,$2,$3,$4,$5)`,[grantId,id,operation,payloadHash,current]);return null;
});}
export async function completeOperation(store,grantId,id,result){return store.transaction(async db=>{
 const current=await epoch(store,db,grantId);
 const row=(await db.query(`SELECT status,result_epoch::text AS epoch FROM ${store.schema}.operations WHERE grant_id=$1 AND request_id=$2 FOR UPDATE`,[grantId,id])).rows[0];
 if(!row||row.status!=='started'||row.epoch!==current)return false;
 await db.query(`UPDATE ${store.schema}.operations SET status='complete',result=$3 WHERE grant_id=$1 AND request_id=$2`,[grantId,id,result]);return true;
});}
export async function discardOperation(store,grantId,id){return store.transaction(async db=>{
 const current=await epoch(store,db,grantId);
 await db.query(`DELETE FROM ${store.schema}.operations WHERE grant_id=$1 AND request_id=$2 AND status='started' AND result_epoch=$3`,[grantId,id,current]);
});}
