import test from 'node:test';
import assert from 'node:assert/strict';
import {checkCompletedAccess,runOnce} from './account-tools.mjs';

test('cached completed operations must pass a fresh access check without repeating writes',async()=>{
 const cached={saved:true,folder_id:'folder',record:{id:'record',title:'Private title'}};
 let writes=0,queries=0,checks=0;
 const provider={store:{schema:'fixture',accountSchema:'account_fixture',lockGrantAccount:async()=>({account_id:'account'}),async transaction(run){return run({query:async sql=>{queries++;return sql.includes('deletion_epoch')?{rows:[{epoch:'0'}]}:{rows:[{operation:'save_note',payload_hash:(await import('./oauth-store.mjs')).hashToken(JSON.stringify({text:'same'})),status:'complete',result_epoch:'0',result:cached}]};}});}}};
 const auth={extra:{grantId:'grant'}};
 const result=await runOnce(provider,auth,'same_request','save_note',{text:'same'},async()=>{writes++;return {};});
 assert.equal(result.repeated_request,true);assert.equal(writes,0);assert.ok(queries>0);
 await assert.rejects(checkCompletedAccess(async()=>{checks++;throw Object.assign(new Error('Restricted'),{status:403});},'/access'),error=>error.operationCompleted===true&&!error.message.includes('Private title')&&error.message.includes('Do not retry'));
 assert.equal(checks,1);assert.equal(writes,0);
 await checkCompletedAccess(async()=>({allowed:true}),'/access');
 await assert.rejects(checkCompletedAccess(async()=>({}),'/access'),error=>error.operationCompleted===true);
 await assert.rejects(checkCompletedAccess(async()=>{throw new Error('network timeout');},'/access'),error=>error.operationCompleted===true);
});
