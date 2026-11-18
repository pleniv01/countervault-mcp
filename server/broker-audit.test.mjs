import test from 'node:test';import assert from 'node:assert/strict';
import {bindBrowserIdentity,brokerAudit} from './broker-audit.mjs';
test('Browser authority is a private bearer binding, never a serialized actor claim',async()=>{
 const info={user:{id:'user'},account:{id:'account'},principal:{kind:'person'},auth_mode:'passwordless'};
 const db={query:async()=>{throw Error('Untrusted identity must be rejected before SQL');}},audit=brokerAudit(null,'protocol','account');
 await assert.rejects(audit.browser(db,{...info,browserSessionDigest:'forged',actorType:'person'}),e=>e.status===401);
 const bound=bindBrowserIdentity(info,'private-session');assert.equal(JSON.stringify(bound).includes('private-session'),false);
 await assert.rejects(audit.browser(db,JSON.parse(JSON.stringify(bound))),e=>e.status===401);
 await assert.rejects(audit.browser(db,{...bound}),e=>e.status===401);
 bound.account={id:'other'};await assert.rejects(audit.browser(db,bound),e=>e.status===401);
});
