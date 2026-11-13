import test from 'node:test';
import assert from 'node:assert/strict';
import {recordOrigin} from './record-origin.mjs';
import {createApp} from './index.mjs';
import {Client} from '@modelcontextprotocol/sdk/client/index.js';
import {StreamableHTTPClientTransport} from '@modelcontextprotocol/sdk/client/streamableHttp.js';

test('legacy record projections derive origin without accepting contradictory labels',()=>{
  assert.deepEqual(recordOrigin({source_type:'typed_note'}),{tier:'record',content_origin:'user_authored'});
  assert.deepEqual(recordOrigin({source_type:'drive',tier:'record',content_origin:'external',storage_mode:'linked',content_stored:false}),{tier:'record',content_origin:'external'});
  assert.throws(()=>recordOrigin({source_type:'typed_note',content_origin:'external'}),/inconsistent/);
  assert.throws(()=>recordOrigin({source_type:'typed_note',tier:'agent_interpretation'}),/inconsistent/);
  assert.throws(()=>recordOrigin({}),/missing/);
});
test('Claude and ChatGPT transports preserve record origin and refuse to save host analysis',async()=>{
  const folderId='11111111-1111-4111-8111-111111111111',recordId='22222222-2222-4222-8222-222222222222';
  let writes=0,operations=0;
  const provider={issuer:'https://countervault-mcp-production.up.railway.app/',resource:'https://countervault-mcp-production.up.railway.app/mcp',clientsStore:{getClient(){}},
    store:{schema:'synthetic',async q(){operations++;return {rowCount:1,rows:[]};}},
    async verifyAccessToken(token){if(!['claude_fixture','chatgpt_fixture'].includes(token))throw Error('invalid');return {token,scopes:['countervault:read','countervault:write'],clientId:token,resource:new URL(this.resource),extra:{grantId:token}};},
    async backendSession(){return 'synthetic_session';},
    async requestAccount(_session,path,options={}){
      if(options.method==='POST'){writes++;assert.equal(options.body.contentOrigin,'user_authored');return {record:{id:recordId,source_type:'typed_note',metadata:{title:'Statement'},sha256:'a'.repeat(64)}};}
      return {folder:{id:folderId,title:'Synthetic'},records:[{id:recordId,source_type:'typed_note',tier:'record',content_origin:'user_authored',storage_mode:'stored',content_stored:true,metadata:{text:'My statement'}},{id:'external',source_type:'drive',tier:'record',content_origin:'external',storage_mode:'linked',content_stored:false}],receipts:[]};
    }};
  const listener=createApp({provider}).listen(0,'127.0.0.1');await new Promise(r=>listener.once('listening',r));
  try{for(const host of ['claude','chatgpt']){
    const client=new Client({name:host+'-conformance',version:'1'});
    try{
      await client.connect(new StreamableHTTPClientTransport(new URL('http://127.0.0.1:'+listener.address().port+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+host+'_fixture'}}}));
      const read=await client.callTool({name:'get_folder',arguments:{folder_id:folderId}});
      assert.deepEqual(read.structuredContent.records.map(r=>[r.tier,r.content_origin]),[['record','user_authored'],['record','external']]);
      assert.deepEqual(read.structuredContent.records.map(r=>[r.storage_mode,r.content_stored]),[['stored',true],['linked',false]]);
      const args={folder_id:folderId,title:'Statement',text:'My statement',request_id:host+'_request_001'};
      const saved=await client.callTool({name:'save_note',arguments:{...args,text_origin:'user_authored'}});
      assert.equal(saved.structuredContent.saved,true);assert.equal(saved.structuredContent.record.content_origin,'user_authored');
      const before=[writes,operations];
      const hostResult=await client.callTool({name:'save_note',arguments:{...args,text_origin:'host_assistant'}});
      assert.equal(hostResult.structuredContent.saved,false);assert.equal(hostResult.structuredContent.tier,'agent_interpretation');assert.deepEqual([writes,operations],before);
      const missing=await client.callTool({name:'save_note',arguments:args});assert.equal(missing.isError,true);assert.deepEqual([writes,operations],before);
    }finally{await client.close();}
  }}finally{await new Promise(r=>listener.close(r));}
});
