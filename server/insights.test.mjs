import test from 'node:test';
import assert from 'node:assert/strict';
import {registerInsightsTools} from './insights-tools.mjs';
const id='11111111-1111-4111-8111-111111111111';
function fixture(scopes){
 const tools=new Map(),calls=[];
 registerInsightsTools({registerTool(name,metadata,handler){tools.set(name,{metadata,handler});}}, {
  issuer:'https://countervault-mcp-production.up.railway.app/',
  async backendSession(){calls.push('session');return 'private';},
  async requestAccount(session,path){assert.equal(session,'private');calls.push(path);return {tier:'agent_interpretation',reports:[{id,summary:'Interpretation'}],countervault_url:'https://countervault.co/?insights=1'};}
 },scopes?{scopes}:undefined);
 return {tools,calls};
}
test('Insights tools advertise explicit permission and reject old scopes before accessing any account',async()=>{
 for(const scopes of [undefined,[],['countervault:read'],['countervault:insights']]){
  const {tools,calls}=fixture(scopes);assert.equal(tools.size,3);
  for(const {metadata,handler} of tools.values()){
   assert.deepEqual(metadata._meta.securitySchemes,[{type:'oauth2',scopes:['countervault:read','countervault:insights']}]);
   assert.equal(metadata.annotations.readOnlyHint,true);assert.equal(metadata.annotations.destructiveHint,false);
   const result=await handler({report_id:id,offset:0,limit:10});assert.equal(result.isError,true);
   assert.match(result._meta['mcp/www_authenticate'][0],/countervault:insights/);
  }
  assert.deepEqual(calls,[]);
 }
});
test('Insights tools use fixed read endpoints and preserve interpretation labels and web controls',async()=>{
 const {tools,calls}=fixture(['countervault:read','countervault:insights']);
 const summary=await tools.get('get_insights').handler({project_id:id,offset:0,limit:10});
 assert.equal(summary.structuredContent.tier,'agent_interpretation');assert.equal(summary.structuredContent.reports.length,1);assert.equal(summary.structuredContent.next_offset,null);
 await tools.get('get_report').handler({report_id:id});await tools.get('insights_status').handler({});
 assert.deepEqual(calls,['session','/api/assistant/insights/projects/'+id,'session','/api/assistant/insights/reports/'+id,'session','/api/assistant/insights/status']);
 assert.match(tools.get('get_report').metadata.description,/from_user_statement/);
 assert.match(tools.get('insights_status').metadata.description,/cannot perform/);
});
