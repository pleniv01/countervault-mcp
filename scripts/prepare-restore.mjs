import pg from 'pg';import {createOAuthStore} from '../server/oauth-store.mjs';
if(process.env.COUNTERVAULT_RESTORE_QUARANTINE!=='true')throw Error('Schema preparation requires restore quarantine');
const connectionString=process.env.DATABASE_URL;if(!connectionString)throw Error('Set the isolated restore database URL');
const pool=new pg.Pool({connectionString,ssl:connectionString.includes('railway')?{rejectUnauthorized:false}:undefined});
try{await createOAuthStore({pool});console.log('MCP restore schema prepared; no HTTP server or cleanup job started.');}finally{await pool.end();}
