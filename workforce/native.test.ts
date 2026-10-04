import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { Hono } from 'hono';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { setSignedCookie } from 'hono/cookie';
import { workforceExternalId } from '@isoastra/fleet-scim';
import { adapterFor, pool, migration, issuer, selfGrant, oidcLogin, mintSession, validSession, authorizePath, requestBoundary, providerFor, verifyWithKeys } from './native.js';
const db=pool();after(async()=>db.end());
test('full native schema lifecycle, actual HTTP/cookies, scope and concurrent fences',async()=>{
 await db.query(migration);
 await db.query(`INSERT INTO "User"(email,"updatedAt",roles) VALUES('ronit@isoastra.com',now(),ARRAY['ADMIN','USER']::"Role"[]),('customer@example.invalid',now(),ARRAY['USER']::"Role"[])`);
 const owner=(await db.query('SELECT id FROM "User" WHERE email=\'ronit@isoastra.com\'')).rows[0].id;
 await db.query('INSERT INTO "Account"(id,"userId",type,provider,"providerAccountId") VALUES($1,$2,\'oauth\',\'oidc\',\'388597630173413379\')',[randomUUID(),owner]);
 const baseline=(await db.query('SELECT count(*) FROM "Organisation"')).rows[0].count;
 const adapter=adapterFor(db),principal={issuer,subject:'fixture-managed-workforce'};
 const input={kind:'Users' as const,externalId:workforceExternalId(principal),userName:'customer@example.invalid',active:true,principal,grants:selfGrant,authorityEpoch:'1',desiredVersion:'1'};
 let resource=await adapter.create(input);const userId=Number(resource.id);
 assert.notEqual(resource.provisioningState,'drift');assert.deepEqual(resource.effectiveGrants,selfGrant);
 assert.equal((await db.query('SELECT count(*) FROM "User" WHERE email=\'customer@example.invalid\'')).rows[0].count,'1');
 assert.equal((await db.query('SELECT count(*) FROM "Organisation"')).rows[0].count,baseline);
 assert.match((await db.query('SELECT email FROM "User" WHERE id=$1',[userId])).rows[0].email,/^workforce-.*@identity.invalid$/);
 assert.equal((await oidcLogin(principal.subject,'customer@example.invalid')).userId,userId);
 await assert.rejects(oidcLogin('never-provisioned','customer@example.invalid'),/unassigned/);
 assert.equal((await oidcLogin('388597630173413379','ronit@isoastra.com')).userId,owner);
 await assert.rejects(adapter.create({...input,externalId:workforceExternalId({issuer,subject:'388597630173413379'}),principal:{issuer,subject:'388597630173413379'}}),/Protected/);
 await assert.rejects(authorizePath(userId,'/api/auth/email-password/signin'),/managed OIDC/);
 const token='fixture-cookie-token',sid=createHash('sha256').update(token).digest('hex');
 const session={id:sid,sessionToken:sid,userId,updatedAt:new Date(),expiresAt:new Date(Date.now()+600000),ipAddress:null,userAgent:null};
 await mintSession(session,async()=>{throw new Error('Native binding must own session insertion');});assert.equal(await validSession(sid),true);
 process.env.NEXTAUTH_SECRET='fixture-secret-at-least-32-bytes';process.env.NEXT_PUBLIC_WEBAPP_URL='http://127.0.0.1';
 const app=new Hono();app.get('/fixture-cookie',async c=>{await setSignedCookie(c,'sessionId',token,process.env.NEXTAUTH_SECRET!);return c.text('ok');});app.use(requestBoundary);app.all('*',c=>c.text('stock-route'));
 const cookie=(await app.request('/fixture-cookie')).headers.get('set-cookie')!.split(';')[0];
 const profile=await app.request('/workforce/me',{headers:{cookie}});assert.equal(profile.status,200);assert.deepEqual((await profile.json()).grants,selfGrant);
 for(const path of ['/api/trpc/team.get','/documents','/api/v2/documents','/admin','/settings/security'])assert.equal((await app.request(path,{headers:{cookie}})).status,403);
 const provider=providerFor(db,'write'.repeat(10),'read'.repeat(10));
 const http=async(method:string,path:string,token:string,body?:unknown)=>provider(new Request('https://sign.isoastra.com/scim/v2'+path,{method,headers:{authorization:'Bearer '+token,'content-type':'application/scim+json'},...(body?{body:JSON.stringify(body)}:{})}));
 const folder = await mkdtemp(tmpdir() + '/documenso-scim-http-');
 try {
  await writeFile(folder + '/read', 'read'.repeat(10), { mode: 0o600 });
  await writeFile(folder + '/write', 'write'.repeat(10), { mode: 0o600 });
  process.env.WORKFORCE_SCIM_TOKEN_FILE = folder + '/write'; process.env.WORKFORCE_SCIM_READ_TOKEN_FILE = folder + '/read';
  assert.equal((await app.request('/scim/v2/ServiceProviderConfig', { headers: { authorization: 'Bearer ' + 'read'.repeat(10) } })).status, 200);
 } finally { await rm(folder, { recursive: true }); }
 assert.equal((await http('GET','/ServiceProviderConfig','bad')).status,401);assert.equal((await http('GET','/ServiceProviderConfig','read'.repeat(10))).status,200);assert.equal((await http('POST','/Users','read'.repeat(10),{})).status,401);
 const next={...input,desiredVersion:'2',grants:[]};const concurrent=await Promise.allSettled([adapter.replace(resource.id,next,resource.revision),adapter.replace(resource.id,next,resource.revision)]);
 assert.equal(concurrent.filter(x=>x.status==='fulfilled').length,1);assert.equal(concurrent.filter(x=>x.status==='rejected').length,1);
 resource=(await adapter.get('Users',resource.id))!;assert.equal(await validSession(sid),false);assert.equal((await db.query('SELECT count(*) FROM "Session" WHERE "userId"=$1',[userId])).rows[0].count,'0');assert.ok(resource.revocation?.sessions);
 await assert.rejects(mintSession({...session,id:'disabled-mint',sessionToken:'disabled-mint'},async()=>{}),/revoked/);
 const groupInput={kind:'Groups' as const,externalId:'workforce:signing:production:self',displayName:'Managed profile',members:[resource.id],authorityEpoch:'1',desiredVersion:'1'};
 let group=await adapter.create(groupInput);assert.deepEqual((await adapter.get('Users',resource.id))!.effectiveGrants,selfGrant);
 group=await adapter.replace(group.id,{...groupInput,members:[],desiredVersion:'2'},group.revision);assert.deepEqual((await adapter.get('Users',resource.id))!.effectiveGrants,[]);
 resource=(await adapter.get('Users',resource.id))!;resource=await adapter.replace(resource.id,{...input,desiredVersion:'3'},resource.revision);
 await db.query('UPDATE "User" SET roles=ARRAY[\'ADMIN\']::"Role"[] WHERE id=$1',[userId]);await assert.rejects(oidcLogin(principal.subject,'customer@example.invalid'),/unassigned/);assert.equal((await adapter.get('Users',resource.id))!.provisioningState,'drift');
 resource=await adapter.replace(resource.id,{...input,desiredVersion:'3'},resource.revision);assert.notEqual(resource.provisioningState,'drift');
 resource=await adapter.replace(resource.id,{...input,active:false,grants:[],desiredVersion:'4'},resource.revision);assert.ok(resource.revocation?.tokens);assert.deepEqual(resource.effectiveGrants,[]);
 await assert.rejects(adapter.replace(resource.id,{...input,desiredVersion:'1'},resource.revision), error => (error as any).status === 409);
 assert.deepEqual((await db.query('SELECT roles::text[] AS roles,disabled FROM "User" WHERE id=$1',[owner])).rows[0],{roles:['ADMIN','USER'],disabled:false});
 assert.equal((await db.query('SELECT count(*) FROM "User" WHERE email=\'customer@example.invalid\'')).rows[0].count,'1');
});

test('signed OIDC requires issuer, audience, signature, nonce and verified immutable identity', async () => {
 const pair = await generateKeyPair('RS256');
 const keys = createLocalJWKSet({ keys: [{ ...await exportJWK(pair.publicKey), kid: 'fixture', alg: 'RS256' }] });
 const make = (claims: Record<string, unknown> = {}, tokenIssuer: string = issuer) => new SignJWT({ sub: 'fixture', nonce: 'nonce', email: 'fixture@example.invalid', email_verified: true, ...claims }).setProtectedHeader({ alg: 'RS256', kid: 'fixture' }).setIssuer(tokenIssuer).setAudience('fixture-client').setIssuedAt().setExpirationTime('1m').sign(pair.privateKey);
 assert.equal((await verifyWithKeys(await make(), 'fixture-client', 'nonce', keys)).sub, 'fixture');
 await assert.rejects(verifyWithKeys(await make({}, 'https://untrusted.example.invalid'), 'fixture-client', 'nonce', keys), error => (error as any).status === 403);
 const signed = await make(); const pieces = signed.split('.'); pieces[2] = (pieces[2][0] === 'A' ? 'B' : 'A') + pieces[2].slice(1);
 await assert.rejects(verifyWithKeys(pieces.join('.'), 'fixture-client', 'nonce', keys), error => (error as any).status === 403);
 for (const [claims, aud, nonce] of [[{}, 'wrong-client', 'nonce'], [{}, 'fixture-client', 'wrong-nonce'], [{email_verified:false}, 'fixture-client', 'nonce'], [{sub:undefined}, 'fixture-client', 'nonce']] as const) {
  await assert.rejects(verifyWithKeys(await make(claims), aud, nonce, keys), error => (error as any).status === 403);
 }
});
