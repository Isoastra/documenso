import { readFileSync, writeFileSync } from 'node:fs';
const root = process.argv[2] || '/app/apps/remix/build/server';
function replace(file, before, after) {
 const path = root + '/' + file;
 const text = readFileSync(path, 'utf8');
 if (text.split(before).length !== 2) {
  throw new Error('Unrecognized frozen native boundary: ' + file);
 }
 writeFileSync(path, text.replace(before, after));
}
const auth = 'hono/packages/auth/server/lib/';
const imp = "import * as workforce from '/app/workforce/native.mjs';\n";
for (const file of [auth+'utils/handle-oauth-callback-url.js',auth+'utils/authorizer.js',auth+'session/session.js','hono/server/router.js']) {
 const path=root+'/'+file;
 writeFileSync(path, imp+readFileSync(path,'utf8'));
}
replace(auth+'utils/handle-oauth-authorize-url.js', "url.searchParams.set('prompt', prompt);", "url.searchParams.set('prompt', prompt);\n  if (clientOptions.id === 'oidc') { const nonce = generateState(); url.searchParams.set('nonce',nonce); setCookie(c,'oidc_workforce_nonce',nonce,{...sessionCookieOptions,sameSite:'lax',maxAge:oauthCookieMaxAge}); }");
replace(auth+'utils/handle-oauth-callback-url.js', "  if (email.toLowerCase() === legacyServiceAccountEmail()", "  if (clientOptions.id === 'oidc') { try { const managed = await workforce.oidcLogin(sub,email); await onAuthorize({userId:managed.userId},c); return c.redirect(managed.workforce ? '/workforce/me' : redirectPath,302); } catch { return c.text('workforce-unassigned',403); } }\n  if (email.toLowerCase() === legacyServiceAccountEmail()");
replace(auth+'utils/handle-oauth-callback-url.js', 'const claims = decodeIdToken(tokens.idToken());', "const claims = clientOptions.id === 'oidc' ? await workforce.verifyOidc(idToken,clientOptions.clientId,deleteCookie(c,'oidc_workforce_nonce') || '') : decodeIdToken(tokens.idToken());");
replace(auth+'utils/authorizer.js', '  await assertUserNotDisabledById', '  await workforce.authorizePath(user.userId,c.req.path);\n  await assertUserNotDisabledById');
replace(auth+'session/session.js', '  await prismaWithReplicas.session.create({\n    data: session\n  });', '  await workforce.mintSession(session, async () => { await prismaWithReplicas.session.create({data:session}); });');
replace(auth+'session/session.js', '  const result = await prismaWithReplicas.session.findUnique', "  if (!(await workforce.validSession(sessionId))) return {session:null,user:null,isAuthenticated:false};\n  const result = await prismaWithReplicas.session.findUnique");
replace('hono/server/router.js', 'app.use(contextStorage());', 'app.use(workforce.requestBoundary);\napp.use(contextStorage());');
// RR7 bundle has its own native session validator copy. Patch every loaded copy.
const { readdirSync } = await import('node:fs');
let count=0;
for (const name of readdirSync(root+'/assets')) {
 if (!name.endsWith('.js')) continue;
 const path=root+'/assets/'+name;
 const text=readFileSync(path,'utf8');
 const needle='const validateSessionToken = async (token) => {';
 if (!text.includes(needle)) continue;
 const anchor='  const result = await prismaWithReplicas.session.findUnique({';
 if (text.split(anchor).length!==2) throw new Error('Unknown native RR7 session boundary');
 writeFileSync(path,imp+text.replace(anchor, '  if (!(await workforce.validSession(sessionId))) return {session:null,user:null,isAuthenticated:false};\n'+anchor));
 count++;
}
if(count!==1) throw new Error('Expected one native RR7 session validator, got '+count);
console.log('patched native auth/router/session modules and RR7 validator');
