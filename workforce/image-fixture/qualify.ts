import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { pool } from '/app/workforce/native.mjs';
import { onCreateUserHook } from '/app/apps/remix/build/server/hono/packages/lib/server-only/user/create-user.js';
import { prisma } from '/app/apps/remix/build/server/hono/packages/prisma/index.js';

// A production DSN must never pass this guard, even if this fixture is invoked accidentally.
assert.equal(new URL(process.env.NEXT_PRIVATE_DATABASE_URL).hostname, 'documenso-qualified-pg');
const base = 'http://127.0.0.1:3000';
const userExtension = 'urn:isoastra:params:scim:schemas:extension:workforce:2.0:User';
const groupExtension = 'urn:isoastra:params:scim:schemas:extension:workforce:2.0:Group';
const subject = 'fixture-image-' + randomUUID();
const write = 'fixture-write-native-qualification-token';
const read = 'fixture-read-native-qualification-token';
const cookies = new Map();

const request = async (method, path, body = undefined, bearer = undefined, revision = undefined) => {
  const headers = { origin: base, 'user-agent': 'Native image qualification' };
  if (body !== undefined) {
    headers['content-type'] = path.startsWith('/scim/') ? 'application/scim+json' : 'application/json';
  }
  if (bearer) {
    headers.authorization = 'Bearer ' + bearer;
  }
  if (revision) {
    headers['if-match'] = revision;
  }
  headers.cookie = [...cookies].map(([name, value]) => name + '=' + value).join('; ');
  const response = await fetch(base + path, { method, headers, redirect: 'manual',
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  for (const cookie of response.headers.getSetCookie()) {
    const first = cookie.split(';')[0];
    const split = first.indexOf('=');
    cookies.set(first.slice(0, split), first.slice(split + 1));
  }
  const text = await response.text();
  return { status: response.status, headers: response.headers,
    body: text && response.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text };
};

const login = async (sub, changes = {}) => {
  cookies.clear();
  const authorize = await request('POST', '/api/auth/oauth/authorize/oidc', {});
  assert.equal(authorize.status, 200);
  const params = new URL(authorize.body.redirectUrl).searchParams;
  const claims = { sub, email: 'same-customer@example.invalid', nonce: params.get('nonce'), ...changes };
  const code = Buffer.from(JSON.stringify(claims)).toString('base64url');
  return request('GET', '/api/auth/callback/oidc?' + new URLSearchParams({ code, state: params.get('state') }));
};

const inventory = async () => (await pool().query(`SELECT json_build_object(
 'users',(SELECT json_agg(json_build_object('id',u.id,'email',u.email,'roles',u.roles,'disabled',u.disabled) ORDER BY u.id)
   FROM "User" u WHERE NOT EXISTS(SELECT 1 FROM documenso_workforce_user w WHERE w.user_id=u.id)),
 'organisations',(SELECT json_agg(json_build_object('id',id,'ownerUserId',"ownerUserId") ORDER BY id) FROM "Organisation"),
 'members',(SELECT count(*) FROM "OrganisationMember"), 'teams',(SELECT count(*) FROM "Team"),
 'customerKeys',(SELECT count(*) FROM "ApiToken" k WHERE NOT EXISTS(SELECT 1 FROM documenso_workforce_user w WHERE w.user_id=k."userId")),
 'accounts',(SELECT json_agg(json_build_object('id',a.id,'userId',a."userId",'subject',a."providerAccountId") ORDER BY a.id)
   FROM "Account" a WHERE NOT EXISTS(SELECT 1 FROM documenso_workforce_user w WHERE w.user_id=a."userId"))) AS inventory`)).rows[0].inventory;

try {
  const owner = await prisma.user.create({ data: { email: 'ronit@isoastra.com', name: 'Fixture Owner', roles: ['ADMIN', 'USER'] } });
  const customer = await prisma.user.create({ data: { email: 'same-customer@example.invalid', name: 'Fixture Customer' } });
  await prisma.account.create({ data: { userId: owner.id, type: 'oauth', provider: 'oidc', providerAccountId: '388597630173413379' } });
  await onCreateUserHook(owner);
  await onCreateUserHook(customer);
  const team = await prisma.team.findFirst({ where: { organisation: { ownerUserId: owner.id } } });
  await prisma.apiToken.create({ data: { name: 'Preserved owner service key', token: 'fixture-owned-key', userId: owner.id, teamId: team.id } });
  const before = await inventory();
  assert.equal((await login('388597630173413379', { email: owner.email })).status, 302);
  assert.equal((await request('GET', '/api/auth/session')).body.isAuthenticated, true);
  assert.equal((await request('GET', '/scim/v2/ServiceProviderConfig', undefined, read)).status, 200);
  assert.equal((await request('POST', '/scim/v2/Users', {}, read)).status, 401);
  assert.equal((await login('fixture-unknown')).status, 403);

  const body = { schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', userExtension],
    externalId: JSON.stringify(['https://auth.isoastra.com', subject]), userName: customer.email, active: true,
    name: { givenName: 'Fixture', familyName: 'Workforce' }, [userExtension]: {
      issuer: 'https://auth.isoastra.com', subject, grants: [], authorityEpoch: '1', desiredVersion: '1' } };
  const created = await request('POST', '/scim/v2/Users', body, write);
  assert.equal(created.status, 201);
  const id = created.body.id;
  assert.equal((await login(subject)).status, 403);
  const group = { schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group', groupExtension],
    externalId: 'workforce:signing:production:self', displayName: 'Fixture self', members: [{ value: id }],
    [groupExtension]: { authorityEpoch: '1', desiredVersion: '1' } };
  const membership = await request('POST', '/scim/v2/Groups', group, write);
  assert.equal(membership.status, 201);
  for (const changes of [{ nonce: 'wrong' }, { aud: 'wrong' }, { issuer: 'https://untrusted.invalid' },
    { invalidSignature: true }, { email_verified: false }]) {
    assert.ok((await login(subject, changes)).status >= 400);
  }
  const accepted = await login(subject);
  assert.equal(accepted.status, 302);
  assert.equal(accepted.headers.get('location'), '/workforce/me');
  assert.equal((await request('GET', '/workforce/me')).status, 200);
  for (const path of ['/documents', '/api/v2/documents', '/admin', '/settings/security', '/api/trpc/user.getProfile']) {
    assert.equal((await request('GET', path)).status, 403);
  }
  await pool().query('INSERT INTO "ApiToken"(name,token,"userId","teamId") VALUES($1,$2,$3,$4)',
    ['Fixture workforce API key', createHash('sha512').update('fixture-native-api').digest('hex'), id, team.id]);
  await pool().query('UPDATE "Account" SET access_token=$2,refresh_token=$2,id_token=$2 WHERE "userId"=$1', [id, 'fixture']);
  assert.equal((await request('GET', '/api/v2/documents', undefined, 'fixture-native-api')).status, 403);
  group.members = [];
  group[groupExtension].desiredVersion = '2';
  assert.equal((await request('PUT', '/scim/v2/Groups/' + membership.body.id, group, write, membership.body.meta.version)).status, 200);
  assert.notEqual((await request('GET', '/workforce/me')).status, 200);
  assert.equal((await login(subject)).status, 403);
  const current = (await request('GET', '/scim/v2/Users/' + id, undefined, read)).body;
  body.active = false;
  body[userExtension].desiredVersion = '2';
  const disabled = await request('PUT', '/scim/v2/Users/' + id, body, write, current.meta.version);
  assert.equal(disabled.status, 200);
  assert.equal(disabled.body[userExtension].provisioningState, 'confirmed');
  assert.equal(disabled.body[userExtension].revocation.revision, disabled.body[userExtension].revocationEpoch);
  assert.equal((await login(subject)).status, 403);
  assert.deepEqual(await inventory(), before);
  for (const table of ['Session', 'ApiToken']) {
    assert.equal((await pool().query('SELECT count(*) AS n FROM "' + table + '" WHERE "userId"=$1', [id])).rows[0].n, '0');
  }
  assert.equal((await pool().query('SELECT count(*) AS n FROM "Account" WHERE "userId"=$1 AND (access_token IS NOT NULL OR refresh_token IS NOT NULL OR id_token IS NOT NULL)', [id])).rows[0].n, '0');
  assert.equal((await pool().query('SELECT count(*) AS n FROM "Account" WHERE "providerAccountId"=$1', ['fixture-unknown'])).rows[0].n, '0');
  console.log(JSON.stringify({ result: 'passed', userId: id, extension: disabled.body[userExtension], preserved: before,
    limits: ['Disposable PostgreSQL only; test-only IdP fetch transport; real ZITADEL network not qualified.'] }));
} finally {
  await pool().end();
  await prisma.$disconnect();
}
