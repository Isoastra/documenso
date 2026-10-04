// native.ts
import { randomUUID, createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { getSignedCookie } from "hono/cookie";
import { HTTPException } from "hono/http-exception";
import { createScimProvider, ScimError, normalizeWorkforceGrants } from "@isoastra/fleet-scim";
import { createPostgresScimAdapter, FLEET_WORKFORCE_SCIM_MIGRATION } from "@isoastra/fleet-scim/postgres";
var { Pool } = pg;
var issuer = "https://auth.isoastra.com";
var scope = { applicationId: "documenso", scopeId: "signing:production", issuer };
var protectedSubjects = /* @__PURE__ */ new Map([["388597630173413379", "ronit@isoastra.com"], ["388644017279107075", "support@isoastra.com"]]);
var selfGrant = [{ role: "workforce-self", resource: scope.scopeId }];
var migration = FLEET_WORKFORCE_SCIM_MIGRATION + `
CREATE TABLE IF NOT EXISTS documenso_workforce_user (
 user_id integer PRIMARY KEY REFERENCES "User"(id) ON DELETE RESTRICT,
 issuer text NOT NULL, subject text NOT NULL, active boolean NOT NULL DEFAULT false,
 grants jsonb NOT NULL DEFAULT '[]', revocation_epoch bigint NOT NULL DEFAULT 0,
 UNIQUE(issuer, subject)
);
ALTER TABLE "Session" ADD COLUMN IF NOT EXISTS "workforceEpoch" bigint;
CREATE OR REPLACE FUNCTION documenso_workforce_identity_guard() RETURNS trigger AS $$ BEGIN
 IF TG_OP='DELETE' OR NEW.user_id<>OLD.user_id OR NEW.issuer<>OLD.issuer OR NEW.subject<>OLD.subject
 THEN RAISE EXCEPTION 'workforce identity is immutable'; END IF; RETURN NEW; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS documenso_workforce_identity_guard ON documenso_workforce_user;
CREATE TRIGGER documenso_workforce_identity_guard BEFORE UPDATE OR DELETE ON documenso_workforce_user FOR EACH ROW EXECUTE FUNCTION documenso_workforce_identity_guard();
`;
var equivalent = (a, b) => JSON.stringify(a) === JSON.stringify(b);
var nativeAdapter = () => ({
  async resolveUser(tx, input) {
    if (protectedSubjects.has(input.principal.subject)) {
      throw new ScimError(403, null, "Protected operator identity");
    }
    const existing = await tx.query("SELECT user_id FROM documenso_workforce_user WHERE issuer=$1 AND subject=$2 FOR UPDATE", [input.principal.issuer, input.principal.subject]);
    if (existing.rows[0]) {
      return String(existing.rows[0].user_id);
    }
    if ((await tx.query(`SELECT 1 FROM "Account" WHERE provider='oidc' AND "providerAccountId"=$1`, [input.principal.subject])).rows.length) {
      throw new ScimError(409, "uniqueness", "Legacy native identity requires explicit migration");
    }
    const id = randomUUID();
    const user = await tx.query(`INSERT INTO "User"(email,name,"emailVerified","updatedAt",roles,"identityProvider",disabled) VALUES($1,$2,now(),now(),ARRAY['USER']::"Role"[],'OIDC',true) RETURNING id`, ["workforce-" + id + "@identity.invalid", input.userName]);
    const userId = String(user.rows[0].id);
    await tx.query("INSERT INTO documenso_workforce_user(user_id,issuer,subject) VALUES($1,$2,$3)", [userId, input.principal.issuer, input.principal.subject]);
    await tx.query(`INSERT INTO "Account"(id,"userId",type,provider,"providerAccountId") VALUES($1,$2,'oauth','oidc',$3)`, [randomUUID(), userId, input.principal.subject]);
    return userId;
  },
  async applyUser(tx, input) {
    await tx.query("SELECT user_id FROM documenso_workforce_user WHERE user_id=$1 FOR UPDATE", [input.userId]);
    const business = await tx.query('SELECT 1 FROM "Organisation" WHERE "ownerUserId"=$1 UNION ALL SELECT 1 FROM "OrganisationMember" WHERE "userId"=$1 LIMIT 1', [input.userId]);
    if (business.rows.length) {
      throw new ScimError(409, null, "Unexpected native business membership requires explicit repair");
    }
    await tx.query("UPDATE documenso_workforce_user SET active=$2,grants=$3::jsonb,revocation_epoch=$4 WHERE user_id=$1", [input.userId, input.active, JSON.stringify(input.active ? input.grants : []), input.revocationEpoch]);
    await tx.query(`UPDATE "User" SET name=$2,disabled=$3,password=NULL,roles=ARRAY['USER']::"Role"[],"updatedAt"=now() WHERE id=$1`, [input.userId, [input.name?.givenName, input.name?.familyName].filter(Boolean).join(" ") || input.userName, !input.active]);
    if (input.revoke) {
      await tx.query('DELETE FROM "Session" WHERE "userId"=$1', [input.userId]);
      await tx.query('DELETE FROM "ApiToken" WHERE "userId"=$1', [input.userId]);
      await tx.query('DELETE FROM "PasswordResetToken" WHERE "userId"=$1', [input.userId]);
      await tx.query('DELETE FROM "VerificationToken" WHERE "userId"=$1', [input.userId]);
      await tx.query('DELETE FROM "Passkey" WHERE "userId"=$1', [input.userId]);
      await tx.query('UPDATE "Account" SET access_token=NULL,refresh_token=NULL,id_token=NULL,password=NULL WHERE "userId"=$1', [input.userId]);
      await tx.query('UPDATE "Webhook" SET enabled=false WHERE "userId"=$1', [input.userId]);
    }
    return { sessions: true, tokens: true, delegations: true };
  },
  async readUser(tx, input) {
    const result = await tx.query(`SELECT w.*, u.disabled, u.roles::text[] AS roles, u.password,
   EXISTS(SELECT 1 FROM "Organisation" WHERE "ownerUserId"=u.id) OR EXISTS(SELECT 1 FROM "OrganisationMember" WHERE "userId"=u.id) OR EXISTS(SELECT 1 FROM "ApiToken" WHERE "userId"=u.id) OR EXISTS(SELECT 1 FROM "Passkey" WHERE "userId"=u.id) OR EXISTS(SELECT 1 FROM "Webhook" WHERE "userId"=u.id AND enabled) AS drift
   FROM documenso_workforce_user w JOIN "User" u ON u.id=w.user_id WHERE w.user_id=$1 FOR UPDATE OF w,u`, [input.userId]);
    const row = result.rows[0];
    if (!row) {
      return null;
    }
    return { active: row.active === true && row.disabled === false && row.drift === false && row.password === null && equivalent(row.roles, ["USER"]), grants: row.drift ? [] : normalizeWorkforceGrants(row.grants), revocationEpoch: String(row.revocation_epoch) };
  }
});
var adapterFor = (pool2) => createPostgresScimAdapter(pool2, nativeAdapter(), {
  ...scope,
  validateGrant: async (_tx, grant) => grant.role === "workforce-self" && grant.resource === scope.scopeId,
  groupGrants: async (_tx, id) => id === "workforce:signing:production:self" ? selfGrant : null
});
var singleton;
var pool = () => {
  if (!singleton) {
    const url = new URL(process.env.NEXT_PRIVATE_DATABASE_URL);
    for (const key of ["sslmode", "sslcert", "sslkey", "sslrootcert"]) {
      url.searchParams.delete(key);
    }
    singleton = new Pool({ connectionString: url.toString(), max: 5, ...process.env.WORKFORCE_DATABASE_TLS_CA ? { ssl: { rejectUnauthorized: true, ca: readFileSync(process.env.WORKFORCE_DATABASE_TLS_CA, "utf8") } } : {} });
  }
  return singleton;
};
var state = async (userId) => {
  const result = await pool().query(`SELECT w.*,u.disabled,u.roles::text[] AS roles,u.password,
 EXISTS(SELECT 1 FROM "Organisation" WHERE "ownerUserId"=u.id) OR EXISTS(SELECT 1 FROM "OrganisationMember" WHERE "userId"=u.id) OR EXISTS(SELECT 1 FROM "ApiToken" WHERE "userId"=u.id) OR EXISTS(SELECT 1 FROM "Passkey" WHERE "userId"=u.id) OR EXISTS(SELECT 1 FROM "Webhook" WHERE "userId"=u.id AND enabled) AS drift
 FROM documenso_workforce_user w JOIN "User" u ON u.id=w.user_id WHERE user_id=$1`, [userId]);
  return result.rows[0];
};
var allowed = (row) => !!row && row.active && !row.disabled && !row.drift && row.password === null && equivalent(row.roles, ["USER"]) && equivalent(row.grants, selfGrant);
var keyset;
var verifyWithKeys = async (idToken, clientId, nonce, keys) => {
  try {
    const { payload } = await jwtVerify(idToken, keys, { issuer, audience: clientId, algorithms: ["RS256"], requiredClaims: ["exp", "iat", "sub"] });
    if (!nonce || payload.nonce !== nonce || payload.email_verified !== true || typeof payload.sub !== "string" || typeof payload.email !== "string") {
      throw new Error("Verified immutable OIDC identity required");
    }
    return payload;
  } catch {
    throw new HTTPException(403, { message: "Verified immutable OIDC identity required" });
  }
};
var verifyOidc = async (idToken, clientId, nonce) => {
  keyset ??= createRemoteJWKSet(new URL(issuer + "/oauth/v2/keys"));
  return verifyWithKeys(idToken, clientId, nonce, keyset);
};
var oidcLogin = async (subject, email) => {
  if (protectedSubjects.get(subject) === email.toLowerCase()) {
    const existing = await pool().query(`SELECT "userId" FROM "Account" WHERE provider='oidc' AND "providerAccountId"=$1`, [subject]);
    if (!existing.rows[0]) {
      throw new Error("Protected operator requires existing immutable native account");
    }
    return { userId: existing.rows[0].userId, workforce: false };
  }
  const result = await pool().query("SELECT user_id FROM documenso_workforce_user WHERE issuer=$1 AND subject=$2", [issuer, subject]);
  const userId = result.rows[0]?.user_id;
  if (!userId || !allowed(await state(userId))) {
    throw new Error("workforce-unassigned");
  }
  return { userId, workforce: true };
};
var authorizePath = async (userId, path) => {
  if (await state(userId) && path !== "/api/auth/callback/oidc") {
    throw new HTTPException(403, { message: "Workforce requires the managed OIDC authentication path" });
  }
};
var mintSession = async (session, fallback) => {
  const client = await pool().connect();
  try {
    await client.query("BEGIN");
    const result = await client.query("SELECT * FROM documenso_workforce_user WHERE user_id=$1 FOR SHARE", [session.userId]);
    if (!result.rows[0]) {
      await client.query("COMMIT");
      return fallback();
    }
    const current = await state(session.userId);
    if (!allowed(current)) {
      throw new Error("Workforce access revoked");
    }
    await client.query('INSERT INTO "Session"(id,"sessionToken","userId","updatedAt","expiresAt","ipAddress","userAgent","workforceEpoch") VALUES($1,$2,$3,$4,$5,$6,$7,$8)', [session.id, session.sessionToken, session.userId, session.updatedAt, session.expiresAt, session.ipAddress, session.userAgent, current.revocation_epoch]);
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};
var validSession = async (sessionId) => {
  const result = await pool().query('SELECT s."userId",s."workforceEpoch" FROM "Session" s WHERE id=$1', [sessionId]);
  const session = result.rows[0];
  if (!session) {
    return false;
  }
  const current = await state(session.userId);
  return !current || allowed(current) && String(session.workforceEpoch) === String(current.revocation_epoch);
};
var equalToken = (a, b) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length > 0 && x.length === y.length && timingSafeEqual(x, y);
};
var providerFor = (db, write, read) => createScimProvider({ ...scope, baseUrl: "https://sign.isoastra.com/scim/v2", adapter: adapterFor(db), authenticate: async (request) => {
  const supplied = request.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
  return equalToken(supplied, write) || request.method === "GET" && equalToken(supplied, read);
} });
var requestBoundary = async (c, next) => {
  const path = c.req.path;
  if (path === "/scim/v2" || path.startsWith("/scim/v2/")) {
    const provider = providerFor(pool(), readFileSync(process.env.WORKFORCE_SCIM_TOKEN_FILE, "utf8").trim(), readFileSync(process.env.WORKFORCE_SCIM_READ_TOKEN_FILE, "utf8").trim());
    const url = new URL(c.req.raw.url);
    const trustedUrl = new URL(url.pathname + url.search, "https://sign.isoastra.com");
    return provider(new Request(trustedUrl, c.req.raw));
  }
  const bearer = c.req.header("authorization")?.replace(/^Bearer /, "");
  if (bearer) {
    const hash = createHash("sha512").update(bearer).digest("hex");
    const keys = await pool().query('SELECT 1 FROM "ApiToken" k JOIN documenso_workforce_user w ON w.user_id=k."userId" WHERE k.token=$1', [hash]);
    if (keys.rows.length) {
      return c.text("Workforce native API credentials are unavailable", 403);
    }
  }
  const cookieName = process.env.NEXT_PUBLIC_WEBAPP_URL?.startsWith("https:") ? "__Secure-sessionId" : "sessionId";
  const token = await getSignedCookie(c, process.env.NEXTAUTH_SECRET, cookieName);
  if (typeof token !== "string") {
    return next();
  }
  const id = createHash("sha256").update(token).digest("hex");
  const session = await pool().query('SELECT "userId","workforceEpoch","expiresAt" FROM "Session" WHERE id=$1', [id]);
  const native = session.rows[0];
  const current = native && await state(native.userId);
  if (!current) {
    return next();
  }
  if (!allowed(current) || String(native.workforceEpoch) !== String(current.revocation_epoch) || native.expiresAt <= /* @__PURE__ */ new Date()) {
    return c.text("Workforce access revoked", 401);
  }
  if (c.req.method === "GET" && path === "/workforce/me") {
    return c.json({ name: "Managed workforce account", subject: current.subject, scope: scope.scopeId, grants: current.grants });
  }
  if (path === "/api/auth/callback/oidc" || path === "/api/auth/signout") {
    return next();
  }
  return c.text("workforce-profile-scope-only", 403);
};
export {
  adapterFor,
  allowed,
  authorizePath,
  issuer,
  migration,
  mintSession,
  nativeAdapter,
  oidcLogin,
  pool,
  protectedSubjects,
  providerFor,
  requestBoundary,
  scope,
  selfGrant,
  state,
  validSession,
  verifyOidc,
  verifyWithKeys
};
