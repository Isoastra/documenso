// Test-only IdP transport. Never include this file in the production image.
import { generateKeyPair, exportJWK, SignJWT } from '/app/node_modules/jose/dist/webapi/index.js';

const pair = await generateKeyPair('RS256');
const jwk = { ...await exportJWK(pair.publicKey), kid: 'fixture', alg: 'RS256' };
const originalFetch = globalThis.fetch;

globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === 'string' ? input : input.url ?? input.toString());
  if (url.origin !== 'https://auth.isoastra.com') {
    return originalFetch(input, init);
  }
  if (url.pathname === '/oauth/v2/keys') {
    return Response.json({ keys: [jwk] });
  }
  if (url.pathname === '/.well-known/openid-configuration') {
    return Response.json({
      authorization_endpoint: 'https://auth.isoastra.com/fixture-authorize',
      token_endpoint: 'https://auth.isoastra.com/fixture-token',
      scopes_supported: ['openid', 'email', 'profile'],
    });
  }
  if (url.pathname !== '/fixture-token') {
    throw new Error('Unexpected fixture IdP path');
  }
  const body = init?.body ?? input.body;
  const params = new URLSearchParams(typeof body === 'string' || body instanceof URLSearchParams
    ? body : await new Response(body).text());
  const claims = JSON.parse(Buffer.from(params.get('code'), 'base64url').toString());
  let token = await new SignJWT({
    sub: claims.sub, email: claims.email, email_verified: claims.email_verified ?? true,
    name: 'Native Fixture', nonce: claims.nonce,
  }).setProtectedHeader({ alg: 'RS256', kid: 'fixture' })
    .setIssuer(claims.issuer ?? 'https://auth.isoastra.com')
    .setAudience(claims.aud ?? 'fixture-client').setIssuedAt().setExpirationTime('5m')
    .sign(pair.privateKey);
  if (claims.invalidSignature) {
    token = token.slice(0, -4) + 'badx';
  }
  return Response.json({ access_token: 'fixture-access', token_type: 'Bearer', expires_in: 300, id_token: token });
};
