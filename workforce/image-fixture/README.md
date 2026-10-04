# Native image qualification

Run `bash workforce/image-fixture/run.sh documenso:workforce-RELEASE` on the native
Linux deployment builder after building the frozen application image. Also run
the deployed HTTPS origin with both native environment predicates:

```sh
bash workforce/image-fixture/run.sh documenso:workforce-RELEASE https://sign.isoastra.com absent
bash workforce/image-fixture/run.sh documenso:workforce-RELEASE https://sign.isoastra.com production
```

The first case must mint and enforce `sessionId`; the second must mint and enforce
`__Secure-sessionId`. Tests send the real signed cookies through the application
HTTP path and assert the actual minted cookie name. This catches a guard that
guesses a secure prefix from HTTPS alone instead of matching the frozen native
`NODE_ENV` predicate. The HTTPS label configures callback/cookie behavior; the
fixture HTTP listener stays inside its disposable Docker network.

Requires
Docker and the PostgreSQL 18 image; the application image supplies Node 22,
Prisma, the compiled auth routes and the native workforce module. The runner
refuses existing fixture container/network names and removes only its own
disposable containers, volumes, network and temporary files on exit.

The test applies every migration from the actual image, then the additive
workforce migration before starting the application. Native Prisma hooks seed
an owner, customer, personal organisations, memberships, teams and a preserved
service key. Requests enter the actual frozen Hono auth/router/session modules,
including the signed OIDC callback and native signed-cookie validation. The
profile and stock product/API boundaries, group removal, deactivation, native
session/OAuth/API-key revocation, immutable subject admission and existing
identity/business preservation are asserted against the real database.

`preload.ts` is test-only: it intercepts IdP discovery, token exchange and JWKS
inside the fixture process and signs RS256 tokens with an ephemeral private key.
It exercises signature, issuer, audience, nonce and email-verification failures
without changing the production verifier. It must never be copied into the
production image or configured through production `NODE_OPTIONS`. The fixture
checks its database hostname before creating any test identities. Fixture tokens
and secrets are deliberate test constants and never grant access to deployed
systems. A pass does not qualify real ZITADEL network callbacks; those must be
tested separately after deployment.
