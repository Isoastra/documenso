# Native workforce production qualification

Release `documenso:workforce-20261003-3`, image SHA256
`4d8f811f771f992051a48f2a6f7a512b97e86b1945eaecfc1bb76bd948669d76`,
uses the frozen v2.17.0 runtime and the native cookie-predicate fix from
[source PR4](https://github.com/Isoastra/documenso/pull/4).
The [live browser receipt](live-browser-receipt.json) records actual production
HTTP observations at `https://sign.isoastra.com`; no cookies, credentials, codes
or MFA secrets are included. The four screenshots were viewed before committing.

| Observation | Result |
| --- | --- |
| Real native OIDC-issued cookie, explicit `workforce-self` on `signing:production` | `/workforce/me` 200 |
| Documents, API v1/v2 documents, admin, settings, teams | All six paths 403 |
| Native deactivation/readback | Inactive, empty direct/effective grants, epoch1, sessions/tokens/delegations acknowledged |
| Previously issued cookie after revocation | Profile unavailable; document browser redirects to `/signin` |
| Repeated original ZITADEL password/MFA callback after revocation | 403 `workforce-unassigned` |
| Fresh never-provisioned ZITADEL password/MFA callback | 403 `workforce-unassigned` |

The first observed existing-cookie denial was 44.390 seconds after the recorded
native acknowledgment. This is the observation interval, not a measured maximum
revocation delay. Deleted native sessions follow the application's stock
unauthenticated behavior: profile404, product sign-in redirect and unauthenticated
API rejection. It is not reported as a uniform401 response.

[Scoped profile](scoped-profile.png), [fresh unknown denial](fresh-unknown-denied.png),
[revoked browser login](revoked-login.png), [revoked callback](revoked-callback.png).

The separate [isolated actual-image receipt](isolated-image-receipt.json) and
[reproducible image fixture](../../../workforce/image-fixture/README.md) cover
PostgreSQL18, all163 frozen image migrations, native additive schema, actual Hono
OIDC/session/router modules, signed token failures, native session/OAuth/API-key
revocation and owner/customer/organisation/service-key preservation. HTTP and both
HTTPS native cookie modes passed. Its test-only IdP transport is distinct from
the real production ZITADEL callbacks recorded above.

The supported workforce grant is profile-only. Signing, documents, organisation,
team, administrator and API credential scopes remain unavailable. Existing
protected operators and customer signing records remain outside fleet workforce
provisioning. No Aakash Documenso assignment was made.
