# RG-004 Independent Acceptance Matrix

This is a test plan for SEC-01–SEC-11 in `docs/decisions/RG-004-security-v1.md` revision 1. It is not evidence that TLS, PKI, authorization or service integration exists. Tests must call the implementation's production TLS verifier and channel/server configuration; a parallel QA verifier alone is not acceptable evidence.

| Case | Input / fault | Required observable result | Evidence boundary |
| --- | --- | --- | --- |
| Valid leaf | Directly signed registered leaf; correct exact URI, role EKU, time window and DER hash | TLS success and exactly one expected RPC dispatch | Proves a generated probe profile only |
| Wrong URI | CA-valid certificate with unregistered or different URI SAN | TLS verification failure; handler count remains zero | Include server pin and client principal paths if driver supports both |
| Wrong leaf pin | Same CA and same URI but a different leaf DER/hash | TLS verification failure; handler count zero | Confirms SEC-01/03/05 pinning, not URI alone |
| SAN ambiguity | No URI SAN, two URI SANs, unknown URI, malformed URI; NUL SAN if constructible | Reject; no fallback to CN or another SAN; handler count zero | State if certificate encoding makes a malformed fixture unrepresentable |
| Wrong EKU/role | CA-valid adapter with serverAuth only; server without serverAuth; replica lacking a required role | Rejection at the relevant handshake/authorization boundary | Keep peer-role checks distinct from TLS protocol identity |
| Unknown CA / malformed chain | Leaf signed by unrelated CA; altered/intermediate chain where applicable | TLS failure and no handler dispatch | Only one root/direct leaf is in v1; do not imply intermediate support |
| Missing client cert | Client connects to REQUIRE_AND_VERIFY server without a certificate | Handshake fails and handler count remains zero | Verify actual configured server credential options |
| Expiry boundaries | notBefore > trusted time; now == notAfter; valid just before notAfter; expired root and expired leaf | Reject invalid cases, accept valid in-window cases | Test injected trusted wall clock; UTC accuracy is not established by fakes |
| Reused channel | Advance fake trusted time past leaf/root validity after channel establishment, then make RPC | Per SEC-07, dispatch/commit revalidation denies expired identity; no quota debit | A handshake-only verifier is insufficient |
| Reconnect / resumption | Force reconnect and, if enabled, TLS session resumption; remove peer leaf metadata or substitute another pin | Exact pin revalidated, or path fails closed; no URI-only/cached fallback | Do not claim session-resumption support from a new full handshake |
| Epoch/slot binding | Valid CA leaf with stale epoch/slot/incarnation registry entry | Startup/readiness rejection or request authorization denial as contract specifies | Requires registry implementation; not proven by certificate SAN alone |
| Registry integrity | Change registered URI/role/hash or policy/manifest digest | Startup refuses readiness | Requires supervisor manifest binding; integration gate |
| Wall-clock trust loss | TIME_ERROR, STA_UNSYNC, STA_CLOCKERR, read failure, observed backward time | Trust-loss latches; service unavailable; no quota `LIMITED` | Junior owns real adjtimex implementation; unit tests do not prove actual VM preflight |
| Secret/log review | Capture verifier, server, client and test logs across success/failure cases | No private keys, credentials, full certificate PEM/DER, or secret file contents appear | Public fingerprints may be logged only if contract explicitly allows |

## Required harness evidence

1. Include a handler invocation counter. For all handshake failures (wrong pin/URI, unknown CA, missing client certificate, wrong cryptographic certificate), it must remain zero. A server-side RPC permission denial can enter the handler and must be reported separately.
2. Record the tested certificate properties independently from the production verifier: DER SHA-256, CA identity, URI SAN set, EKUs, validity interval, and whether the chain is direct. Do not call the production verification function to compute expected results.
3. Capture test logs and assert forbidden PEM markers/private key material are absent. Do not include keys, full certs or credentials in expected-output fixtures.
4. Exercise both client and server custom-verifier paths. A single valid handshake does not verify reconnect, reused-channel expiry, TLS resumption, cache pinning, or adapter revalidation before forwarding.
5. Preserve an explicit pass/unsupported/fail result. An unsupported namespace, clock capability or TLS resumption path is not a pass; for SEC-11 it must reject resumption closed if leaf metadata cannot be validated.

## Scope decision

Component acceptance may cover leaf parsing/pinning, URI, EKU, CA, missing-certificate and initial handshake behavior. Full RG-004 acceptance also requires SEC-04/07 live service authorization and expiry-before-commit/forward, SEC-06 actual Linux VM wall-clock preflight, SEC-01 registry/epoch binding through RG-006, and SEC-11 reused/reconnect/resumption behavior. Never label the security component complete based only on fake-clock TLS unit tests or an in-process successful handshake.
