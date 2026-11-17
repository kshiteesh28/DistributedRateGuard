# RG004-B2 independent QA matrix (pre-implementation)

## Scope and evidence boundary

Exercise the production `PeerAuthenticator` and `AuthorizationResolver` from a real gRPC C++ server handler using the pinned gRPC/OpenSSL toolchain, a real TLS `grpc::AuthContext`, the verified B1 immutable registry, the frozen policy snapshot, and an injectable trusted UTC source. The handler fixture may use a spy state port, but must call the production security components first. This proves only the authenticated identity and authorization component path; it does not prove the complete admission/authority, epoch fencing, supervisor, resumption, or performance path.

Transport failures during TLS handshake are not expected to produce a structured application gRPC status. Assert they do not invoke the handler or state port. For calls that reach the handler, assert precise gRPC status and zero state-port calls on auth/policy errors. Never print PEM, keys, URI identities, raw OpenSSL errors, or tenant values.

Pinned AuthContext properties for the gRPC 1.51.1 TLS connector: `IsPeerAuthenticated()==true`, transport security type `tls`, URI property `peer_uri` (`GRPC_PEER_URI_PROPERTY_NAME`), and actual presented leaf property `x509_pem_cert` (`GRPC_X509_PEM_CERT_PROPERTY_NAME`). Require exactly one value for each property. Inspect values in memory only. Do not depend on full-chain PEM or use request selectors as caller identity. `PeerAuthenticator::Authenticate(const grpc::AuthContext&)` should return an opaque token that owns `shared_ptr<const CertificateRegistry>`; it independently checks URI and DER leaf pin against that registry and fresh trusted UTC. `AuthorizationResolver::Resolve` must recheck root+selected leaf validity using fresh trusted UTC, so a cached token cannot outlive notAfter.

## Real gRPC identity/authentication cases

| Case | Expected result | Handler/state evidence |
| --- | --- | --- |
| Registered adapter leaf, exact SAN and DER pin, valid time | Authenticated token for exact URI/adapter role | One handler call; policy resolution allowed only configured pair |
| Missing AuthContext, missing peer URI, missing leaf PEM, duplicate peer URI, malformed or embedded-NUL property | UNAUTHENTICATED | No state-port invocation |
| Registered URI with alternate leaf DER, unknown URI, unregistered valid-CA leaf, wrong role/EKU | TLS rejection before handler where verifier rejects it; otherwise UNAUTHENTICATED | Handler count and state-port count remain zero |
| `peer_uri` differs from URI SAN in the actual leaf | UNAUTHENTICATED | Confirms authenticator binds context properties together rather than trusting either property alone |
| Non-TLS transport or wrong transport-security property | UNAUTHENTICATED | No state-port invocation |
| Valid adapter certificate on the same established channel: first call before expiration, advance injected trusted UTC to notAfter, call again | First succeeds; second UNAUTHENTICATED | Second call is rejected before state port; proves per-call expiry and does not infer it from TLS handshake/reconnect |
| Authenticate while valid, retain token, advance injected clock to notAfter, call AuthorizationResolver with cached token | typed Expired/NotAuthenticated failure | Authorized operation not produced; spy remains zero for this call |
| Clock becomes untrusted between calls | application `UNAVAILABLE` over gRPC OK | No state-port invocation on second call; no quota outcome of LIMITED and no raw transport UNAVAILABLE |

For the same-channel expiry case, record server-side TLS verifier invocation count after the first RPC and assert it remains unchanged for the expired second RPC. Also compare `ServerContext::peer()` and retain the first shared `AuthContext` plus its backing for pointer/property comparison. The fake trusted UTC changes; OS/TLS wall time remains valid. This demonstrates the application guard, not TLS handshake expiry or session resumption.

Also retain a positive authority/replica-authentication fixture for the internal role path where implemented. A replica uses the B1 leaf's exact registered URI, role, DER pin, slot and incarnation; adapter credentials cannot authenticate as replica and vice versa. Use a separate policy fixture that grants one replica a test pair; the unchanged policy-v1 golden fixture has no replica permissions.

## Policy authorization cases

Using `tests/fixtures/policy_v1.json`, whose adapter `spiffe://rateguard.local/adapter/ingress1` permits `(zeta,list)` at cost 2 and `(alpha,read)` at cost 1:

- Both allowed pairs resolve to the policy-owned operation and exact cost, independent of any request-supplied value.
- `(zeta,delete)`, `(alpha,write)`, unknown tenant, unknown operation, and cross-tenant pair attempts cannot call the state port or mutate/create tenant state.
- Adapter used for a replica/authority operation and replica used for adapter admission fail role authorization.
- Attempted client cost field (unknown protobuf field 6) cannot change resolved cost; wire field table currently has no request cost, mode, time, or caller URI. Omitted cost is derived; mismatching internal supplied cost (if resolver API exposes it) is rejected.
- Wrong request epoch/digest, malformed ID width/payload, wrong method/mode, and `AcquireCredit` slot/incarnation/trigger-cost/sequence mismatch return `INVALID_ARGUMENT` before state access. A token from a different registry instance returns `UNAUTHENTICATED`. Record zero state-port calls.
- A decoded protobuf over 16 KiB returns `INVALID_ARGUMENT` in the resolver. Do not claim the future transport receive limit or predecode `RESOURCE_EXHAUSTED` from a direct-handler fixture.
- Resolver tokens are opaque: external caller cannot construct or mutate `AuthenticatedPeer`/`AuthorizedOperation`; token retains the registry/policy snapshot for its lifetime. Drop original owners and confirm token remains valid only for its captured epoch/digest.
- AuthenticatedPeer/AuthorizedOperation/AuthorizedGrant copies and rvalue-expression copies retain the same registry instance. A token created under registry A cannot resolve under byte-identical independent registry B (UNAUTHENTICATED). Resolver derives policy only from its B1 registry; no cross-snapshot policy constructor exists.

For every case, assert outcome/status, commitment `NotCommitted`, no resolver/authority state mutation, and bounded diagnostic category. Successful authorization returns trusted tenant, operation and configured cost exactly; no request-controlled field becomes a trusted identity or cost.

## Required mutant/fault controls

- A test-only mutant that accepts AuthContext URI without checking the actual leaf DER pin must be detected by the same-URI/alternate-leaf case.
- A test-only mutant that skips exact role/pair authorization must be detected by an unauthorized-pair request before state port invocation.
- If a mutant cannot be built without production test hooks, retain direct independent expected-map tests and state the gap; do not call the test result a mutation kill.

## Open behavior decisions to settle before implementation

The frozen contract `docs/contracts/peer-authorization-v1.md` revision 1 selects mappings: unknown tenant/operation, malformed fields/widths, stale request epoch/digest, AcquireCredit slot/incarnation/cost/zero sequence, and method/mode mismatch → `INVALID_ARGUMENT`; configured unauthorized pair/wrong role → `PERMISSION_DENIED`; missing/untrusted context, wrong pin, expiry and mixed-registry token → `UNAUTHENTICATED`; clock/config/crypto/resource dependency → application `UNAVAILABLE` over gRPC OK. CheckAdmission accepts either mode; StrictCheck is STRICT-only; AcquireCredit is CREDIT-only. The RPC receives a protobuf already decoded, so B2 tests only the 16 KiB defense-in-depth `ByteSizeLong` invalid-argument check, not future transport predecode `RESOURCE_EXHAUSTED`.

Replica-to-authority authorization requires a per-replica allowed pair. Use a separate policy fixture granting one registered slot a pair; do not change the policy-v1 golden fixture. The real TLS expiry test and cached-token Resolve test both recheck time; neither proves a quota commit/pre-forward guard or resumed-channel behavior.

## Deferred evidence

No B2 test here proves manifest serialization/authenticity, process fencing, service readiness, real quota commit behavior, client wrapper leaf-expiry checks, reconnect/session-resumption, live revocation/rotation, adapter forwarding-expiry integration, or full RG004 AC01–03. TLS two-RPC reuse is only a prerequisite for the per-call expiry test, not expiry proof by itself.

The independent RPC fixture uses a mutable fake trusted clock to move between
valid, expired, and unhealthy subcases. This is test injection only; resetting
that fake does not model recovery from the production clock's sticky trust
failure and is not evidence of epoch recovery, readiness, or process fencing.
