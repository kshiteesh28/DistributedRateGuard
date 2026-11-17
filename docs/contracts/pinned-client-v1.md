# RG-004-B3 pinned client and validity-guard contract

**Revision:** 1 · **Date:** 2026-11-17 UTC · **Status:** Selected implementation contract. Current delivery/evidence is tracked in the [live work log](https://github.com/kshiteesh28/DistributedRateGuard/blob/docs/scrum-work-log/docs/SCRUM-WORK-LOG.md).  
**Branch:** `feature/RG-004-client-guards`, based on verified B2 head `20210d5fbabcd891dbbb20ab89eca26f3a73a1db`.  
**Sources:** PRD 8 PRD-008/024; SRD 5 D1/D2/D6/D9 and FR-003; LLD 5 A-02/A-05/§17; SEC-01–11 revision 2. Requirements/protobufs are unchanged.

## Scope and owners

B3 supplies a stateless certificate/time guard, a sealed typed gRPC client, and separate reconnect/resumption evidence. Junior owns ClientCallGuard; Senior owns PinnedPeerRpcClient; Tester independently owns real TLS and native session qualification; Master records decisions, integrates and verifies.

No function commits quota, allocates credits, forwards a request, rotates credentials, fences processes or asserts an active epoch. Actual service dispatch/precommit/pregrant and adapter ALLOW/deadline/preforward composition remain with their service stories. Trusted clock providers must outlive guards/clients.

## Guard and proof semantics

Create one immutable guard binding from a B1 CertificateRegistry, trusted wall clock, local URI, expected server URI and purpose:

| Purpose | Local role | Exact expected server role |
| --- | --- | --- |
| AdapterToReplicaAdmission | Adapter | Replica |
| ReplicaToAuthority | Replica | Authority |

Validate registry/policy epoch, authority identity, root digest and canonical digest. Resolve URIs only through immutable policy/registry; never from headers. Require bounded ASCII URIs and exact registered identities, including replica slot/incarnation provenance.

ValidateBeforeCall samples healthy-before/Now/healthy-after, checks a legal integer UTC tuple, and requires root, OWN client leaf and selected server leaf validity `notBefore <= now < notAfter`. Private PreparedClientCall retains the exact guard binding. ValidateBeforeForward repeats current checks, rejects foreign bindings and a sample earlier than the prepared sample, and returns only a fresh time-validation proof.

Proofs use shared immutable payloads with exception-safe complete copies/assignments; rvalues do not detach ownership. They do not imply a timely ALLOW, known commitment, active epoch or forwarding eligibility. Guard failures contain bounded local CredentialInvalid/ApplicationUnavailable classifications, no gRPC status, secret text or inferred commitment.

## Sealed client construction

PinnedPeerRpcClient constructs its TLS credentials, channel and generated stubs internally. It exposes no raw credentials/channel/stub or arbitrary RPC callback. Configuration fixes one target, purpose, local principal and expected server for the object's lifetime.

Root/leaf/private-key PEM inputs are individually capped at 64 KiB. Parse exactly one matching object with only surrounding whitespace, no NUL/extra blocks. Bind root and local leaf DER SHA-256 to the B1 registry; verify the local private key is present and matches the leaf. Reject encrypted keys without a password callback/prompt. Root signing keys are never inputs. Configuration and crypto failures expose bounded reasons only; key/cert text and OpenSSL diagnostics never enter logs/artifacts.

Construct ordinary chain verification plus PinnedPeerVerifier for the exact expected server URI/role/leaf pin. Use static in-memory credentials, a private local subchannel pool, retry=0 and hedging=0. No caller-supplied channel arguments, service fallback, alternative server or session-cache option is accepted.

Implementation bounds: send/receive messages and metadata each 16 KiB. These are finite client limits, not measured capacity. Caller deadlines must be finite and future; Authority StrictCheck/AcquireCredit use `min(caller deadline, now + 20 ms)` per D6. Admission uses the supplied finite deadline; the 50 ms benchmark deadline is not silently made a universal API maximum. gRPC transport deadlines do not replace the actual quota transition's shared CLOCK_MONOTONIC checks.

## Exact-once invocation and raw results

Public methods are CheckAdmission, StrictCheck and AcquireCredit. Enforce purpose and immutable mode: admission supports either epoch mode; StrictCheck requires STRICT; AcquireCredit requires CREDIT. Each method performs fresh preflight and invokes the generated stub at most once. No automatic strict retry, hedging or mode fallback exists.

Return one of:

- **NotSent:** stub was never invoked for this attempt, with no fabricated gRPC status/response. This establishes NotCommitted only for this attempt; it cannot erase a caller's earlier commitment.
- **Invoked:** preserve raw gRPC status when available, raw response and private prepared proof. These are not trusted ALLOW/grant/commitment results. An exception after stub entry remains Invoked with uncertain transport state.

Allocate invocation storage before stub entry; after invocation, publication/failure handling must not allocate a replacement that could falsely return NotSent. One immutable payload prevents copy failure from mixing response/proof generations. Post-response trust failure never discards or rewrites the raw reply.

The client's ValidateBeforeForward checks only certificate/time binding for its adapter invocation. The adapter must separately require valid response correlation, timely ALLOW, active epoch and its actual forwarding gate. This API never forwards. Local downstream trust failure becomes dependency unavailability at the caller's service boundary, not a forged server UNAUTHENTICATED response or quota LIMITED.

## Reconnect and session qualification

Production channels omit session caching. The pinned v1.51.1 source configures client cache behavior only with an explicit cache argument; qualification must independently verify no-cache fresh reconnect behavior.

A test-only native fixture may attach one bounded LRU entry using grpc_ssl_session_cache_create_lru/create_channel_arg and ChannelArguments::SetPointerWithVtable. Keep registry, target/SNI and credentials fixed while creating a distinct local-pool transport; retain cache ownership, close old channel/stub and keep server alive. Same-channel RPC reuse is not TLS resumption.

Record new transport/endpoint, verifier counts and actual GRPC_SSL_SESSION_REUSED_PROPERTY on both sides, plus required peer URI and leaf PEM/pin evidence. Full-chain PEM is not a substitute: OpenSSL can omit it on resumed sessions.

| Qualification state | Interpretation |
| --- | --- |
| QUALIFIED | Actual new transport reports reuse=true and exact leaf/pin verification remains demonstrated |
| NOT_DEMONSTRATED | Bounded attempts did not establish actual resumption; never count as passing enablement |
| UNSAFE / insufficient identity evidence | Fail closed; resumed path stays disabled and cannot be claimed |

No-cache fresh/forced-reconnect checks are required passing tests. A diagnostic collection step can succeed while reporting NOT_DEMONSTRATED; evidence must retain that distinction. Session caching remains unavailable through the production factory, even if the SDK probe qualifies it. Enabling production resumption needs explicit subsequent review/change control.

Primary sources: [cache C API](https://github.com/grpc/grpc/blob/v1.51.1/include/grpc/grpc_security.h), [channel arguments](https://github.com/grpc/grpc/blob/v1.51.1/include/grpc/impl/codegen/grpc_types.h), [TLS credentials cache consumption](https://github.com/grpc/grpc/blob/v1.51.1/src/core/lib/security/credentials/tls/tls_credentials.cc), [TSI session implementation](https://github.com/grpc/grpc/blob/v1.51.1/src/core/tsi/ssl_transport_security.cc), [auth property mapping](https://github.com/grpc/grpc/blob/v1.51.1/src/core/lib/security/security_connector/ssl_utils.cc).

## Acceptance and limits

| ID | Required evidence |
| --- | --- |
| B3-AC01 | Independent root/client/server validity boundaries, clock failure/invalid/backwards samples, exact binding and immutable proof lifetimes |
| B3-AC02 | Actual sealed client calls at both endpoint roles; local expiry/trust/method/deadline failures are NotSent with unchanged handler count |
| B3-AC03 | Exact-once stub invocation, raw transport/reply retention and fresh post-response time rejection without invented forwarding/commitment |
| B3-AC04 | Forced fresh reconnect and endpoint substitution verify exact pins; missing/changed leaf identity fails closed |
| B3-AC05 | Versioned session probe distinguishes QUALIFIED from NOT_DEMONSTRATED/UNSAFE using actual session metadata; production cache remains disabled |
| B3-AC06 | Real crypto/config bounds and key mismatches, independent defect controls, normal/clean Linux tests and targeted sanitizers |

Full RG-004 AC01–03, deployment, real event/export privacy, actual commit/forward/fencing, performance and formal-assurance gates remain open. No benchmark, implementation beyond this input, or production-readiness claim is implied.
