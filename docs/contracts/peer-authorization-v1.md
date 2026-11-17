# RG-004-B2 peer authentication and authorization contract

**Revision:** 1 · **Date:** 2026-11-17 UTC · **Status:** Selected implementation contract. Current verification is tracked in [B2 evidence](https://github.com/kshiteesh28/DistributedRateGuard/blob/docs/scrum-work-log/docs/evidence/RG-004-B2.md); full RG-004 remains incomplete.  
**Branch:** `feature/RG-004-peer-authorization`, based on B1 head `6366df84903049fde3fd92243b3aa7bd06c43986`.  
**Sources:** PRD 8 PRD-008/024; SRD 5 FR-003/D1/D2/D9; LLD 5 A-02/A-05/§17; [SEC-01–11 revision 2](https://github.com/kshiteesh28/DistributedRateGuard/blob/docs/scrum-work-log/docs/decisions/RG-004-security-v1.md); frozen [admission](https://github.com/kshiteesh28/DistributedRateGuard/blob/feature/RG-004-certificate-registry/proto/rateguard/v1/admission.proto) and [authority](https://github.com/kshiteesh28/DistributedRateGuard/blob/feature/RG-004-certificate-registry/proto/rateguard/v1/authority.proto) messages. PRD/SRD/protobuf fields are unchanged.

## Boundary and ownership

PeerAuthenticator consumes the real server-side gRPC AuthContext, the verified immutable CertificateRegistry and trusted wall-clock provider. It alone constructs an opaque AuthenticatedPeer. AuthorizationResolver owns the same registry, derives its policy exclusively from that snapshot and alone constructs private authorized-operation/request values. These values contain trusted principal/method/tenant/operation/cost and the applicable epoch, digest and replica identity. Authorization is not quota ALLOW, a credit allocation or a forwarding permit.

A token belongs to the exact registry instance that created it; transfer to another instance fails closed, including byte-identical independently loaded snapshots. This is a local capability rule, not wire identity. Registry ownership survives caller input destruction and value copies/moves; no public default constructor or arbitrary-principal constructor exists. The injected wall-clock provider must outlive its authenticator/resolver; tokens do not reference that provider.

No function creates quota state, performs RPC routing, forwards a request, debits a bucket or emits a grant. The caller's actual commitment phase is never inferred by an authentication failure. Runtime services must revalidate immediately before commit/pregrant/preforward in later integration.

## Transport authentication

Production callers must supply ServerContext::auth_context() from the trusted gRPC connector. Never manufacture it from request data or install an AuthMetadataProcessor that rewrites the protected TLS/URI/leaf properties. Synthetic contexts are internal test seams, not evidence of a real handshake.

Require IsPeerAuthenticated() and exactly one of each property:

| Property | Required value/bound |
| --- | --- |
| transport_security_type | Exact `tls`, the pinned experimental TLS connector's type |
| peer_uri | Exact registered ASCII URI, 1–256 bytes, no NUL |
| x509_pem_cert | One strict public leaf PEM, at most 64 KiB; no NUL or unrelated prefix/trailing data |

Reject missing/ambiguous/malformed metadata. Do not use request headers, CN, GetPeerIdentity(), SPIFFE convenience properties or certificate-chain PEM as identity fallbacks. Decode the leaf, hash its DER with SHA-256 and match the registry's exact URI/pin. The registry already validated that exact certificate's role, profile and SAN.

At every Authenticate invocation, sample trusted UTC and require healthy time plus root and selected peer validity `notBefore <= now < notAfter`. Resolver samples again on every Resolve, preventing reuse of an authenticated token after expiry. Check the selected caller, not every unrelated principal. Failure latches/fencing remain the clock/service/supervisor responsibilities; no instantaneous epoch-wide stop is implied.

Pinned primary evidence: [AuthContext API](https://github.com/grpc/grpc/blob/v1.51.1/include/grpcpp/security/auth_context.h), [property constants](https://github.com/grpc/grpc/blob/v1.51.1/include/grpc/grpc_security_constants.h), [TLS connector](https://github.com/grpc/grpc/blob/v1.51.1/src/core/lib/security/security_connector/tls/tls_security_connector.cc), [property population](https://github.com/grpc/grpc/blob/v1.51.1/src/core/lib/security/security_connector/ssl_utils.cc). Leaf availability on reconnect/resumption still requires separate evidence; absence fails closed.

## Authorization and binding

| RPC | Caller and policy gate | Trusted result |
| --- | --- | --- |
| Admission.CheckAdmission | Adapter; permitted configured tenant/operation; either immutable epoch mode | Cost from policy; exact attempt/epoch/digest binding |
| Authority.StrictCheck | Replica with a registered fixed slot/incarnation; permitted pair; STRICT policy only | Cost and replica identity from policy; request has no slot field |
| Authority.AcquireCredit | Replica with permitted pair; CREDIT policy only | Exact request slot/incarnation, nonzero sequence and configured trigger cost |

Authority principals are server identities and cannot call these methods. Resolve selectors against known immutable tenant/operation records, then their permission pair. Never insert unknown records. Enforce ASCII identifier syntax, 16-byte attempt/epoch/incarnation IDs, 32-byte digest, exact active request epoch/digest and the existing 16 KiB decoded-message cap. AcquireCredit's slot/incarnation must equal the authenticated replica's configured identity; its trigger cost must exactly equal policy cost. CheckAdmission has no supplied-cost field; unknown protobuf fields and metadata cannot override policy cost. Preserve frozen wire fields and enum values.

## Selected error interpretations

These implementation defaults close unspecified per-request classifications without changing release/product behavior:

| Condition | Disposition |
| --- | --- |
| Missing/untrusted/ambiguous transport identity, wrong leaf pin, expired/not-yet-valid credential, token from another registry | UNAUTHENTICATED |
| Recognized caller with wrong method role or configured but unauthorized pair | PERMISSION_DENIED |
| Unknown tenant/operation, malformed fields/widths, stale request epoch/digest, incorrect credit slot/incarnation/cost, zero sequence, method/mode mismatch | INVALID_ARGUMENT |
| Clock trust loss or internal configuration/crypto/resource dependency failure | Application UNAVAILABLE on gRPC OK |

Request-binding errors follow the verified RG-001 validation helpers. The method/mode gate is an explicit fail-closed default: StrictCheck cannot implement a credit fallback, and AcquireCredit cannot allocate in a strict epoch. There is no caller-supplied mode or adaptive grant choice.

The 16 KiB transport receive limit is enforced before decoding by future server wiring; its gRPC RESOURCE_EXHAUSTED is distinct from the defense-in-depth post-decode INVALID_ARGUMENT check. B2 failure objects contain only bounded reasons/dispositions. Future handlers preserve actual NotCommitted/Possible/Committed phase, never refund, and must not turn dependency failure into LIMITED. INVALID/UNAUTHENTICATED enum values remain frozen but are not emitted as successful decision responses.

## Acceptance and evidence

| ID | Required evidence |
| --- | --- |
| B2-AC01 | Actual mTLS RPC exposes the required properties and validates registered URI/leaf pins; negative identities never reach the fixture state port. |
| B2-AC02 | Positive adapter/replica mapping and negative role/pair/epoch/digest/slot/incarnation/cost/mode cases match the table, with zero state-port calls on rejection. |
| B2-AC03 | Fake trusted UTC crosses root/leaf validity on an established TLS connection; verification count/connection evidence excludes a new handshake. Cached-token Resolve also rejects expiry. |
| B2-AC04 | Opaque construction, copies/moves/input lifetimes, metadata/payload caps and bounded reason-only failures are verified; PEM/keys are never diagnostic output. |
| B2-AC05 | Independent expected permission/cost fixtures and separately compiled unsafe variants detect widened permission/cost or pin checks; normal positive controls pass first. |

Senior owns transport extraction; Junior owns resolver implementation; Tester owns independent fixtures/spy/defect checks; Master integrates and records exact CI evidence. Synthetic policy variants may grant a replica a pair, but the original policy-v1 golden fixture remains unchanged.

Full RG-004 AC01 needs service integration; AC02 still needs precommit/preforward, reconnect/resumption and fenced rotation; AC03 needs real event/export privacy. Supervisor, quota service, deployment and all numerical release gates remain open.
