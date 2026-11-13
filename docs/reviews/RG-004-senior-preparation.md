# Senior Dev preparation — historical review input

**Status:** Requirements/source research only. Open questions in this handoff are superseded where resolved by [Master security decisions revision 1](../decisions/RG-004-security-v1.md). No security implementation or test result is claimed.

# RG-004 pre-implementation contract extraction

## Sources inspected

- PRD revision 8, main, blob 32dbcaad040f7170afdd6a3538430d5b07d05e46
- SRD revision 5, main, blob 74a60f3a010edffbb883302a05b0e8d41c263ea
- LLD revision 5, main, blob a6236628f34b4c6e21aa56cf3fcbcf2cdde3e9db
- Frozen policy-v1 revision 1, feature/RG-002-policy-arithmetic, blob 3ea68e606ea563eef08d50d73d933a88529b8e6a

No code or tests were run for RG-004, and no GitHub writes were made.

## Binding identity and authorization contract

### Identity and epoch trust

- Each epoch has immutable policy, one authority incarnation, a trust-root fingerprint, and registered replica identities. The policy binds SHA-256 of the CA root certificate’s DER bytes, not PEM formatting or private material. RG-004 must compare the actual configured CA DER fingerprint with the manifest/policy fingerprint before readiness.
- D9 requires gRPC mTLS for registered adapter URI SAN principals. LLD A-02 selects a local epoch-scoped CA and a separate leaf/key per process. The leaf chain, exact expected server URI SAN, client role, validity, and immutable epoch allowlist are checked.
- Accepted principal URI templates:
  - adapter: spiffe://rateguard.local/adapter/<id>
  - replica: spiffe://rateguard.local/replica/<decimal-slot-id>/<lowercase-incarnation-hex>
  - authority: spiffe://rateguard.local/authority/<lowercase-authority-incarnation-hex>
- Policy identities are unique and compare exactly. Replica URI, configured uint32 slot and incarnation must agree; authority URI must match authority incarnation.
- Policy requires at least one adapter, exactly one authority, and exactly one replica principal per registered slot. Slot IDs are unique uint32 values, up to eight, need not be contiguous or zero-based.
- Adapter and replica permission entries reference existing tenant/operation pairs and can be empty (deny all). Authority permissions must be empty. Every tenant has at least one operation. Unknown identities/pairs never create state.
- Mode/policy/trust root and slot membership are immutable within an epoch. Trust rotation or revocation closes old channels and requires a fully fenced new epoch with a rebuilt registry. No online revocation or live rotation is claimed.
- Wall time is for certificate validity only, never refill. The LLD says loss of trusted wall-time validity rejects calls; it does not define a detector or the trust source for wall time.

### Role / operation matrix

| Caller | Transport role and registered identity | Permitted operation | Authorization source |
|---|---|---|---|
| Adapter to admission replica | mTLS client; registered adapter URI SAN | CheckAdmission only; requested tenant/operation pair must be in that principal’s permissions | Immutable policy; adapter derives context from trusted upstream/test configuration, ignores client override headers |
| Admission replica to authority | mTLS client; registered replica URI SAN bound to slot/incarnation | Internal strict check and/or AcquireCredit for a configured tenant/operation pair; registered slot/incarnation, epoch and digest must match | Immutable policy and fixed epoch slot registry |
| Admission replica serving adapter | mTLS server; registered replica URI SAN | Serve CheckAdmission | Caller pins/accepts exact registered server identity |
| Authority serving replicas | mTLS server; exact authority URI SAN/incarnation | Strict/grant RPCs from registered replica role only; adapter role cannot acquire credits | Trust registry + role/slot/policy |
| Authority to witness | Local Unix socket, not another mTLS role | Witness protocol from the inventoried authority process | Supervisor-owned OS peer credentials, bound to authority inventory identity; never a caller-supplied PID |

### Certificate and request processing

1. Before readiness, load immutable policy and trust registry; parse the configured root certificate, compute SHA-256 over DER, compare with policy fingerprint, reject mismatch.
2. At TLS peer establishment and every RPC, validate the presented leaf chain to the expected epoch root, leaf role/EKU, URI SAN registration, certificate validity, and role/permission binding. Reused channels do not bypass application-level expiry checks.
3. Client verification includes clientAuth; server verification includes serverAuth; client-side channel validates the exact expected server URI SAN.
4. Resolve peer URI exactly from the registered principal table. Resolve requested tenant/operation against immutable permission pairs and derive cost only from policy. Client-supplied cost/time/identity overrides never raise allowance.
5. Any authentication/authorization/validation error is rejected before quota state or grant sequence mutation. No private key, full credential, raw sensitive payload, or full certificate may enter logs or exported artifacts.
6. Local keys are provisioned outside the repository with owner-only permissions and read-only process mounts. The documents do not claim secure provisioning/PKI is already available.
7. Failure after a valid request proceeds into a state transition may have Possible or Committed commitment. Raw transport loss never authorizes forwarding or refunds. Pre-state authentication/authorization/validation failures have NotCommitted. D1/D2 mappings: malformed input -> INVALID_ARGUMENT; absent/untrusted identity -> UNAUTHENTICATED; authenticated but wrong role/permission -> PERMISSION_DENIED; all do not charge.

## Proposed internal API surface

These signatures are proposed shape only; concrete types should follow LLD section 17 and RG-001 C++20 error contract.

    Result<AuthenticatedPeer, AuthError>
    PeerAuthenticator::Authenticate(const TransportPeer&, TrustedWallTime);

    Result<void, AuthError>
    PeerAuthenticator::AuthorizeRpc(const AuthenticatedPeer&, RpcKind,
                                    EpochId, PolicyDigest, TrustedWallTime);

    Result<AuthorizedOperation, AuthorizationError>
    AuthorizationResolver::Resolve(const AuthenticatedPeer&,
                                   TenantId, OperationId,
                                   RequestOrigin);

    Result<TrustSnapshot, ConfigError>
    PeerAuthenticator::Create(const PolicySnapshot&, const EpochManifest&,
                              const RootCertificateDer&, TrustedWallClock&);

- AuthenticatedPeer should contain a non-secret immutable principal URI, role, certificate validity bounds/fingerprint needed for per-RPC revalidation, and verified epoch trust identity; never retain/log the full DER chain unnecessarily.
- AuthorizationResolver is the sole constructor of trusted tenant/operation/cost context. Its input must distinguish adapter-originated server context from internal replica calls so an adapter identity cannot invoke authority-only methods.
- Expected server identity is a channel/config input from the trusted registry, never request data. For replica-to-authority it is the one authority URI bound to this epoch. Adapter-to-replica should pin the actual selected registered replica URI for that channel.
- If a cert has multiple URI SAN entries, the implementation must avoid selecting an arbitrary one; a safe default is require exactly one accepted RateGuard URI SAN and reject duplicates/ambiguous identities.

## Behavior-changing gaps to resolve before code

1. Replica EKU: a replica is both a gRPC server for adapters and a gRPC client to the authority. One per-process leaf therefore needs both serverAuth and clientAuth, or the process needs separate role-bound certificates. LLD says separate leaf/key per process and that server leaves require serverAuth and clients require clientAuth, but does not decide the dual-EKU/dual-leaf construction. Choose one before certificate fixtures and config generation.
2. Trusted wall-time source/failure detector: LLD requires per-RPC certificate expiry validation and rejects loss of trusted wall-time validity, but does not define what marks wall time trusted. Decide the v1 source/assumption and fail-closed behavior; do not use monotonic time for X.509 validity.
3. Expiry timing under queueing: specify whether certificate validity is checked once at RPC dispatch or again at the quota transition. Since every RPC is checked and handlers may queue, checking at dispatch and immediately before commit is the conservative behavior; this must be explicit for expiry-during-queue tests.
4. URI SAN cardinality: documents require registered URI SANs and exact URI identity, but do not say how to handle a leaf with multiple URI SANs. Require one recognized RateGuard URI SAN, or define deterministic rejection of multiple recognized identities before implementation.
5. Unknown principal classification: D2 clearly maps missing identity to UNAUTHENTICATED and wrong permission to PERMISSION_DENIED, but exact treatment of a chain-valid CA-signed URI SAN absent from registry should be frozen (recommended UNAUTHENTICATED as unregistered identity). All choices remain no-mutation.
6. Replica permission semantics: frozen policy permits replica permission pairs but does not state whether an internal strict/grant call must satisfy the replica’s own tenant/operation pair as well as the adapter’s original authorization. Recommended yes: authority authorizes the registered replica slot and requested pair; the replica separately authorizes the adapter principal. This preserves checks at both trust boundaries and prevents a compromised/buggy replica from widening its scope.
7. Server identity set for adapters: LLD requires an exact expected server SAN, but no explicit channel-selection rule says which registered replica SAN an adapter expects when replicas are load-balanced. Pin the selected replica identity per channel; never accept an arbitrary URI SAN from the request.
8. Certificate chain/leaf shape: LLD chooses local epoch CA, role-specific EKU and URI SAN, but does not enumerate whether intermediates are supported, required CA basic constraints/key usage, or the exact SAN extension policy. Default to a simple one-root/one-leaf chain with strict X.509 verification unless there is an explicit requirement for intermediates; serialize this in test fixtures so identities cannot be ambiguous.

Items 1–6 affect eligibility, failure status, or admission timing and should be resolved before enabling RG-004. Items 7–8 can be fixed as safe implementation defaults with independent fixtures if the owner confirms they do not add PKI scope. No dependency or online revocation mechanism is proposed.


9. TLS handshake failure versus structured gRPC outcome: absent/untrusted client certs may fail the TLS handshake before an RPC handler can return UNAUTHENTICATED. Define that this is a transport-establishment rejection with no quota/grant mutation, and define which auth failures discovered by an interceptor map to UNAUTHENTICATED or PERMISSION_DENIED. Do not promise a gRPC status when no RPC exists.
10. Reused-channel checks apply on both sides: server interceptors must revalidate client certificate validity/authorization, and outgoing clients must revalidate the cached server peer certificate/expected SAN before each RPC, not only during initial TLS handshake. State whether validity is checked for the leaf only or every presented chain certificate, and what happens if any validity check fails.


## Pinned dependency research and proposed defaults (not yet accepted)

### gRPC C++ v1.51.1 API findings

Inspected the upstream v1.51.1 source files:
- [tls_credentials_options.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpcpp/security/tls_credentials_options.h)
- [tls_certificate_verifier.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpcpp/security/tls_certificate_verifier.h)
- [grpc_security.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpc/grpc_security.h)
- [grpc_security_constants.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpc/grpc_security_constants.h)
- [client_interceptor.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpcpp/support/client_interceptor.h)
- [server_context.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpcpp/server_context.h)
- [auth_context.h](https://github.com/grpc/grpc/blob/v1.51.1/include/grpcpp/security/auth_context.h)

The pinned release contains the experimental C++ ExternalCertificateVerifier / CertificateVerifier and TlsChannelCredentialsOptions::set_certificate_verifier APIs. TlsCustomVerificationCheckRequest exposes target_name(), peer leaf PEM, URI SAN names, and peer_cert_full_chain(); the full chain is explicitly not guaranteed to be present. The upstream implementation invokes custom verification after the TLS handshake and before peer-check completion, so a failed verifier prevents the channel/RPC from proceeding. This is suitable for exact URI-SAN pinning before request dispatch. The request's target name is not the RateGuard identity; compare the URI SAN against a preconfigured exact expected identity. Use synchronous local checks, no filesystem/network calls in the verifier.

Keep normal cryptographic peer verification enabled: explicitly set client-side verify_server_certs=true; on server credentials require a client certificate using GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY. The custom verifier adds the RateGuard URI/role allowlist check. Disable default per-call hostname matching only when URI SAN comparison is configured instead; do not disable chain validation. One channel should be bound to one expected authority URI or one selected registered replica URI. No caller-supplied expected SAN or dynamic arbitrary identity list.

The same external verifier can inspect client URI SANs at the server handshake. ServerContext::auth_context() exposes per-call AuthContext; the gRPC constants identify the peer leaf PEM property. A client interceptor can access ClientRpcInfo::client_context() and ClientContext::auth_context() during an RPC; however, this review has not validated that the peer certificate property is populated at the PRE_SEND_INITIAL_METADATA hook on both fresh and reused channels. Make that a required integration probe before relying on the client-side per-RPC expiry check. TLS verifier is experimental in gRPC 1.51.1, so pin this dependency and test channel handshakes/failure-before-dispatch.

### Proposed decisions for the ten gaps

These are defaults for the technical lead to accept or replace; they are not yet product decisions.

1. Replica EKU: issue one replica leaf with both clientAuth and serverAuth EKUs. The replica is both an admission gRPC server and authority gRPC client; the LLD already calls for one leaf/key per process and policy has one URI principal per replica. Adapter leaf is clientAuth; authority leaf is serverAuth.
2. Wall-time source and loss: use the Linux VM's CLOCK_REALTIME/system UTC, which is also what the pinned gRPC TLS stack uses for normal certificate validity verification. Treat accuracy/synchronization as an explicit VM deployment precondition; v1 adds no NTP/chrony/systemd dependency because Docker Desktop's time-sync mechanism is host-managed and not a portable in-container API. A syscall failure or observed backwards step marks local certificate authentication unavailable and fails closed (no quota or sequence mutation) until supervisor-controlled trust revalidation; an arbitrary inaccurate but monotonic UTC source cannot be detected by this library. If the product requires machine-detectable synchronization loss, this remains a deployment blocker requiring an explicit trusted health signal.
3. Expiry timing: check certificate validity at RPC dispatch and again immediately before the quota/grant commit after queueing. Expiry before commit rejects with no debit or grant-sequence consumption. A late response remains subject to normal D1/D2 uncertainty and forwarding rules.
4. URI SAN cardinality: require exactly one URI SAN total in the leaf, and require it to equal the registered RateGuard URI. Reject missing, duplicate, multiple, malformed, or unregistered URI SANs. Do not select the first matching identity.
5. Unknown identity/status: invalid chain, absent client certificate, expired/not-yet-valid certificate, or chain-valid but unregistered URI principal yields UNAUTHENTICATED where an application response is possible; a registered principal with wrong role/RPC/pair yields PERMISSION_DENIED. All are precommit/NotCommitted. A TLS handshake rejected before an RPC exists produces a connection/transport failure, not a fabricated structured gRPC status.
6. Replica permissions: enforce both boundaries. The replica authenticates and authorizes the adapter principal's tenant/operation pair; authority independently authorizes the replica principal's same requested pair and fixed slot/incarnation. Empty permissions deny. This makes policy replica permission entries operational and prevents a replica from widening an adapter's authorized pair.
7. Expected server SAN: authority clients pin the epoch's sole authority URI; adapters pin the selected registered replica URI per channel. Resolve the selected replica from trusted endpoint configuration and verify exact SAN on handshake. A load balancer that may switch among replica certificates must use per-replica channels or a design decision accepting a registered set before code; never infer identity from host/DNS/SNI alone.
8. Chain profile: v1 uses one epoch CA trust anchor and one leaf, no intermediate CAs. Require a CA:TRUE root with keyCertSign, CA:FALSE leaf with role-appropriate EKU, and exactly the configured principal URI SAN; retain default strict chain verification. No OCSP/CRL or online revocation; trust-root/leaf rotation is a fenced new epoch.
9. Reused-connection validity: TLS verifies chain validity at handshake. Additionally, each server RPC rechecks peer leaf notBefore/notAfter from that call's gRPC AuthContext against CLOCK_REALTIME before dispatch and commit. Each client RPC should do the analogous server-leaf check in a PRE_SEND_INITIAL_METADATA interceptor using ClientContext::auth_context; the fresh/reused-channel availability probe is a blocking acceptance test. If the peer leaf is absent/ambiguous at that point, do not dispatch; rely on TLS handshake only for the initial connection once a test proves verifier gating. Revalidate URI/role against immutable registry on each call; full chain path is validated by gRPC TLS at handshake.
10. Secret/role lifecycle: keep private keys outside version control and artifacts, restrict file/mount access, log only bounded failure class and pseudonymous principal, and disable session-key logging. Expired certs reject per call; CA or principal membership change requires closed channels and fenced fresh epoch. No live trust changes.

### Trusted-time evidence and scope

OpenSSL 3 documentation confirms X509_verify_cert validates certificate chain and validity periods; X509_STORE_CTX_set_time / X509_VERIFY_PARAM_set_time can supply an explicit verification time to OpenSSL contexts. The gRPC 1.51.1 C++ TLS credential options expose no wall-time provider or verification-time setter, so the default TLS handshake validation uses the TLS stack/system wall clock. An application-level X509 recheck can compare leaf validity to a sampled time, but cannot retroactively change the time used by the already-completed gRPC handshake. Therefore keep one system CLOCK_REALTIME source for v1; do not claim independent trusted-time assurance.

Official OpenSSL references:
- [X509_verify_cert (OpenSSL 3.0)](https://docs.openssl.org/3.0/man3/X509_verify_cert/)
- [X509_VERIFY_PARAM_set_time (OpenSSL 3.0)](https://docs.openssl.org/3.0/man3/X509_VERIFY_PARAM_set_flags/)
- [X509_cmp_time (OpenSSL 3.0)](https://docs.openssl.org/3.0/man3/X509_cmp_time/)

Research was source inspection only; no API compile probe or certificate integration test was run. The exact SAN verifier is library-supported in the pinned gRPC headers. Per-RPC expiry on reused channels is not yet proven in a running v1.51.1 client/server and remains a story acceptance test. Accurate wall-time synchronization is a deployment precondition, not something the library can independently establish. No implementation has started.

## Root-ready status summary

### Source-verified API answer

For exact server URI verification before any request is dispatched, gRPC C++ v1.51.1 has a source-compatible (experimental) route: configure TlsChannelCredentialsOptions / TlsServerCredentialsOptions with an ExternalCertificateVerifier; its post-handshake request exposes the peer leaf URI SAN values. A verifier that rejects the exact expected registered URI prevents connection peer-check completion, so RPC dispatch cannot succeed first. Compare the SAN to a trusted channel identity; do not rely on target_name, DNS hostnames, or request metadata. Keep client verify_server_certs enabled and require/verify client certificates on server credentials. Do not depend on peer_cert_full_chain because upstream marks it not always available. This is API/source verified, but a compile/handshake integration test is still required.

### One blocking decision: wall-time trust

The gRPC credential API has no trusted wall-time provider/verification-time argument. OpenSSL supports an explicit verification time in X509_STORE_CTX, but gRPC TLS options do not expose it and normal handshake checks use the process/system wall clock. Proposed default: use CLOCK_REALTIME/system UTC for TLS validity, declare host/VM time synchronization a deployment precondition, reject certificates outside their validity window, and fail closed with no mutation if the realtime syscall fails or an observed backward step occurs. The library cannot detect a wrong-but-monotonic UTC source. If an active detector for synchronization loss is required by “trusted wall time”, that detector/source is a deployment blocker before RG-004 code; do not claim it is supplied by gRPC/OpenSSL.

### Remaining verification boundary

Server-side per-RPC leaf expiry can be checked from ServerContext::auth_context() before request admission and before commit. ClientContext::auth_context() and ClientRpcInfo::client_context() exist in gRPC 1.51.1, but this research did not establish that a remote server leaf is always available at PRE_SEND_INITIAL_METADATA across fresh/reused channels. Keep that as an explicit integration acceptance gate; do not make an unsupported per-RPC client-side expiry claim. Root received this distinction.

No implementation/API compilation was run. The detailed source links are above in this note.EOF
cat >> /tmp/rateguard-senior-worklog.md <<'EOF'

- Root-ready RG-004 research status: exact URI SAN verification before dispatch is source-verified through gRPC v1.51.1 experimental post-handshake CertificateVerifier; compile/integration evidence remains pending. One blocking wall-time decision is whether CLOCK_REALTIME with VM synchronization as a deployment precondition is accepted, or active synchronization-loss detection is required (no detector/source exists in current gRPC/OpenSSL contracts). Client-side per-RPC server-leaf expiry remains a runtime API acceptance probe, not a claim.
