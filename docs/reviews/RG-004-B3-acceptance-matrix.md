# RG004-B3 independent QA plan

## Scope and binding decisions

Sources reviewed: PRD 8, SRD 5, LLD 5 on `main`; SEC-01–11 revision 2 and the published B2 contract at `20210d`. This QA slice covers only the outgoing-client trust guard and reusable pre-forward guard. It does not claim quota/credit behavior, adapter forwarding integration, epoch fencing, or product release gates.

Binding client requirements:

- Pin the endpoint from immutable registry metadata (expected URI, role/incarnation, leaf DER digest); configuration never comes from the request.
- Preserve ordinary TLS chain validation and enforce the exact endpoint pin during the TLS handshake, including reconnects.
- On every outbound call, sample fresh trusted UTC and verify clock health, trust-root validity, the client's own leaf validity, and the expected server leaf validity. Validity is `notBefore <= now < notAfter`.
- A guard failure before dispatch is a local `NotSent` result with a bounded reason/disposition, not a fabricated gRPC status. Credential/expiry failures classify as `CredentialInvalid`; clock/dependency loss classifies as `ApplicationUnavailable`. The caller may map either local dependency failure to an application `UNAVAILABLE` response, never `LIMITED`; no RPC dispatch and no guard-inferred commitment.
- A reusable pre-forward guard must recheck trusted UTC and root/own-leaf/server-leaf validity for a timely received ALLOW before allowing the caller to proceed. This test seam is not a quota implementation or complete forwarding integration.
- Disable gRPC retries and hedging on enforcement channels. The tests verify the configured channel factory and count dispatches; they do not claim exactly-once network delivery.
- Test TLS verification on fresh and forced reconnect channels separately from session resumption. Same-channel RPC reuse is not a reconnect or resumption test. A resumed session counts as evidence only when the pinned gRPC SDK exposes and the test observes `GRPC_SSL_SESSION_REUSED=true`; if the fixture cannot establish a resumed session, label that evidence NOT QUALIFIED rather than passed.

## Planned fixture and evidence

Use real gRPC C++ mTLS with ephemeral in-memory certificates, actual B1 registry metadata, actual pinned server verifier, a fake trusted UTC clock, and a server handler counter. Avoid writing/logging PEM or private keys. Use a replica leaf for the server endpoint and adapter leaf for the client endpoint. Assert exact URI/DER pin is selected from the registry. Keep message responses as test sentinels; never return ALLOW as a test quota result.

| Case | Required check | Dispatch / result evidence |
| --- | --- | --- |
| Valid outbound call on warm TLS channel | Fresh time sample validates root, adapter leaf and expected replica leaf; endpoint pin remains exact. | Exactly one RPC dispatch; test sentinel response; no quota claim. |
| Root expires before a later call | Keep channel established and OS TLS time valid; move only injected trusted UTC to root `notAfter`. | Wrapper returns `NotSent` + `CredentialInvalid`; dispatch count unchanged. |
| Client's own leaf expires before a later call | Root and server leaf remain valid; fake UTC reaches client leaf `notAfter`. | Wrapper returns `NotSent` + `CredentialInvalid`; dispatch count unchanged; no retry. |
| Expected server leaf expires before a later call | Root and client leaf remain valid; fake UTC reaches server leaf `notAfter`. | Wrapper returns `NotSent` + `CredentialInvalid`; dispatch count unchanged; cached TLS channel does not bypass client guard. |
| Trusted clock becomes unhealthy | Existing warm channel remains otherwise valid. | Wrapper returns `NotSent` + `ApplicationUnavailable`; no RPC dispatch. No commitment phase is invented by the primitive; caller explicitly supplies pre-dispatch phase. |
| Pre-forward guard expiry | First obtain a raw response fixture while time is valid, then advance fake UTC to each root/client/server boundary before guard use. | Guard returns `CredentialInvalid`; backend spy remains unchanged. The guard does not validate ALLOW/deadline/epoch and no actual backend request is sent. |
| Invalid/unregistered endpoint pin | Configure wrong registered server leaf or same URI with alternate DER; ordinary chain may still validate. | TLS verifier rejects before handler. This complements, but does not replace, the warm-channel date checks. |
| Forced reconnect, cache disabled | Create a new channel with an isolated subchannel pool and connect to a distinct server TCP endpoint; count verifier calls and endpoint. | New handshake is observed; exact pin is rechecked. Do not call this session resumption. |
| TLS session resumption, if supported by frozen gRPC API | Share explicit bounded SSL session cache across credentials/channels; force a new transport and inspect actual `GRPC_SSL_SESSION_REUSED` property from AuthContext. | Require true for a qualified resumption case and still prove pin/validity policy. If the runtime does not resume, record NOT QUALIFIED; never use same-channel reuse as substitute. |
| Retry / hedge suppression | Inspect the exact factory-produced channel args and use server dispatch counters under a transport retryable failure. | No hidden second RPC; application retries remain caller-controlled. |

## Ownership and status table

The test fixture should call the production client guard before invoking the generated stub and call the reusable pre-forward guard on the returned synthetic response. Client-side pre-call failure should leave handler and state-spy counters at zero. A direct TLS handshake rejection may produce no structured RPC status; assert only transport failure and zero handler calls. Clock loss uses the frozen application-unavailable mapping, not a fabricated transport error or quota outcome.

The fake clock is mutable only to stage cases; that does not model production sticky clock failure recovery, participant readiness, epoch fencing, or participant-wide stop. Restore it only between isolated test subcases and label this clearly.

## Evidence limits / not acceptance

- A warm channel proves per-call guard behavior only for that fixture; it does not prove forwarding, deadline races, quota commit, or the global epoch response.
- A new TCP connection proves reconnect pin validation only. It does not prove resumption.
- `GRPC_SSL_SESSION_REUSED=true` proves a resumed transport occurred in this pinned test environment; it does not by itself establish all TLS 1.3 ticket, cache eviction, process restart, or production deployment behavior.
- No backend invocation or quota authority is part of this fixture. No PRD/SRD numerical gate is measured.
- Do not accept a test that checks only the TLS verifier while ignoring fresh UTC on a reused connection; do not accept one that checks only the pre-forward guard while omitting the per-outbound-call guard.
