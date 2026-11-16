# RG-004-B1 certificate registry input contract

**Revision:** 1 · **Date:** 2026-11-16 · **Status:** Selected implementation contract; not accepted implementation evidence.
**Sources:** PRD 8 PRD-008/024; SRD 5 FR-003/D9/NFR-008; LLD 5 A-02; [SEC-01–11 revision 2](https://github.com/kshiteesh28/DistributedRateGuard/blob/docs/scrum-work-log/docs/decisions/RG-004-security-v1.md).
**Branch:** `feature/RG-004-certificate-registry`, based on verified RG-004-A head `f5b3e975225c869e4a9638af57ab9f7c8a06e546`.

## Boundary

Consume an already-validated immutable PolicySnapshot, caller-owned public root/leaf PEM views and ITrustedWallClock. Return either an immutable registry snapshot or bounded reason-only error. Do not read/write files, accept private keys, serialize supervisor manifests, authorize requests, rotate credentials or claim service readiness. RG-006 owns manifest binding and positive fencing; B2 owns authenticated peer/policy authorization.

The snapshot binds canonical policy digest, epoch/authority/slot identities, root fingerprint, and exactly one leaf per configured principal. Only public identity/fingerprint/validity metadata survives loading. The trusted validation timestamp describes construction; fresh validity/trust checks remain mandatory before later readiness/calls/commit/forwarding. No immutable snapshot makes an expired certificate valid.

## Validation contract

- At most 10,000 principals, using policy-v1's existing cap; at most 64 KiB per PEM certificate and 64 MiB aggregate root plus leaves. The byte caps are explicit NFR-008 implementation bounds, not new product capacity claims. Reject excess before certificate parsing; never silently truncate.
- Exactly one certificate per input, with only surrounding whitespace; reject embedded NUL, trailing certificates/keys or other data. No raw PEM or OpenSSL error text in returned diagnostics/logs.
- Bind the root's DER SHA-256 to policy trust_root_sha256. Require self-signature, EC P-256/SHA-256, CA=true, pathLen=0 and certificate-signing usage.
- Each directly signed leaf uses EC P-256/SHA-256, CA=false and digitalSignature. Apply strict chain validation and each role's required OpenSSL purpose. Accept no intermediates.
- Require exact role EKUs: adapter clientAuth; authority serverAuth; replica both. Do not derive role from CN or request fields.
- Require exactly one NUL-free URI SAN, matching one configured policy principal byte-for-byte. Reject missing/extra/duplicate principals and retain exact leaf DER SHA-256 pins.
- Use an explicit trusted UTC sample, checked integer certificate-time conversion and `notBefore <= now < notAfter`, including fractional current seconds. Bind the resulting snapshot to unchanged canonical policy bytes/digest.
- Invalid input, crypto/provider failure, allocation/resource failure or trusted-clock failure returns no snapshot. Immutable lookups do not insert or mutate state.

## Evidence and owners

Senior Dev implements and supplies developer tests. Junior independently reviews integer time, lifetime and cap boundaries. Tester independently constructs positive/negative fixtures and defect controls against compiled production code. Master integrates a stacked PR and records actual Linux/OpenSSL/ASan results before review readiness.

Full RG-004 AC01–03, live authorization, established-channel expiry, reconnect/resumption, end-to-end guards and export privacy remain open. A successful B1 test run will only validate this input contract.
