# RG004-B1 Independent Acceptance Matrix (draft)

Scope: bounded, immutable certificate registry construction only. The production registry is exercised through its real C++ API/driver and OpenSSL; tests must not call production validation helpers as their oracle. This slice does not prove manifest authenticity, request authorization, epoch readiness/fencing, deployed TLS channel behavior, or service admission behavior.

## Positive cases

- Valid self-signed P-256/SHA-256 trust root and registered direct leaf chain for adapter, replica and authority roles; root fingerprint is SHA-256 over DER bytes, not PEM text.
- Exact supplied policy digest, epoch, authority identity, URI principal and role bindings accepted; registry metadata immutable after successful load.
- `notBefore == trusted_now` accepted, `notAfter > trusted_now` accepted; ensure interval comparison uses UTC seconds+nanos consistently.
- Multiple principal inputs accepted up to documented cap with stable lookup results independent of input ordering if ordering is not part of contract.
- Trust chain accepted only when root is the supplied root and all cert/profile requirements pass.
- Exact-cap root and leaf PEMs accepted with surrounding whitespace; one-byte-over is rejected before certificate parsing. Aggregate size exactly 64 MiB reaches later validation; one byte over returns ResourceLimit. A 10,001-leaf input is rejected before parsing.
- Successful load leaves only immutable metadata: root/policy digests, epoch/authority identity, principals/roles/leaf pins, validity and `validated_at`. Destroy caller-owned PEM strings, fixture PKI and policy references; the registry remains usable.

## Negative cases

- Wrong root DER fingerprint; root not self-signed; root CA=false; pathLen != 0; missing keyCertSign; wrong key type/signature algorithm.
- Missing, duplicate, multiple, or extra URI SAN; unknown URI; principal not bound by supplied policy; role EKU mismatch or extra EKUs if exact-role-only.
- Leaf CA=true; key usage missing digitalSignature; wrong curve or signature digest.
- notBefore > now; now == notAfter; malformed/invalid validity; clock failure/unknown time.
- Unknown issuer, wrong chain root, chain-depth/path violations, malformed PEM/DER, trailing unrelated PEM blocks.
- Wrong EKU for role; adapter clientAuth only, authority serverAuth only, replica both; no extra EKUs.
- Wrong key/curve/signature profile, non-CA root, non-CA constraints/pathLen/keyCertSign mismatch, CA=true or missing digitalSignature on leaf where independent fixture variants are available.
- Per-certificate PEM >64 KiB; aggregate PEM >64 MiB; more than 10,000 leaf inputs. Check exact-at-cap behavior and one-over behavior wherever contract specifies cap representation.
- Empty, duplicated, missing, or extra leaf inputs relative to policy principals. Ensure failed load returns no partial/published snapshot.
- Safe bounded error code only; diagnostics must not leak raw OpenSSL errors, certificate text, keys, or SAN contents.

## Evidence required

- Production compiled integration test against real OpenSSL and parser; no local-toolchain substitute is acceptance evidence.
- Independent fixture construction and expected-case map. Include a test-only mutation that skips at least one material check and confirm the independent suite rejects it.
- Exact output for success/failure status, stable error class, root fingerprint and principal count only; no PEM/key output.
