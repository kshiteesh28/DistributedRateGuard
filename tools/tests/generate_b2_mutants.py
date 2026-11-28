#!/usr/bin/env python3
"""Create isolated RG004-B2 unsafe variants for CI mutation checks.

The inputs are production source files. Outputs are test-only source copies and
must never be compiled into the normal library or shipped.
"""
from __future__ import annotations

import argparse
from pathlib import Path


PAIR_GUARDS = (
    """    if (!snapshot.IsAuthorized(peer.uri(), principal->role,
                               request.tenant_id(), request.operation_id()))
      return Denied(Reason::UnauthorizedPair);""",
)
PIN_GUARD = """    if (presented_digest != registered->peer.leaf_der_sha256) {
      return Failure(PeerAuthFailureReason::LeafPinMismatch,
                     PeerAuthDisposition::Unauthenticated);
    }"""


def replace_exact(source: str, anchor: str, replacement: str, count: int) -> str:
    found = source.count(anchor)
    if found != count:
        raise ValueError(f"mutation anchor count {found}; expected {count}")
    return source.replace(anchor, replacement)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--resolver-src", type=Path, required=True)
    parser.add_argument("--auth-src", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    resolver = args.resolver_src.read_text(encoding="utf-8")
    auth = args.auth_src.read_text(encoding="utf-8")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    pair_mutant = resolver
    for anchor in PAIR_GUARDS:
        pair_mutant = replace_exact(
            pair_mutant, anchor, "    // MUTATION: permission guard omitted", 1)
    pin_mutant = replace_exact(auth, PIN_GUARD, "    // MUTATION: certificate pin comparison omitted", 1)
    (args.out_dir / "authorization_resolver_pair_mutant.cpp").write_text(
        pair_mutant, encoding="utf-8")
    (args.out_dir / "peer_authenticator_pin_mutant.cpp").write_text(
        pin_mutant, encoding="utf-8")
    print("generated isolated pair and pin mutants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
