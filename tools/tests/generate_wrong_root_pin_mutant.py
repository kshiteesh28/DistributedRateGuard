#!/usr/bin/env python3
"""Create a test-only mutant that skips only the certificate root-pin check."""
from __future__ import annotations

import argparse
from pathlib import Path

ANCHOR = """  if (root_digest != snapshot->trust_root_sha256())
    return Error{ErrorCode::RootFingerprintMismatch};"""
REPLACEMENT = """  // TEST-ONLY MUTANT: deliberately bypass the policy root fingerprint guard.
  // The remaining profile, chain, principal, EKU, validity and size checks stay active."""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    source = args.source.read_text(encoding="utf-8")
    if source.count(ANCHOR) != 1:
        raise SystemExit("expected exactly one root-fingerprint guard anchor")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(source.replace(ANCHOR, REPLACEMENT, 1), encoding="utf-8")
    print("generated test-only root-pin bypass mutant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
