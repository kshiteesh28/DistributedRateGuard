#!/usr/bin/env python3
"""Require the real mTLS RPC probe to catch a verifier-bypass mutant."""
from __future__ import annotations

import re
import subprocess
import sys


EXPECTED_REJECTIONS = (
    "wrong_uri: FAIL rpc=OK handler_calls=1",
    "same_uri_wrong_leaf_pin: FAIL rpc=OK handler_calls=1",
    "wrong_server_uri: FAIL rpc=OK handler_calls=1",
    "same_uri_wrong_server_leaf_pin: FAIL rpc=OK handler_calls=1",
)
FORBIDDEN = (
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mtls_verifier_bypass_mutation_test.py /path/to/mutant_probe")
    result = subprocess.run([sys.argv[1]], text=True, capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    if result.returncode == 0:
        raise SystemExit("mTLS probe did not detect the accept-all verifier mutant")
    if len(output) > 64 * 1024:
        raise SystemExit("mutant mTLS probe output exceeded 64 KiB")
    if any(marker in output for marker in FORBIDDEN):
        raise SystemExit("mutant probe output exposed certificate or private-key PEM")
    for expected in EXPECTED_REJECTIONS:
        if expected not in result.stdout:
            raise SystemExit("mutant was not detected by the expected URI/leaf-pin case: " + expected
                             + "\nstdout:\n" + result.stdout + "\nstderr:\n" + result.stderr)
    # Every emitted scenario line must be a C++ probe result, not a compiler or
    # verifier diagnostic that happens to contain the expected substring.
    for line in result.stdout.splitlines():
        if not re.fullmatch(r"[a-z_]+: (?:PASS|FAIL) rpc=(?:OK|REJECTED) handler_calls=[0-9]+", line):
            raise SystemExit("unexpected mutation probe output: " + line)
    print("mTLS RPC probe detected accept-all verifier mutant on URI and leaf-pin cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
