#!/usr/bin/env python3
"""Black-box acceptance checks for the ephemeral mTLS RPC probe output."""
from __future__ import annotations

import re
import subprocess
import sys


EXPECTED = {
    "valid": ("OK", 1),
    "wrong_uri": ("REJECTED", 0),
    "same_uri_wrong_leaf_pin": ("REJECTED", 0),
    "wrong_eku": ("REJECTED", 0),
    "unknown_ca": ("REJECTED", 0),
    "missing_client_certificate": ("REJECTED", 0),
    "expired_client_leaf": ("REJECTED", 0),
    "not_yet_valid_client_leaf": ("REJECTED", 0),
    "multiple_uri_sans": ("REJECTED", 0),
    "wrong_server_uri": ("REJECTED", 0),
    "same_uri_wrong_server_leaf_pin": ("REJECTED", 0),
    "unknown_server_ca": ("REJECTED", 0),
    "reused_channel_two_rpcs": ("OK", 2),
}
FORBIDDEN = (
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mtls_probe_output_test.py /path/to/mtls_probe_test")
    result = subprocess.run([sys.argv[1]], text=True, capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise SystemExit(f"mTLS probe exited {result.returncode}:\n{output}")
    if len(output) > 64 * 1024:
        raise SystemExit("mTLS probe output exceeded 64 KiB")
    if any(marker in output for marker in FORBIDDEN):
        raise SystemExit("mTLS probe output contains full certificate or private-key PEM")
    observed: dict[str, tuple[str, int]] = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"([a-z_]+): PASS rpc=(OK|REJECTED) handler_calls=([0-9]+)", line)
        if not match:
            raise SystemExit("unexpected probe output line: " + line)
        name, status, calls = match.groups()
        if name in observed:
            raise SystemExit("duplicate probe scenario: " + name)
        observed[name] = (status, int(calls))
    if observed != EXPECTED:
        raise SystemExit(f"probe outcomes differed: expected {EXPECTED!r}, got {observed!r}")
    print("independent mTLS probe-output and redaction checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
