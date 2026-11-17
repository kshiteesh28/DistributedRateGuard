#!/usr/bin/env python3
"""Black-box acceptance checks for the ephemeral mTLS RPC probe output."""
from __future__ import annotations

import re
import json
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
PEM_ARMOR = re.compile(r"-----BEGIN [A-Z0-9 ]{1,80}-----")
PKI_PREFLIGHT = re.compile(
    r"PKI_PREFLIGHT_FAIL server_error=(-?[0-9]{1,10}) client_error=(-?[0-9]{1,10})"
)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: mtls_probe_output_test.py /path/to/mtls_probe_test")
    result = subprocess.run([sys.argv[1]], text=True, capture_output=True, timeout=90)
    output = result.stdout + result.stderr
    if len(output) > 64 * 1024:
        raise SystemExit("mTLS probe output exceeded 64 KiB")
    if PEM_ARMOR.search(output):
        raise SystemExit("mTLS probe output contains PEM-encoded material; child output withheld")
    if result.returncode == 3:
        match = PKI_PREFLIGHT.fullmatch(result.stderr.strip())
        if match is None or result.stdout:
            raise SystemExit("mTLS PKI preflight failed with unexpected output; child output withheld")
        server_error, client_error = (int(value) for value in match.groups())
        print(json.dumps({
            "probe_exit_code": 3,
            "pki_preflight": {"result": "failed", "server_error": server_error,
                              "client_error": client_error},
            "scenarios": [],
        }, separators=(",", ":")))
        raise SystemExit("mTLS PKI preflight failed; only allowlisted numeric codes were emitted")
    observed: dict[str, tuple[str, str, int]] = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"([a-z_]+): (PASS|FAIL) rpc=(OK|REJECTED) handler_calls=([0-9]+)", line)
        if not match:
            raise SystemExit("mTLS probe emitted an unexpected line; child output withheld")
        name, assertion, status, calls = match.groups()
        if name in observed:
            raise SystemExit("mTLS probe emitted a duplicate scenario; child output withheld")
        observed[name] = (assertion, status, int(calls))
    summary = {
        "probe_exit_code": result.returncode,
        "scenarios": [
            {"name": name, "assertion": observed[name][0],
             "rpc": observed[name][1], "handler_calls": observed[name][2]}
            for name in EXPECTED if name in observed
        ],
    }
    print(json.dumps(summary, separators=(",", ":")))
    correct = {name: ("PASS", status, calls) for name, (status, calls) in EXPECTED.items()}
    if result.returncode != 0 or observed != correct:
        raise SystemExit("mTLS probe acceptance failed; only allowlisted scenario fields were emitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
