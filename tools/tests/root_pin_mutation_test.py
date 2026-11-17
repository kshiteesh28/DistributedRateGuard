#!/usr/bin/env python3
"""Prove the independent registry acceptance test catches a root-pin defect."""
from __future__ import annotations

import argparse
import re
import subprocess

PEM_ARMOR = re.compile(rb"-----BEGIN [A-Z0-9 ]{1,80}-----")
MAX_OUTPUT = 64 * 1024
PASS_LINE = b"PASS registry_valid_binding_negative_identity_eku_time_caps"
MUTANT_FAILURE = b"FAIL wrong_root_digest_rejected"


def run(path: str, fixture: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([path, fixture], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=120, check=False)


def safe_output(result: subprocess.CompletedProcess[bytes]) -> bytes:
    output = result.stdout + result.stderr
    if len(output) > MAX_OUTPUT:
        raise SystemExit("registry child output exceeded 64 KiB; withheld")
    if PEM_ARMOR.search(output):
        raise SystemExit("registry child output contained PEM armor; withheld")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--normal", required=True)
    parser.add_argument("--mutant", required=True)
    parser.add_argument("--fixture", required=True)
    args = parser.parse_args()

    normal = run(args.normal, args.fixture)
    normal_output = safe_output(normal)
    if normal.returncode != 0 or normal_output.strip() != PASS_LINE:
        raise SystemExit("normal registry fixture suite failed; child output withheld")

    mutant = run(args.mutant, args.fixture)
    mutant_output = safe_output(mutant)
    if mutant.returncode == 0 or mutant_output.strip() != MUTANT_FAILURE:
        raise SystemExit("wrong-root-pin mutant escaped expected independent check; child output withheld")
    print("PASS independent registry suite detects root-pin bypass mutant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
