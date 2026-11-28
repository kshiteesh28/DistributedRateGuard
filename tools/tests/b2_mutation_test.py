#!/usr/bin/env python3
"""Check actual RPC behavior and isolated mutants without exposing child output."""
import argparse
import os
import re
import resource
import signal
import subprocess
import tempfile

LIMIT = 64 * 1024
ARMOR = re.compile(rb'-----BEGIN [A-Z0-9 ]{1,80}-----')
RPC_OK = b'PASS peer_authorization_real_tls_rpc'
AUTH_OK = b'peer authenticator checks passed'
PAIR_FAIL = b'FAIL known_unauthorized_pair_maps_permission_denied_before_state_spy'
PIN_FAIL = b'FAIL: same URI with different leaf DER fails pin check'

def cap_files():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))

def run(binary, fixture):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen([binary, fixture], stdout=out, stderr=err,
                                 start_new_session=True, preexec_fn=cap_files)
        try:
            code = child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise RuntimeError('test timeout; output withheld') from None
        out.seek(0)
        err.seek(0)
        stdout, stderr = out.read(LIMIT + 1), err.read(LIMIT + 1)
        if len(stdout) + len(stderr) >= LIMIT:
            raise RuntimeError('test output cap reached; output withheld')
        if ARMOR.search(stdout + stderr):
            raise RuntimeError('PEM armor in test output; output withheld')
        return code, stdout.strip(), stderr

def positive(binary, fixture, expected):
    code, stdout, _ = run(binary, fixture)
    if code != 0 or stdout != expected:
        raise RuntimeError('normal positive-control suite failed; output withheld')

def negative(binary, fixture, expected):
    code, stdout, stderr = run(binary, fixture)
    failures = [line.strip() for line in stderr.splitlines() if line.startswith(b'FAIL')]
    if code != 1 or stdout or failures != [expected]:
        raise RuntimeError('unsafe variant escaped exact expected check; output withheld')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--fixture', required=True)
    parser.add_argument('--normal-rpc', required=True)
    parser.add_argument('--pair-mutant-rpc')
    parser.add_argument('--normal-auth')
    parser.add_argument('--pin-mutant-auth')
    args = parser.parse_args()
    mutant_args = (args.pair_mutant_rpc, args.normal_auth, args.pin_mutant_auth)
    if any(mutant_args) and not all(mutant_args):
        parser.error('all mutant controls must be supplied together')
    positive(args.normal_rpc, args.fixture, RPC_OK)
    if not all(mutant_args):
        print('PASS actual TLS peer authorization RPC checks')
        return
    negative(args.pair_mutant_rpc, args.fixture, PAIR_FAIL)
    positive(args.normal_auth, args.fixture, AUTH_OK)
    negative(args.pin_mutant_auth, args.fixture, PIN_FAIL)
    print('PASS independent permission and leaf-pin defect controls')

if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('B2 child check failed; bounded output withheld') from None
