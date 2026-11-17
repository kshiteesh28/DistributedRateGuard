#!/usr/bin/env python3
"""Bound/redact TLS test output and retain exact session qualification facts."""
import argparse
import json
import os
from pathlib import Path
import re
import resource
import signal
import subprocess
import tempfile

LIMIT = 64 * 1024
ARMOR = re.compile(rb'-----BEGIN [A-Z0-9 ]{1,80}-----')
NORMAL = b'PASS pinned_peer_rpc_client_fresh_guard'
DEFECT = b'FAIL fresh_per_call_guard_blocks_expired_pinned_identity_before_dispatch'
ALLOWED = {'status', 'actual_resumed', 'new_transport', 'client_leaf_pin',
           'server_leaf_pin', 'client_verifier_calls', 'server_verifier_calls',
           'client_verifier_delta', 'server_verifier_delta', 'verifiers_ran',
           'uncached_reconnects_passed', 'cache_attempts', 'cache_capacity',
           'max_attempts', 'dispatch_unchanged', 'server_reused_property',
           'handler_dispatched'}

def cap():
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMIT, LIMIT))

def run(binary, fixture, qualify=False):
    args = [binary, fixture] + (['--qualify-session'] if qualify else [])
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        child = subprocess.Popen(args, stdout=out, stderr=err,
                                 start_new_session=True, preexec_fn=cap)
        try:
            code = child.wait(timeout=120)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise RuntimeError('TLS test timed out; output withheld') from None
        out.seek(0); err.seek(0)
        stdout, stderr = out.read(LIMIT + 1), err.read(LIMIT + 1)
        if len(stdout) + len(stderr) >= LIMIT or ARMOR.search(stdout + stderr):
            raise RuntimeError('TLS output rejected by bound/privacy check')
        return code, stdout.strip(), stderr

def positive(binary, fixture):
    code, stdout, stderr = run(binary, fixture)
    if code != 0 or stdout != NORMAL:
        labels = [s for s in stderr.splitlines()
                  if re.fullmatch(rb'FAIL [a-z0-9_]{1,128}', s)]
        for label in labels[:2]:
            print(label.decode('ascii'))
        raise RuntimeError('normal TLS suite failed; raw output withheld')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--binary', required=True)
    p.add_argument('--fixture', required=True)
    p.add_argument('--mutant')
    p.add_argument('--qualify', action='store_true')
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    if a.qualify:
        if a.mutant or not a.output:
            p.error('qualification requires output and no mutant')
        code, stdout, _ = run(a.binary, a.fixture, True)
        try:
            data = json.loads(stdout)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError('qualification did not return one JSON record') from None
        if not isinstance(data, dict) or set(data) - ALLOWED:
            raise RuntimeError('qualification has unsupported fields')
        if any(not isinstance(v, (str, bool, int)) for v in data.values()):
            raise RuntimeError('qualification has unsupported value types')
        counts = {'client_verifier_calls', 'server_verifier_calls', 'client_verifier_delta',
                  'server_verifier_delta', 'cache_attempts', 'cache_capacity', 'max_attempts'}
        for key, value in data.items():
            if key == 'status':
                continue
            if key in counts:
                if type(value) is not int or not 0 <= value <= 100000:
                    raise RuntimeError('invalid qualification counter')
            elif type(value) is not bool:
                raise RuntimeError('invalid qualification boolean')
        if data.get('status') in {'qualified', 'not_demonstrated', 'not_qualified_no_dispatch_observed'} and (
                data.get('uncached_reconnects_passed') is not True or data.get('cache_capacity') != 1):
            raise RuntimeError('missing uncached control or bounded-cache evidence')
        status = data.get('status')
        safe_statuses = {'qualified', 'not_demonstrated',
                         'not_qualified_no_dispatch_observed'}
        if status not in safe_statuses and not (
                isinstance(status, str) and re.fullmatch(r'unsafe_[a-z_]{1,80}', status)):
            raise RuntimeError('qualification has unsupported status')
        if status == 'qualified' and not all(data.get(k) is True for k in (
                'actual_resumed', 'new_transport', 'client_leaf_pin',
                'server_leaf_pin', 'uncached_reconnects_passed')):
            raise RuntimeError('qualified record lacks required proof')
        if status == 'qualified' and any(type(data.get(k)) is not int or data[k] < 1
                for k in ('client_verifier_delta', 'server_verifier_delta')):
            raise RuntimeError('qualified record lacks fresh verifier deltas')
        if status == 'not_demonstrated' and data.get('actual_resumed') is not False:
            raise RuntimeError('contradictory non-demonstration')
        if status == 'not_qualified_no_dispatch_observed' and (
                data.get('actual_resumed') is not True or data.get('dispatch_unchanged') is not True):
            raise RuntimeError('missing no-dispatch observation')
        record = {'schema_version': 1, 'scope': 'SDK qualification only; production cache disabled',
                  'exit_code': code, 'observation': data}
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record, sort_keys=True))
        if code != 0 or status not in safe_statuses:
            raise RuntimeError('resumed path failed qualification')
        return
    positive(a.binary, a.fixture)
    if a.mutant:
        code, stdout, stderr = run(a.mutant, a.fixture)
        failures = [line.strip() for line in stderr.splitlines() if line.startswith(b'FAIL')]
        if code != 1 or stdout or failures != [DEFECT]:
            raise RuntimeError('preflight mutant escaped its exact expected check')
        print('PASS independent client suite detects preflight bypass')
    else:
        print('PASS sealed pinned client TLS checks')

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('B3 test check failed; bounded raw output withheld') from None
