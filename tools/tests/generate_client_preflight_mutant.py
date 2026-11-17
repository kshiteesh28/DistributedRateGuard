#!/usr/bin/env python3
"""Generate one test-only preflight bypass without changing normal targets."""
from pathlib import Path
import argparse

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    source = a.source.read_text()
    marker = 'ClientCallGuard::ValidateBeforeCall() const {'
    if source.count(marker) != 1:
        raise SystemExit('expected one pre-call method')
    begin = source.index(marker)
    end = source.index('\nstd::variant<ClientCallGuardPassed', begin)
    body = source[begin:end]
    anchor = 'const auto time_result = ValidateCurrentTime();'
    if body.count(anchor) != 1:
        raise SystemExit('expected one preflight guard call')
    body = body.replace(anchor,
        'const std::variant<WallTime, ClientCallGuardFailure> time_result{WallTime{0, 0}};'
        '  // TEST-ONLY MUTANT: skip current certificate/time validation.', 1)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(source[:begin] + body + source[end:])
    print('generated isolated preflight bypass mutant')

if __name__ == '__main__':
    main()
