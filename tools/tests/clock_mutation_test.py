#!/usr/bin/env python3
"""Prove the independent clock suite rejects a backward-time clamp mutant.

Set RG003_SOURCE_ROOT to the directory containing platform/clock_linux.cpp
(normally <repo>/src), and RG003_INCLUDE_ROOT to the directory containing
rateguard/v1/error_contract.h (normally <repo>/include). CXX may select the
compiler; default is c++ so CI uses its recorded toolchain.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile


GUARD = "  if (last_sample_ && sample.value < last_sample_->value)\n    return Latch(ClockFailureReason::BackwardsSample);\n"
CLAMP = "  if (last_sample_ && sample.value < last_sample_->value)\n    return *last_sample_;\n"
EXPECTED_FAILURES = (
    "FAIL: backward sample rejected, never clamped",
    "FAIL: provenance reports latched error",
    "FAIL: successful factory sample is retained as first regression reference",
)


def main() -> int:
    source_root = Path(os.environ["RG003_SOURCE_ROOT"]).resolve()
    include_root = Path(os.environ["RG003_INCLUDE_ROOT"]).resolve()
    production = source_root / "platform" / "clock_linux.cpp"
    test_source = Path(__file__).with_name("clock_independent_test.cpp")
    if not production.is_file() or not test_source.is_file():
        raise SystemExit("required RG003 production/test source is missing")
    original = production.read_text()
    if original.count(GUARD) != 1:
        raise SystemExit("backward-sample guard anchor is missing or ambiguous")

    with tempfile.TemporaryDirectory(prefix="rateguard-clock-mutant-") as work:
        work_path = Path(work)
        mutant = work_path / "clock_linux_clamp_mutant.cpp"
        mutant.write_text(original.replace(GUARD, CLAMP, 1))
        executable = work_path / "clock_mutant_test"
        compiler = os.environ.get("CXX", "c++")
        compile_cmd = [
            compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-pedantic",
            "-pthread", "-I", str(source_root), "-I", str(include_root),
            str(test_source), str(mutant), "-o", str(executable),
        ]
        built = subprocess.run(compile_cmd, text=True, capture_output=True, timeout=90)
        if built.returncode != 0:
            raise SystemExit("mutant compile failed:\n" + built.stdout + built.stderr)
        result = subprocess.run([str(executable)], text=True, capture_output=True, timeout=30)
        if result.returncode == 0:
            raise SystemExit("independent suite failed to detect clamp mutant")
        missing = [line for line in EXPECTED_FAILURES if line not in result.stderr]
        if missing:
            raise SystemExit("mutant failed for unexpected reason; missing: " + repr(missing)
                             + "\nstderr:\n" + result.stderr)
    print("independent clock suite rejected backward-time clamp mutant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
