"""Independent arbitrary-precision oracle for the RG002 bucket transition API.

Run locally with:
  python3 -m unittest /tmp/rateguard-rg002-qa/tools/tests/bucket_math_oracle.py

The oracle never imports or calls the C++ implementation; a tiny line protocol
adapter is compiled separately and compared against this model.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

S = 1_000_000_000
MAX_UNITS = 1_000_000_000
U64_MAX = (1 << 64) - 1
INPUT_ERROR = "ERR 0 0 0 0"    # Input / InvalidArgument / Never / NotCommitted
INTERNAL_ERROR = "ERR 6 7 0 0" # Internal / Internal / Never / NotCommitted
QA_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = Path(os.environ.get("RATEGUARD_REPO_ROOT", QA_ROOT))
DRIVER_SOURCE = QA_ROOT / "tests" / "bucket_math_driver.cpp"
SOURCE_ROOT = REPO_ROOT
HEADER = REPO_ROOT / "src" / "authority" / "bucket_math.h"


def oracle_refill(capacity: int, rate: int, balance: int, last: int, now: int) -> str:
    if not (1 <= capacity <= MAX_UNITS and 1 <= rate <= MAX_UNITS):
        return INPUT_ERROR
    capacity_subunits = capacity * S
    if balance > capacity_subunits or now < last:
        return INTERNAL_ERROR
    elapsed = now - last
    # Python integers are arbitrary precision: this intentionally differs from
    # the checked-u128 implementation under test.
    next_balance = min(capacity_subunits, balance + rate * elapsed)
    return f"OK {next_balance} {now}"


def oracle_retry(deficit: int, rate: int) -> str:
    if not (1 <= rate <= MAX_UNITS):
        return INPUT_ERROR
    return f"OK {(deficit + rate - 1) // rate}"


def oracle_decide(capacity: int, rate: int, balance: int, last: int,
                  cost: int, now: int) -> str:
    if not (1 <= capacity <= MAX_UNITS and 1 <= rate <= MAX_UNITS):
        return INPUT_ERROR
    if not (1 <= cost <= capacity):
        return INPUT_ERROR
    refilled = oracle_refill(capacity, rate, balance, last, now)
    if refilled.startswith("ERR "):
        return refilled
    _, available_text, timestamp_text = refilled.split()
    available = int(available_text)
    timestamp = int(timestamp_text)
    cost_subunits = cost * S
    if available >= cost_subunits:
        return f"OK ALLOW {available - cost_subunits} {timestamp} -"
    deficit = cost_subunits - available
    delay = (deficit + rate - 1) // rate
    return f"OK LIMITED {available} {timestamp} {delay}"


def oracle_command(line: str) -> str:
    fields = line.split()
    op = fields[0]
    values = [int(value) for value in fields[1:]]
    if op == "R" and len(values) == 5:
        return oracle_refill(*values)
    if op == "D" and len(values) == 6:
        return oracle_decide(*values)
    if op == "T" and len(values) == 2:
        return oracle_retry(*values)
    raise ValueError(f"bad command: {line!r}")


def compile_driver(output: Path, header_override: Path | None = None) -> None:
    compiler = os.environ.get("CXX") or shutil.which("c++")
    if not compiler:
        raise RuntimeError("no C++20 compiler found")
    include_dirs = []
    if header_override is not None:
        include_dirs.append(header_override.parent.parent)
    include_dirs.extend([SOURCE_ROOT / "src", SOURCE_ROOT / "include"])
    command = [compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror", "-pedantic"]
    for directory in include_dirs:
        command += ["-I", str(directory)]
    command += [str(DRIVER_SOURCE), "-o", str(output)]
    subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)


def run_driver(executable: Path, lines: list[str]) -> list[str]:
    result = subprocess.run([str(executable)], input="\n".join(lines) + "\n",
                            capture_output=True, text=True, check=True, timeout=30)
    return result.stdout.splitlines()


def check_cases(executable: Path, lines: list[str]) -> None:
    expected = [oracle_command(line) for line in lines]
    actual = run_driver(executable, lines)
    if actual != expected:
        mismatches = [(line, want, got) for line, want, got in zip(lines, expected, actual)
                      if want != got]
        raise AssertionError(f"{len(mismatches)} oracle mismatches; first: {mismatches[:3]}")
    if len(actual) != len(expected):
        raise AssertionError(f"driver emitted {len(actual)} lines for {len(expected)} inputs")


def golden_vectors() -> list[str]:
    return [
        # Fractional unit refill: 1 ns at 3 units/s is 3 subunits exactly.
        "R 4 3 0 100 101",
        # Saturation, exact boundary admission, and one-subunit short.
        f"R 3 2 {2*S} 10 1000000010",
        f"D 1 1 {S-1} 0 1 1",
        f"D 1 1 {S-2} 0 1 1",
        # LIMITED with ceil(deficit/rate); known limited leaves debit unchanged.
        "D 10 3 0 0 1 0",
        # Weighted cost and full-capacity debit.
        f"D 5 7 {5*S} 20 5 20",
        # Maximum policy values and full uint64 elapsed time: safe saturation.
        f"R {MAX_UNITS} {MAX_UNITS} 0 0 {U64_MAX}",
        f"R {MAX_UNITS} {MAX_UNITS} {MAX_UNITS*S} 0 {U64_MAX}",
        # Maximum legal balance/cost stay within uint64 storage after debit.
        f"D {MAX_UNITS} 1 {MAX_UNITS*S} 0 {MAX_UNITS} 0",
        # Retry division exact, rounded up, and at uint64 maximum.
        "T 12 3", "T 13 3", f"T {U64_MAX} 1",
    ]


def invalid_vectors() -> list[str]:
    return [
        "R 0 1 0 0 0", f"R {MAX_UNITS+1} 1 0 0 0",
        "R 1 0 0 0 0", f"R 1 {MAX_UNITS+1} 0 0 0",
        f"D 1 1 {S} 0 0 0", f"D 1 1 {S} 0 2 0",
        f"D {MAX_UNITS+1} 1 0 0 1 0", f"D 1 0 0 0 1 0",
        f"D 1 1 {S+1} 0 1 0",  # corrupt state
        f"R 1 1 0 2 1",         # clock moved backwards
        "T 1 0", f"T 1 {MAX_UNITS+1}",
    ]


def randomized_traces(seed: int = 0xD12A9, bucket_count: int = 24,
                      operations_per_bucket: int = 125) -> list[str]:
    rng = random.Random(seed)
    lines: list[str] = []
    for bucket_index in range(bucket_count):
        capacity = rng.choice([1, 2, 3, 10, 999_999_999, MAX_UNITS,
                               rng.randint(1, MAX_UNITS)])
        rate = rng.choice([1, 2, 3, 7, MAX_UNITS, rng.randint(1, MAX_UNITS)])
        balance = rng.randint(0, capacity * S)
        last = 0
        for operation_index in range(operations_per_bucket):
            # Mostly short intervals, with occasional large intervals that
            # trigger saturation. Timestamps remain monotone per bucket.
            elapsed = rng.choice([0, 1, 2, 999_999_999,
                                  rng.randint(0, 10**12)])
            now = last + elapsed
            cost = rng.randint(1, capacity)
            lines.append(f"D {capacity} {rate} {balance} {last} {cost} {now}")
            expected = oracle_decide(capacity, rate, balance, last, cost, now)
            parts = expected.split()
            if parts[0] != "OK" or parts[1] not in ("ALLOW", "LIMITED"):
                raise AssertionError(f"oracle emitted unexpected result: {expected}")
            balance, last = int(parts[2]), int(parts[3])
            if operation_index % 5 == 0:
                delta = rng.choice([0, 1, 1000, rng.randint(0, 10**9)])
                now = last + delta
                lines.append(f"R {capacity} {rate} {balance} {last} {now}")
                state = oracle_refill(capacity, rate, balance, last, now).split()
                balance, last = int(state[1]), int(state[2])
    return lines


class BucketMathOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not HEADER.is_file():
            raise FileNotFoundError(f"RG002 production header is required: {HEADER}")
        if not DRIVER_SOURCE.is_file():
            raise FileNotFoundError(f"independent driver is required: {DRIVER_SOURCE}")
        cls.temp = tempfile.TemporaryDirectory(prefix="rg002-oracle-")
        cls.temp_path = Path(cls.temp.name)
        cls.driver = cls.temp_path / "bucket_math_driver"
        compile_driver(cls.driver)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def test_golden_and_numeric_boundaries(self) -> None:
        check_cases(self.driver, golden_vectors())

    def test_invalid_and_corrupt_inputs_return_expected_errors(self) -> None:
        check_cases(self.driver, invalid_vectors())

    def test_seeded_arbitrary_precision_state_traces(self) -> None:
        check_cases(self.driver, randomized_traces())

    def _mutant_driver(self, name: str, old: str, new: str) -> Path:
        source = HEADER.read_text(encoding="utf-8")
        if old not in source:
            self.fail(f"mutation anchor not found for {name}")
        mutation_root = self.temp_path / f"mutant-{name}"
        header = mutation_root / "authority" / "bucket_math.h"
        header.parent.mkdir(parents=True, exist_ok=True)
        header.write_text(source.replace(old, new, 1), encoding="utf-8")
        executable = self.temp_path / f"driver-{name}"
        compile_driver(executable, header_override=header)
        return executable

    def test_reject_all_mutation_is_detected(self) -> None:
        mutant = self._mutant_driver(
            "reject-all", "BucketDecision{DecisionOutcome::Allow,",
            "BucketDecision{DecisionOutcome::Limited,")
        lines = ["D 10 1 8000000000 0 2 0"]
        self.assertNotEqual(run_driver(mutant, lines), [oracle_command(line) for line in lines])

    def test_double_debit_mutation_is_detected(self) -> None:
        mutant = self._mutant_driver(
            "double-debit", "available.balance_subunits - cost_subunits,",
            "available.balance_subunits - (cost_subunits * 2),")
        lines = ["D 10 1 8000000000 0 2 0"]
        self.assertNotEqual(run_driver(mutant, lines), [oracle_command(line) for line in lines])


if __name__ == "__main__":
    unittest.main()
