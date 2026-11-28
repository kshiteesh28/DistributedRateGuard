#!/usr/bin/env python3
"""Generate isolated, test-only strict-sequence mutants for negative controls.

Usage: generate_sequence_mutants.py PATH_TO_REFERENCE_MODEL_H OUTPUT_DIR
Each emitted mutant must compile; a separate CTest invocation runs the independent
fixture binary and expects its assertions to fail. Compile errors are not evidence.
"""
from pathlib import Path
import sys

MUTATIONS = {
    "reject_all": (
        "if (available >= cost_subunits) {",
        "if (false && available >= cost_subunits) {",
    ),
    "always_allow": (
        "if (available >= cost_subunits) {",
        "if (available >= cost_subunits || true) {",
    ),
    "limited_does_not_advance_time": (
        "next = {available, attempt.logical_time_ns};",
        "next = {available, current.last_refill_ns};",
    ),
    "debit_on_limited": (
        "next = {available, attempt.logical_time_ns};",
        "next = {available > cost_subunits ? available - cost_subunits : 0,\n"
        "                   attempt.logical_time_ns};",
    ),
    "floor_retry_delay": (
        "retry = quotient + (remainder != 0 ? 1U : 0U);",
        "retry = quotient;",
    ),
    "uses_first_operation_cost": (
        "const Units cost = tenant.operations[operation_found->second].cost_units;",
        "const Units cost = tenant.operations.front().cost_units;",
    ),
    "overcap_refill": (
        "if (elapsed >= ns_to_full) return capacity;",
        "if (elapsed >= ns_to_full) return capacity + 1;",
    ),
    "cross_tenant_state_lookup": (
        "const BucketView current = states[known_tenant_index];",
        "const BucketView current = states.front();",
    ),
    "unknown_tenant_default_admission": (
        "step.invalid_reason = InvalidReason::UnknownTenant;\n"
        "          result.steps.push_back(std::move(step));\n"
        "          continue;",
        "step.decision = Decision::Allow;\n"
        "          step.before = BucketView{0, attempt.logical_time_ns};\n"
        "          step.after = step.before;\n"
        "          result.steps.push_back(std::move(step));\n"
        "          continue;",
    ),
    "reorders_equal_time_attempts": (
        "StrictSequenceResult result;\n"
        "      result.steps.reserve(scenario.attempts.size());\n"
        "      for (const auto& attempt : scenario.attempts) {",
        "StrictSequenceResult result;\n"
        "      result.steps.reserve(scenario.attempts.size());\n"
        "      auto reordered_attempts = scenario.attempts;\n"
        "      std::stable_sort(reordered_attempts.begin(), reordered_attempts.end(),\n"
        "          [](const SyntheticAttempt& left, const SyntheticAttempt& right) {\n"
        "            if (left.logical_time_ns != right.logical_time_ns)\n"
        "              return left.logical_time_ns < right.logical_time_ns;\n"
        "            return left.operation_id > right.operation_id;\n"
        "          });\n"
        "      for (const auto& attempt : reordered_attempts) {",
    ),
    "unchecked_uint64_refill_product": (
        "if (elapsed >= ns_to_full) return capacity;",
        "if (elapsed >= ns_to_full) {\n"
        "      const Subunits wrapped = rate_units_per_second * elapsed;\n"
        "      return std::min<Subunits>(capacity, current.balance_subunits + wrapped);\n"
        "    }",
    ),
}


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: generate_sequence_mutants.py SOURCE_HEADER OUTPUT_DIR", file=sys.stderr)
        return 2
    source_path = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    try:
        original = source_path.read_text(encoding="utf-8")
    except OSError as error:
        print(f"cannot read source header: {error}", file=sys.stderr)
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, (anchor, replacement) in MUTATIONS.items():
        occurrences = original.count(anchor)
        if occurrences != 1:
            print(f"{name}: expected unique anchor once, found {occurrences}", file=sys.stderr)
            return 2
        mutant = original.replace(anchor, replacement, 1)
        target = output_dir / name / "tools" / "replay" / "reference_model.h"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(mutant, encoding="utf-8")
    print(f"generated {len(MUTATIONS)} uniquely anchored test-only mutants")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
