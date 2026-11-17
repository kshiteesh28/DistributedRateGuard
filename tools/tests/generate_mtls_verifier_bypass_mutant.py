#!/usr/bin/env python3
"""Generate a test-only custom-verifier bypass while retaining TLS chain checks."""
from __future__ import annotations

import argparse
from pathlib import Path


START = "bool PinnedPeerVerifier::Verify("
END = "\n\n}  // namespace rateguard::security"
MUTANT = '''bool PinnedPeerVerifier::Verify(
    grpc::experimental::TlsCustomVerificationCheckRequest* request,
    std::function<void(grpc::Status)> callback, grpc::Status* sync_status) {
  (void)request;
  (void)callback;
  if (sync_status != nullptr) *sync_status = grpc::Status::OK;
  return true;
}'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path,
                        help="production tls_certificate_verifier.cpp")
    parser.add_argument("--output", required=True, type=Path,
                        help="temporary test-only mutant source")
    args = parser.parse_args()
    source = args.source.read_text()
    if source.count(START) != 1 or source.count(END) != 1:
        raise SystemExit("verifier mutation anchors missing or ambiguous")
    begin = source.index(START)
    end = source.index(END, begin)
    if end <= begin:
        raise SystemExit("verifier mutation anchors are out of order")
    original_function = source[begin:end].rstrip()
    if "return true;" not in original_function or "*sync_status = grpc::Status::OK;" not in original_function:
        raise SystemExit("source verifier function does not match the reviewed implementation")
    mutant = source[:begin] + MUTANT + source[end:]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(mutant)
    print("generated test-only accept-all custom verifier; normal TLS chain checks remain configured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
