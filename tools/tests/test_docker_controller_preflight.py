from __future__ import annotations

import argparse
import importlib.util
import json
import os
import socket
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock


DRIVER = Path(__file__).resolve().parents[1] / "probes/docker_controller_preflight.py"
SPEC = importlib.util.spec_from_file_location("docker_controller_preflight", DRIVER)
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


def observation(*, mismatch: bool = False) -> dict:
    identity = ["01" * 16, "1", "2", "0", "0", "0", "0", "1"]
    other = list(identity)
    if mismatch:
        other[-2] = "1"
    sample = lambda fields: {"identity_fields": fields}
    clock = lambda fields: {"return_code": 0, "error": None, "sample": sample(fields)}
    wall = {"return_code": 0, "error": None, "valid_json": True,
            "probe": {"trusted": True, "failure_reason": None, "sync_state": 0, "status_flags": 0}}
    return {
        "schema_version": 1,
        "readiness": {"state": "OBSERVATIONS_MATCHED", "reason": None,
                      "comparison": {"identity_fields_match": True, "monotonic_samples_ordered": True}},
        "host": {"clock_before": clock(identity), "clock_after": clock(other if mismatch else identity),
                 "wall_before": dict(wall), "wall_after": dict(wall)},
        "container": {"clock": clock(identity), "wall": dict(wall)},
        "docker": {"repo_digest": "example/image@sha256:" + "a" * 64,
                   "image_id": "sha256:" + "b" * 64},
    }


class FakeSocket:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.offset = 0
        self.closed = False
        self.sent = bytearray()

    def settimeout(self, _value):
        pass

    def connect(self, _path):
        pass

    def getsockopt(self, _level, _option, _length):
        return struct.pack("3i", 123, 0, 0)

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, count):
        if self.offset >= len(self.payload):
            return b""
        result = self.payload[self.offset:self.offset + count]
        self.offset += len(result)
        return result

    def close(self):
        self.closed = True


def version_http(body: bytes, headers: bytes = b"Content-Length: ") -> bytes:
    if headers == b"Content-Length: ":
        headers += str(len(body)).encode("ascii") + b"\r\nConnection: close\r\n"
    return b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + body


class PreflightDriverTests(unittest.TestCase):
    def test_probe_diagnostics_preserve_only_fixed_status_enums(self):
        result = {"setup_stage": "docker_controller_factory", "checks": {"status": [
            "matched_running", "controller_error_6", "controller_error_7_possibly_sent",
            "unknown_reason_15", "already_stopped", "not_run", "secret-value", {"secret": "value"}]}}
        self.assertEqual(preflight._safe_probe_diagnostics(result), {
            "probe_setup_stage": "docker_controller_factory", "probe_status_codes": [
                "matched_running", "controller_error_6", "controller_error_7_possibly_sent",
                "unknown_reason_15", "already_stopped", "not_run", "unrecognized", "unrecognized"]})

    def test_probe_diagnostics_drop_untrusted_stage_and_oversized_status_list(self):
        self.assertEqual(preflight._safe_probe_diagnostics({
            "setup_stage": "private child output", "checks": {"status": ["matched_running"] * 9}}), {})
        self.assertEqual(preflight._safe_probe_diagnostics({"setup_stage": [], "checks": None}), {})

    def _run_to_create_with_image_inspect(self, image_reply: bytes) -> list[tuple[str, ...]]:
        calls: list[tuple[str, ...]] = []
        def docker(_docker, _env, *args, timeout=30):
            del timeout
            calls.append(args)
            if args[:3] == ("image", "inspect", "--format"):
                return image_reply
            if args[0] == "create":
                raise RuntimeError("stop after image verification")
            return b""

        with tempfile.TemporaryDirectory() as td:
            probe = Path(td) / "probe"
            probe.write_text("#!/bin/sh\nexit 0\n")
            probe.chmod(0o700)
            args = argparse.Namespace(probe=str(probe), clock_observation="unused", output="unused")
            with mock.patch.object(preflight.sys, "platform", "linux"), \
                 mock.patch.object(preflight, "_read_json", return_value=observation()), \
                 mock.patch.object(preflight, "_clock_fields", return_value=([], {})), \
                 mock.patch.object(preflight, "_repo_digest", return_value=(
                     "example/image@sha256:" + "a" * 64, "sha256:" + "b" * 64)), \
                 mock.patch.object(preflight, "_http_get_version", return_value={
                     "api_version": "1.57", "min_api_version": "1.42", "engine_version": "test"}), \
                 mock.patch.object(preflight.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), \
                 mock.patch.object(preflight, "_docker", side_effect=docker), \
                 mock.patch.object(preflight, "_inspect", return_value={}):
                with self.assertRaisesRegex(RuntimeError, "stop after image verification"):
                    preflight.run(args)
        return calls

    def fake_http(self, response: bytes):
        fake = FakeSocket(response)
        sock_stat = os.stat_result((stat.S_IFSOCK | 0o600, 1, 1, 1, 0, 0, 0, 0, 0, 0))
        return fake, mock.patch.object(preflight.os, "stat", return_value=sock_stat), \
            mock.patch.object(preflight.socket, "socket", return_value=fake), \
            mock.patch.object(preflight.socket, "SO_PEERCRED", 17, create=True)

    def test_observation_mismatch_fails_before_any_docker_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            probe = Path(td) / "probe"
            probe.write_text("#!/bin/sh\nexit 0\n")
            probe.chmod(0o700)
            args = argparse.Namespace(probe=str(probe), clock_observation="unused", output="unused")
            docker_calls = mock.Mock()
            with mock.patch.object(preflight.sys, "platform", "linux"), \
                 mock.patch.object(preflight, "_read_json", return_value=observation(mismatch=True)), \
                 mock.patch.object(preflight, "_docker", docker_calls), \
                 mock.patch.object(preflight, "_http_get_version", side_effect=AssertionError("must not reach Docker")):
                with self.assertRaises(preflight.PreflightError) as error:
                    preflight.run(args)
            self.assertEqual(error.exception.code, "clock_identity_mismatch")
            docker_calls.assert_not_called()

    def test_boolean_schema_version_fails_before_any_docker_mutation(self):
        invalid = observation()
        invalid["schema_version"] = True  # bool is an int subclass in Python.
        with tempfile.TemporaryDirectory() as td:
            probe = Path(td) / "probe"
            probe.write_text("#!/bin/sh\nexit 0\n")
            probe.chmod(0o700)
            args = argparse.Namespace(probe=str(probe), clock_observation="unused", output="unused")
            docker_calls = mock.Mock()
            with mock.patch.object(preflight.sys, "platform", "linux"), \
                 mock.patch.object(preflight, "_read_json", return_value=invalid), \
                 mock.patch.object(preflight, "_docker", docker_calls), \
                 mock.patch.object(preflight, "_http_get_version", side_effect=AssertionError("must not reach Docker")):
                with self.assertRaises(preflight.PreflightError) as error:
                    preflight.run(args)
            self.assertEqual(error.exception.code, "clock_observation_invalid")
            docker_calls.assert_not_called()

    def test_duplicate_observation_keys_rejected_before_docker(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "observation.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaises(preflight.PreflightError) as error:
                preflight._read_json(str(path), preflight.MAX_OBSERVATION)
            self.assertEqual(error.exception.code, "duplicate_json_key")

    def test_clock_readiness_requires_all_three_exact_identity_snapshots(self):
        with self.assertRaises(preflight.PreflightError) as error:
            preflight._clock_fields(observation(mismatch=True))
        self.assertEqual(error.exception.code, "clock_identity_mismatch")
        bad = observation()
        bad["readiness"]["comparison"]["monotonic_samples_ordered"] = False
        with self.assertRaises(preflight.PreflightError) as error:
            preflight._clock_fields(bad)
        self.assertEqual(error.exception.code, "clock_observation_not_matched")

    def test_http_version_accepts_chunked_and_eof_delimited_json(self):
        body = b'{"ApiVersion":"1.57","MinAPIVersion":"1.42","Version":"test"}'
        chunked = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
                   f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n")
        eof = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n" + body
        for response in (chunked, eof):
            fake, patch_stat, patch_socket, patch_peercred = self.fake_http(response)
            with patch_stat, patch_socket, patch_peercred:
                result = preflight._http_get_version(preflight.DOCKER_SOCKET)
            self.assertEqual(result["api_version"], "1.57")
            self.assertTrue(fake.closed)
            self.assertTrue(fake.sent.startswith(b"GET /version HTTP/1.1\r\n"))

    def test_http_version_rejects_conflicting_or_duplicate_framing(self):
        body = b'{"ApiVersion":"1.57","MinAPIVersion":"1.42"}'
        malformed = (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: " +
            str(len(body)).encode() + b"\r\n\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        )
        for response in malformed:
            fake, patch_stat, patch_socket, patch_peercred = self.fake_http(response)
            with patch_stat, patch_socket, patch_peercred:
                with self.assertRaises(preflight.PreflightError):
                    preflight._http_get_version(preflight.DOCKER_SOCKET)
            self.assertTrue(fake.closed)

    def test_image_inspect_uses_one_format_value_and_one_qualified_reference(self):
        repo_digest = "example/image@sha256:" + "a" * 64
        image_id = "sha256:" + "b" * 64
        calls = self._run_to_create_with_image_inspect(
            (image_id + "|" + json.dumps([repo_digest])).encode("ascii"))
        image_calls = [args for args in calls if args[:2] == ("image", "inspect")]
        self.assertEqual(len(image_calls), 1)
        args = image_calls[0]
        self.assertEqual(args, ("image", "inspect", "--format",
                                "{{.Id}}|{{json .RepoDigests}}", repo_digest))
        self.assertEqual(args.count("--format"), 1)
        self.assertEqual(args.count(repo_digest), 1)

    def test_image_inspect_rejects_malformed_repo_digests_before_create(self):
        repo_digest = "example/image@sha256:" + "a" * 64
        image_id = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as td:
            probe = Path(td) / "probe"
            probe.write_text("#!/bin/sh\nexit 0\n")
            probe.chmod(0o700)
            args = argparse.Namespace(probe=str(probe), clock_observation="unused", output="unused")
            calls: list[tuple[str, ...]] = []
            def docker(_docker, _env, *docker_args, timeout=30):
                del timeout
                calls.append(docker_args)
                if docker_args[:2] == ("image", "inspect"):
                    return (image_id + "|not-json").encode("ascii")
                return b""
            with mock.patch.object(preflight.sys, "platform", "linux"), \
                 mock.patch.object(preflight, "_read_json", return_value=observation()), \
                 mock.patch.object(preflight, "_clock_fields", return_value=([], {})), \
                 mock.patch.object(preflight, "_repo_digest", return_value=(repo_digest, image_id)), \
                 mock.patch.object(preflight, "_http_get_version", return_value={
                     "api_version": "1.57", "min_api_version": "1.42", "engine_version": "test"}), \
                 mock.patch.object(preflight.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), \
                 mock.patch.object(preflight, "_docker", side_effect=docker):
                with self.assertRaises(preflight.PreflightError) as error:
                    preflight.run(args)
            self.assertEqual(error.exception.code, "qualified_image_inspect_invalid")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0], ("image", "inspect", "--format",
                                        "{{.Id}}|{{json .RepoDigests}}", repo_digest))
        self.assertNotIn(("create",), calls)

    def test_inspect_pipe_parser_rejects_noncanonical_bool_and_pid(self):
        cid = "a" * 64
        labels = ["value"] * len(preflight.LABELS)
        valid = "|".join([cid, "/fixture", "running", "true", "false", "123", "no", *labels]).encode()
        with mock.patch.object(preflight, "_docker", return_value=valid):
            parsed = preflight._inspect("docker", {}, cid)
        self.assertIs(parsed["State"]["Running"], True)
        self.assertEqual(parsed["State"]["Pid"], 123)
        for running, pid in (("True", "123"), ("true", "01"), ("true", str(1 << 64))):
            malformed = "|".join([cid, "/fixture", "running", running, "false", pid, "no", *labels]).encode()
            with mock.patch.object(preflight, "_docker", return_value=malformed):
                with self.assertRaises(preflight.PreflightError) as error:
                    preflight._inspect("docker", {}, cid)
            self.assertEqual(error.exception.code, "docker_inspect_invalid")

    def test_cleanup_never_removes_container_with_wrong_binding(self):
        # Exercise the harness finally-block after it has created an exact CID.
        # The second inspect presents a different private label tuple; no rm is allowed.
        cid = "c" * 64
        events: list[tuple[str, tuple[str, ...]]] = []
        def docker(_docker, _env, *args, timeout=30):
            events.append(("docker", args))
            if args[0] == "image":
                digests = json.dumps(["example/image@sha256:" + "a" * 64])
                return ("sha256:" + "b" * 64 + "|" + digests).encode()
            if args[0] == "create":
                return cid.encode()
            return b""
        first_inspect = {"Id": cid, "Name": "/wrong-name",
                         "State": {"Status": "created", "Running": False, "Restarting": False, "Pid": 0},
                         "HostConfig": {"RestartPolicy": {"Name": "no"}},
                         "Config": {"Labels": {}}}
        inspected = []
        def inspect(*_args):
            inspected.append(1)
            return first_inspect
        with tempfile.TemporaryDirectory() as td:
            probe = Path(td) / "probe"
            probe.write_text("#!/bin/sh\nexit 0\n")
            probe.chmod(0o700)
            args = argparse.Namespace(probe=str(probe), clock_observation="unused", output="unused")
            with mock.patch.object(preflight.sys, "platform", "linux"), \
                 mock.patch.object(preflight, "_read_json", return_value=observation()), \
                 mock.patch.object(preflight, "_clock_fields", return_value=([], {})), \
                 mock.patch.object(preflight, "_repo_digest", return_value=(
                     "example/image@sha256:" + "a" * 64, "sha256:" + "b" * 64)), \
                 mock.patch.object(preflight, "_http_get_version", return_value={
                     "api_version": "1.57", "min_api_version": "1.42", "engine_version": "test"}), \
                 mock.patch.object(preflight.shutil, "which", side_effect=lambda name: "/usr/bin/" + name), \
                 mock.patch.object(preflight, "_docker", side_effect=docker), \
                 mock.patch.object(preflight, "_inspect", side_effect=inspect):
                with self.assertRaises(preflight.PreflightError):
                    preflight.run(args)
        self.assertEqual(len(inspected), 2)  # initial validation plus one cleanup recheck
        self.assertFalse(any(call[1][0] == "rm" for call in events))


if __name__ == "__main__":
    unittest.main()
