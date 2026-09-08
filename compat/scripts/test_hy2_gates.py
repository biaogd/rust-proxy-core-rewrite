"""Regression tests for evidence gates (no network or Go binary required)."""

import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import phase5b1a
from phase_hy2c_hysteria2 import process_fd_count, process_rss_kib
from phase_hy2c_hysteria2_soak import resource_verdict, soak_seconds


class EvidenceGateTests(unittest.TestCase):
    def test_missing_samples_fail_closed(self):
        for samples in ([], [{"rss": 1024, "fd": None}] * 12, [{"rss": None, "fd": 10}] * 12):
            self.assertFalse(resource_verdict(samples, 60)["rss-bounded"])
            self.assertFalse(resource_verdict(samples, 60)["fd-bounded"])

    def test_stable_samples_pass(self):
        result = resource_verdict([{"rss": 50000, "fd": 12}] * 12, 60)
        self.assertTrue(result["rss-bounded"])
        self.assertTrue(result["fd-bounded"])

    def test_growth_fails(self):
        samples = [{"rss": 50000 + i * 10000, "fd": 10 + i * 20} for i in range(12)]
        result = resource_verdict(samples, 60)
        self.assertFalse(result["rss-bounded"])
        self.assertFalse(result["fd-bounded"])

    def test_sparse_samples_fail(self):
        self.assertFalse(resource_verdict([{"rss": 50000, "fd": 12}] * 2, 7200)["samples-complete"])

    def test_production_requires_release_and_long_duration(self):
        for profile, duration in (("debug", "7200"), ("release", "120")):
            with patch.dict(os.environ, {"HY2_PRODUCTION_GATE": "1", "HY2_BUILD_PROFILE": profile, "HY2C_SOAK_SECONDS": duration}):
                with self.assertRaises(ValueError):
                    soak_seconds()
        with patch.dict(os.environ, {"HY2_PRODUCTION_GATE": "1", "HY2_BUILD_PROFILE": "release", "HY2C_SOAK_SECONDS": "7200"}):
            self.assertEqual(soak_seconds(), 7200)

    def test_native_process_resources_are_measured(self):
        self.assertGreater(process_rss_kib(os.getpid()), 0)
        self.assertGreater(process_fd_count(os.getpid()), 0)

    def test_staged_runtime_is_an_independent_copy(self):
        suffix = ".exe" if os.name == "nt" else ""
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            target = root / "external-target"
            (target / "release").mkdir(parents=True)
            source = target / "release" / f"rewrite-core{suffix}"
            source.write_bytes(b"exact-executable-bytes")
            with patch.object(phase5b1a, "assert_go_oracle_baseline"), patch.object(phase5b1a, "cargo_target_path", return_value=target), patch.object(phase5b1a.subprocess, "run") as run:
                binaries = phase5b1a.build_binaries(root, profile="release", stage_runtime=True)
            self.assertEqual(binaries["rust"].read_bytes(), source.read_bytes())
            self.assertNotEqual(binaries["rust"], source)
            self.assertIn("--release", run.call_args_list[1].args[0])
            source.write_bytes(b"rebuilt")
            self.assertEqual(binaries["rust"].read_bytes(), b"exact-executable-bytes")


if __name__ == "__main__":
    unittest.main()
