import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    "diagnostics", Path(__file__).with_name("15003-diagnostics.py")
)
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DiagnosticsTests(unittest.TestCase):
    def test_parse_real_map_format(self):
        counts = diagnostics.parse_counts(
            "READY\nREADY\n\n@openat[2]: 20\n@control[2]: 41\n@control[7]: 40\n"
        )
        self.assertEqual(counts, {"openat": {2: 20}, "control": {2: 41, 7: 40}})

    def test_duplicate_maps_rejected(self):
        with self.assertRaises(ValueError):
            diagnostics.parse_counts("@openat[2]: 20\n@openat[2]: 20\n")

    def test_outcomes_on_noncontiguous_cpu_ids(self):
        cases = [
            ({2: 20, 7: 20}, {2: 40, 7: 40}, "NOT_REPRODUCED"),
            ({2: 20}, {2: 40, 7: 40}, "REPRODUCED"),
            ({7: 20}, {2: 40, 7: 40}, "REPRODUCED"),
            ({2: 20, 7: 3}, {2: 40, 7: 40}, "REPRODUCED"),
            ({}, {2: 40, 7: 40}, "INCONCLUSIVE"),
            ({2: 20}, {2: 40}, "INCONCLUSIVE"),
            ({2: 20, 7: 20}, {2: 40, 7: 39}, "INCONCLUSIVE"),
            ({2: 21, 7: 20}, {2: 42, 7: 40}, "INCONCLUSIVE"),
            ({0: 20, 2: 20}, {2: 40, 7: 40}, "INCONCLUSIVE"),
            ({2: 20, 7: 20}, {0: 40, 2: 40, 7: 40}, "INCONCLUSIVE"),
        ]
        for openat, control, expected in cases:
            with self.subTest(openat=openat, control=control):
                status, _ = diagnostics.evaluate(
                    [2, 7], {"openat": openat, "control": control}, 20
                )
                self.assertEqual(status, expected)

    def test_single_cpu_inconclusive(self):
        status, _ = diagnostics.evaluate([2], {"openat": {2: 20}, "control": {2: 40}}, 20)
        self.assertEqual(status, "INCONCLUSIVE")

    def test_ready_requires_live_tracer(self):
        process = Mock()
        process.poll.return_value = 1
        process.returncode = 1
        with self.assertRaisesRegex(RuntimeError, "before readiness"):
            diagnostics.wait_ready(process, Mock())

    def test_readiness_and_timeout(self):
        process = Mock()
        process.poll.return_value = None
        log = Mock()
        log.read_text.return_value = "READY\n"
        diagnostics.wait_ready(process, log)
        with self.assertRaises(TimeoutError):
            diagnostics.wait_ready(process, log, timeout=0)

    def test_stop_timeout_kills_and_reaps_tracer(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("bpftrace", 15), 0]
        with self.assertRaises(TimeoutError):
            diagnostics.stop_tracer(process)
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_count, 2)

    def test_workload_failure_still_stops_tracer(self):
        process = Mock()
        with tempfile.TemporaryDirectory() as directory, (
            patch.object(diagnostics.subprocess, "Popen", return_value=process)
        ), patch.object(diagnostics, "wait_ready"), patch.object(
            diagnostics, "stop_tracer"
        ) as stop, patch.object(
            diagnostics.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(1, "workload"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                diagnostics.trace(Path(directory), [2, 7])
            stop.assert_called_once_with(process)

    def test_main_persists_each_exit_status(self):
        for counts, expected_status, expected_exit in [
            ({"openat": {2: 20, 7: 20}, "control": {2: 40, 7: 40}}, "NOT_REPRODUCED", 0),
            ({"openat": {2: 20}, "control": {2: 40, 7: 40}}, "REPRODUCED", 1),
            ({"openat": {}, "control": {}}, "INCONCLUSIVE", 2),
            (RuntimeError("tracer failed"), "INCONCLUSIVE", 2),
        ]:
            with self.subTest(status=expected_status), tempfile.TemporaryDirectory() as directory:
                with (
                    patch.object(diagnostics.sys, "argv", ["diagnostics", "--output", directory]),
                    patch.object(diagnostics.sys, "platform", "linux"),
                    patch.object(diagnostics.os, "geteuid", return_value=0),
                    patch.object(
                        diagnostics.os, "sched_getaffinity", create=True, return_value={2, 7}
                    ),
                    patch.object(diagnostics, "trace") as trace,
                    patch("builtins.print"),
                ):
                    if isinstance(counts, Exception):
                        trace.side_effect = counts
                    else:
                        trace.return_value = counts
                    self.assertEqual(diagnostics.main(), expected_exit)
                saved = json.loads((Path(directory) / "result.json").read_text())
                self.assertEqual(saved["status"], expected_status)
                if isinstance(counts, Exception):
                    self.assertIn("tracer failed", saved["reason"])

    def test_persistent_results_and_step_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            result = {
                "status": "REPRODUCED",
                "reason": "Missing events.",
                "runner_label": "ubuntu-24.04",
                "image_version": "20261018.339",
                "kernel": "7.0.0-1017-azure",
                "architecture": "x86_64",
                "allowed_cpus": [2, 7],
                "counts": {"openat": {2: 20}, "control": {2: 40, 7: 40}},
            }
            diagnostics.write_result(output, output / "step-summary", result)
            self.assertIn('"7": 40', (output / "result.json").read_text())
            summary = (output / "summary.md").read_text()
            self.assertIn("| 7 | 0 | 40 |", summary)
            self.assertEqual(summary, (output / "step-summary").read_text())


if __name__ == "__main__":
    unittest.main()
