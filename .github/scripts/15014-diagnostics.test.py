import base64
from contextlib import redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "diagnostics", Path(__file__).with_name("15014-diagnostics.py")
)
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)

TOKEN = "github_pat_TEST"
REPOSITORY = "test/private"


class DiagnosticsTests(unittest.TestCase):
    def compare(self, results):
        with patch.object(diagnostics, "probe", side_effect=results), \
                patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}), \
                redirect_stdout(io.StringIO()) as output:
            code = diagnostics.compare(REPOSITORY, TOKEN)
        return code, output.getvalue()

    def test_reproduced_and_workaround_passes(self):
        code, output = self.compare(
            [(128, "fatal: could not read Username"), (0, "")] * 2
        )
        self.assertEqual(code, 0)
        self.assertIn("Issue signature reproduced", output)

    def test_both_pass_is_not_a_reproduction(self):
        code, output = self.compare([(0, "")] * 4)
        self.assertEqual(code, 0)
        self.assertIn("Not reproduced", output)

    def test_different_failure_is_not_claimed_as_reproduced(self):
        code, output = self.compare([(128, "TLS failure"), (0, "")] * 2)
        self.assertEqual(code, 1)
        self.assertIn("Inconclusive", output)

    def test_failed_workaround_fails_job(self):
        code, output = self.compare(
            [(128, "could not read Username"), (128, "access denied")] * 2
        )
        self.assertEqual(code, 1)
        self.assertIn("workaround failed", output)

    def test_redacts_credentials_and_repository(self):
        encoded = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
        encoded_empty = base64.b64encode(f"{TOKEN}:".encode()).decode()
        text = f"https://{TOKEN}@github.com/{REPOSITORY} {encoded} {encoded_empty}"
        output = diagnostics.redact(text, TOKEN, REPOSITORY)
        for secret in (TOKEN, REPOSITORY, encoded, encoded_empty):
            self.assertNotIn(secret, output)

    def test_probe_isolates_configuration_and_discards_refs(self):
        results = [
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.CompletedProcess([], 128, "PRIVATE_REF", f"fatal: {TOKEN} {REPOSITORY}"),
        ]
        with patch.dict(os.environ, {
            "GIT_TRACE": "1", "GIT_CURL_VERBOSE": "1",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
            "GIT_CONFIG_VALUE_0": "Authorization: inherited",
        }), patch.object(diagnostics.subprocess, "run", side_effect=results) as run:
            code, error = diagnostics.probe(REPOSITORY, TOKEN, TOKEN, "")
        self.assertEqual(code, 128)
        self.assertNotIn("PRIVATE_REF", error)
        self.assertNotIn(TOKEN, error)
        self.assertNotIn(REPOSITORY, error)
        env = run.call_args.kwargs["env"]
        self.assertNotIn("GIT_TRACE", env)
        self.assertNotIn("GIT_CURL_VERBOSE", env)
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        self.assertNotIn("PAT", env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertFalse(Path(env["GIT_CONFIG_GLOBAL"]).parent.exists())
        self.assertEqual(run.call_args.args[0][-1], f"https://github.com/{REPOSITORY}")

    def test_timeout_is_explicit(self):
        with patch.object(diagnostics.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, "", ""),
            subprocess.TimeoutExpired("git", 120),
        ]):
            code, error = diagnostics.probe(REPOSITORY, TOKEN, TOKEN, ".git")
        self.assertEqual(code, 124)
        self.assertIn("timed out", error)

    def test_actual_git_rewrite_for_both_credential_formats(self):
        actual_run = subprocess.run
        for credentials in (TOKEN, f"x-access-token:{TOKEN}"):
            with self.subTest(credentials=credentials):
                def run_without_network(command, **kwargs):
                    if "ls-remote" in command:
                        result = actual_run(
                            command[:-4] + ["ls-remote", "--get-url", command[-1]], **kwargs
                        )
                        self.assertEqual(result.returncode, 0)
                        self.assertEqual(
                            result.stdout.strip(),
                            f"https://{credentials}@github.com/{REPOSITORY}.git",
                        )
                        return subprocess.CompletedProcess(command, 0, result.stdout, "")
                    return actual_run(command, **kwargs)

                with patch.object(diagnostics.subprocess, "run", side_effect=run_without_network):
                    self.assertEqual(
                        diagnostics.probe(REPOSITORY, TOKEN, credentials, ".git"), (0, "")
                    )

    def test_summary_is_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            summary = Path(directory) / "summary.md"
            with patch.object(diagnostics, "probe", return_value=(0, "")), \
                    patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostics.compare(REPOSITORY, TOKEN), 0)
            text = summary.read_text()
            self.assertIn("| no suffix (issue) | PASS (0) | PASS (0) |", text)
            self.assertIn("| .git | PASS (0) | PASS (0) |", text)
            self.assertIn("Not reproduced", text)
            self.assertNotIn(TOKEN, text)
            self.assertNotIn(REPOSITORY, text)

    def test_public_target_is_rejected(self):
        with patch.object(diagnostics.urllib.request, "urlopen"), \
                patch.object(diagnostics.json, "load", return_value={"private": False}):
            with self.assertRaisesRegex(RuntimeError, "must be private"):
                diagnostics.require_private_repository(REPOSITORY, TOKEN)

    def test_missing_pat_fails_before_network(self):
        with patch.dict(os.environ, {"PAT": "", "PRIVATE_REPOSITORY": REPOSITORY}), \
                patch.object(diagnostics, "require_private_repository") as preflight, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(diagnostics.main(), 1)
        preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()
