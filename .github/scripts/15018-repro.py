"""Reproduce actions/runner-images#15018 without changing certificate stores."""

import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time


ENDPOINTS = {
    "G3": "https://dv-g3b-emudhra.we-have-a-problem.com/",
    "AAA": "https://dv-g3b-aaa-emudhra.we-have-a-problem.com/",
}


def classify(returncode, stderr):
    if returncode == 0:
        return "ACCEPTED"
    if returncode == 60 or "CRYPT_E_REVOKED" in stderr:
        return "REJECTED"
    return "INCONCLUSIVE"


def run(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=75)
    return {
        "command": command,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def probe_url(executable, url):
    attempts = []
    for attempt in range(4):
        check = run(
            [
                executable,
                "-sS",
                "--connect-timeout", "15",
                "--max-time", "45",
                "-o", os.devnull,
                "--write-out", "http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\n",
                url,
            ]
        )
        check["result"] = classify(check["exit_code"], check["stderr"])
        attempts.append(check)
        if check["result"] != "INCONCLUSIVE":
            break
        print(f"Attempt {attempt + 1}: {url}: {check['stderr']}", flush=True)
        if attempt < 3:
            time.sleep(2)
    return {**attempts[-1], "attempts": attempts}


def table(results):
    lines = [
        "| Image | Image version | curl | G3 | AAA |",
        "|---|---|---|---|---|",
    ]
    for result in sorted(results, key=lambda item: item["label"]):
        for binary in result["binaries"]:
            cells = [
                result["label"],
                result["image_version"],
                binary["name"],
            ]
            for chain in ENDPOINTS:
                probe = binary["probes"][chain]
                cells.append(f'{probe["result"]} (exit {probe["exit_code"]})')
            lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def probe():
    output = Path(os.environ["RUNNER_TEMP"]) / "emudhra-15018"
    output.mkdir(parents=True, exist_ok=True)
    curl = shutil.which("curl")
    if curl is None:
        raise RuntimeError("curl is not available on PATH")
    binaries = [("PATH", curl)]
    if platform.system() == "Darwin":
        binaries.append(("/usr/bin/curl", "/usr/bin/curl"))
    elif platform.system() == "Windows":
        binaries.append(
            ("System32/curl.exe", str(Path(os.environ["SystemRoot"]) / "System32/curl.exe"))
        )

    result = {
        "label": os.environ["RUNNER_LABEL"],
        "image_os": os.environ.get("ImageOS", "not provided"),
        "image_version": os.environ.get("ImageVersion") or "not provided (see job setup)",
        "architecture": os.environ["RUNNER_ARCH"],
        "platform": platform.platform(),
        "binaries": [],
    }
    if shutil.which("dpkg-query"):
        result["ca_certificates"] = run(
            ["dpkg-query", "-W", "-f=${Package} ${Version}\n", "ca-certificates"]
        )
    for name, executable in binaries:
        version = run([executable, "--version"])
        if version["exit_code"] != 0:
            raise RuntimeError(f"Cannot query {executable}: {version}")
        binary = {"name": name, "path": executable, "version": version, "probes": {}}
        for chain, url in ENDPOINTS.items():
            binary["probes"][chain] = probe_url(executable, url)
        result["binaries"].append(binary)
    evidence = json.dumps(result, indent=2)
    (output / "result.json").write_text(evidence + "\n", encoding="utf-8")
    print(evidence)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(table([result]))


def report(directory):
    root = Path(directory)
    results = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in root.glob("*/result.json")
    ]
    if not results:
        raise RuntimeError("No image results were downloaded")
    text = (
        "# eMudhra certificate trust reproduction\n\n"
        "Source: https://github.com/actions/runner-images/issues/15018\n\n"
        "ACCEPTED = TLS connection succeeded (issue reproduced for this chain). "
        "REJECTED = certificate verification failed or Windows reported CRYPT_E_REVOKED. "
        "INCONCLUSIVE = another error; inspect result.json before drawing conclusions.\n\n"
        "No trust-store updates, insecure flags, revocation bypasses, or credentials are used. "
        "G3 and AAA are the two public demonstration endpoints from the issue. "
        "Image versions are read from the actual runner, not the repository documentation.\n\n"
        "Only inconclusive errors are retried (up to four attempts, two seconds apart); "
        "all attempts are retained. A definitive acceptance or rejection is not retried. "
        "If ImageVersion is empty (ubuntu-slim), consult the VM Image section of job setup.\n\n"
        + table(results)
        + "\nRaw artifacts contain curl versions, executable paths, commands, exit codes, "
        "stderr, platform/architecture, and the Ubuntu ca-certificates package version.\n"
    )
    (root / "report.md").write_text(text, encoding="utf-8")
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
        summary.write(text)
    print(text)


if __name__ == "__main__":
    if sys.argv[1:] == ["probe"]:
        probe()
    elif len(sys.argv) == 3 and sys.argv[1] == "report":
        report(sys.argv[2])
    else:
        raise SystemExit("Usage: 15018-repro.py probe | report RESULTS_DIRECTORY")
