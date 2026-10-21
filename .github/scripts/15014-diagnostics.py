"""Compare username-only Git credentials with the workaround for runner-images#15014."""

import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request


def redact(text, token, repository):
    for value in (
        base64.b64encode(f"x-access-token:{token}".encode()).decode(),
        base64.b64encode(f"{token}:".encode()).decode(),
        token,
        repository,
    ):
        text = text.replace(value, "[REDACTED]")
    return re.sub(r"https://[^/\s]*@github\.com/", "https://[REDACTED]@github.com/", text)


def require_private_repository(repository, token):
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            metadata = json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"Repository preflight returned HTTP {error.code}; check PAT access and SSO authorization."
        ) from None
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise RuntimeError(f"Repository preflight failed ({type(error).__name__}).") from None
    if not isinstance(metadata, dict) or metadata.get("private") is not True:
        raise RuntimeError("The target must be private; a public repository cannot validate this bug.")


def probe(repository, token, credentials, suffix):
    # Do not inherit checkout credentials, local configuration, helpers, or tracing.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("GIT_", "GCM_"))
        and key not in ("PAT", "GH_TOKEN", "GITHUB_TOKEN")
    }
    with tempfile.TemporaryDirectory(prefix="git-15014-") as directory:
        env.update(
            HOME=directory,
            XDG_CONFIG_HOME=directory,
            GIT_CONFIG_GLOBAL=str(Path(directory) / ".gitconfig"),
            GIT_CONFIG_NOSYSTEM="1",
            GIT_TERMINAL_PROMPT="0",
            GIT_ASKPASS="/bin/false",
            GCM_INTERACTIVE="Never",
        )
        command = [
            "git", "-c", "credential.helper=", "-c", "http.extraHeader=",
            "-c", "http.followRedirects=initial", "-c", "protocol.version=2",
        ]
        result = subprocess.run(
            ["git", "config", "--global", f"url.https://{credentials}@github.com/.insteadOf",
             "https://github.com/"],
            env=env, cwd=directory, capture_output=True, text=True, timeout=30,
        )
        if result.returncode:
            raise RuntimeError("Could not configure the isolated Git URL rewrite.")
        try:
            result = subprocess.run(
                command + ["ls-remote", "-q", "--end-of-options",
                           f"https://github.com/{repository}{suffix}"],
                env=env, cwd=directory, capture_output=True, text=True, timeout=120,
            )
        except subprocess.TimeoutExpired:
            return 124, "Git timed out after 120 seconds."
        # stdout contains private ref names and is deliberately discarded.
        return result.returncode, redact(result.stderr, token, repository)


def compare(repository, token):
    rows = []
    failed = False
    reproduced = False
    for suffix, label in (("", "no suffix (issue)"), (".git", ".git")):
        baseline_code, baseline_error = probe(repository, token, token, suffix)
        fixed_code, fixed_error = probe(repository, token, f"x-access-token:{token}", suffix)
        signature = baseline_code != 0 and "could not read Username" in baseline_error
        reproduced = reproduced or signature
        failed = failed or fixed_code != 0 or (baseline_code != 0 and not signature)
        baseline = "PASS" if baseline_code == 0 else (
            "FAIL: issue signature" if signature else "FAIL: different error"
        )
        rows.append(f"| {label} | {baseline} ({baseline_code}) | "
                    f"{'PASS' if fixed_code == 0 else 'FAIL'} ({fixed_code}) |")
        for mode, code, error in (
            ("Original", baseline_code, baseline_error),
            ("Workaround", fixed_code, fixed_error),
        ):
            print(f"{label} / {mode}: exit {code}")
            if code:
                # Prefix every line so remote stderr cannot inject Actions commands.
                for line in error.splitlines():
                    print(f"  git: {line}")
    if failed:
        conclusion = "Inconclusive or workaround failed; inspect the errors above."
    elif reproduced:
        conclusion = "Issue signature reproduced; x-access-token:<PAT> succeeded on the same VM."
    else:
        conclusion = "Not reproduced on this VM; both credential formats succeeded."
    summary = "\n".join([
        "## Private Git authentication: runner-images#15014",
        "",
        f"Image version: `{os.environ.get('ImageVersion', 'unknown')}`",
        "",
        "| URL suffix | PAT as username | x-access-token:PAT |",
        "| --- | --- | --- |",
        *rows,
        "",
        conclusion,
        "",
    ])
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
            output.write(summary)
    return 1 if failed else 0


def main():
    repository = os.environ.get("PRIVATE_REPOSITORY", "")
    token = os.environ.get("PAT", "")
    try:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise RuntimeError("Set secret REPRO_REPO to owner/repo.")
        if repository.endswith(".git"):
            raise RuntimeError("Use owner/repo without the .git suffix.")
        if not re.fullmatch(r"[A-Za-z0-9_]+", token):
            raise RuntimeError("Set secret PAT to a GitHub personal access token.")
        require_private_repository(repository, token)
        return compare(repository, token)
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"::error::{redact(str(error), token, repository) if token and repository else error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
