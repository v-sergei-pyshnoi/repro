#!/usr/bin/env python3
"""Reproduce actions/runner-images#15003 without kernel changes or workarounds."""

import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


COMM = "bpf15003"
ITERATIONS = 20
PROGRAM = r"""
tracepoint:syscalls:sys_enter_openat /comm == "bpf15003"/ {
  @openat[cpu] = count();
}
tracepoint:raw_syscalls:sys_enter /comm == "bpf15003"/ {
  @control[cpu] = count();
}
interval:s:1 {
  printf("READY\n");
}
"""


def parse_counts(output):
    counts = {"openat": {}, "control": {}}
    for probe, cpu, count in re.findall(
        r"^@(openat|control)\[(\d+)\]:\s*(\d+)\s*$", output, re.MULTILINE
    ):
        cpu = int(cpu)
        if cpu in counts[probe]:
            raise ValueError(f"Duplicate {probe} count for CPU {cpu}")
        counts[probe][cpu] = int(count)
    return counts


def evaluate(cpus, counts, iterations):
    expected_cpus = set(cpus)
    if len(expected_cpus) < 2:
        return "INCONCLUSIVE", "At least two allowed CPUs are needed."
    for probe, values in counts.items():
        if set(values) - expected_cpus:
            return "INCONCLUSIVE", f"Unexpected CPU in {probe} output."
    if any(counts["control"].get(cpu, 0) < 2 * iterations for cpu in cpus):
        return "INCONCLUSIVE", "Raw syscall control did not observe every CPU's workload."
    observed = [counts["openat"].get(cpu, 0) for cpu in cpus]
    if any(count > iterations for count in observed):
        return "INCONCLUSIVE", "More openat events than generated; evidence is contaminated."
    if not any(observed):
        return "INCONCLUSIVE", "No openat events at all; cannot establish the reported CPU-specific loss."
    if any(count < iterations for count in observed):
        return "REPRODUCED", "openat events are missing despite a successful raw syscall control."
    return "NOT_REPRODUCED", "Every CPU delivered all generated openat events on this runner."


def workload(cpu):
    os.sched_setaffinity(0, {cpu})
    libc = ctypes.CDLL(None, use_errno=True)
    # Set comm only after Python startup so its own file opens cannot pollute counts.
    if libc.prctl(15, COMM.encode(), 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    for _ in range(ITERATIONS):
        fd = os.open("/etc/hostname", os.O_RDONLY)
        os.close(fd)


def wait_ready(process, log_path, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"bpftrace exited before readiness: {process.returncode}")
        # An interval probe, unlike BEGIN, fires after tracepoint attachment.
        if "READY\n" in log_path.read_text():
            return
        time.sleep(0.1)
    raise TimeoutError("bpftrace did not report readiness within 45 seconds")


def stop_tracer(process):
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise TimeoutError("bpftrace did not stop and flush maps after SIGINT") from None


def trace(output, cpus):
    source = output / "trace.bt"
    source.write_text(PROGRAM)
    stdout_path = output / "bpftrace.stdout.log"
    with stdout_path.open("w") as stdout, (output / "bpftrace.stderr.log").open("w") as stderr:
        process = subprocess.Popen(
            ["bpftrace", "-q", "-B", "line", str(source)],
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
        )
        try:
            wait_ready(process, stdout_path)
            with (output / "workload.log").open("w") as log:
                for cpu in cpus:
                    subprocess.run(
                        [sys.executable, str(Path(__file__).resolve()), "--workload", str(cpu)],
                        check=True,
                        timeout=15,
                        stdout=log,
                        stderr=log,
                    )
                    log.write(f"CPU {cpu}: generated {ITERATIONS} openat + close pairs\n")
                    log.flush()
            if process.poll() is not None:
                raise RuntimeError(f"bpftrace exited during the workload: {process.returncode}")
        finally:
            stop_tracer(process)
        if process.returncode not in (0, 130, -signal.SIGINT):
            raise RuntimeError(f"bpftrace failed: {process.returncode}; see stderr log")
    return parse_counts(stdout_path.read_text())


def write_result(output, summary_path, result):
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    lines = [
        f"## BPF 15003: {result['status']}",
        "",
        f"- Runner: `{result['runner_label']}`",
        f"- ImageVersion: `{result['image_version']}`",
        f"- Kernel: `{result['kernel']}`",
        f"- Architecture: `{result['architecture']}`",
        f"- {result['reason']}",
        "",
        f"Expected: {ITERATIONS} openat events per CPU; raw syscall control >= {2 * ITERATIONS}.",
        "",
        "| CPU | openat observed | raw syscall control |",
        "| --- | ---: | ---: |",
    ]
    for cpu in result["allowed_cpus"]:
        lines.append(
            f"| {cpu} | {result['counts']['openat'].get(cpu, 0)} "
            f"| {result['counts']['control'].get(cpu, 0)} |"
        )
    lines.extend([
        "",
        "NOT_REPRODUCED applies only to this VM, not to the entire image rollout.",
        "INCONCLUSIVE indicates a diagnostic/setup failure, not a healthy kernel.",
        "",
    ])
    summary = "\n".join(lines)
    (output / "summary.md").write_text(summary)
    if summary_path:
        with Path(summary_path).open("a") as stream:
            stream.write(summary)
    print(summary, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workload", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary")
    parser.add_argument("--runner-label", default="local")
    parser.add_argument("--image-version", default="unknown")
    args = parser.parse_args()
    if args.workload is not None:
        workload(args.workload)
        return 0
    if args.output is None:
        parser.error("--output is required")
    args.output.mkdir(parents=True, exist_ok=True)
    result = {
        "status": "INCONCLUSIVE",
        "reason": "Diagnostic did not complete.",
        "runner_label": args.runner_label,
        "image_version": args.image_version,
        "kernel": os.uname().release,
        "architecture": os.uname().machine,
        "allowed_cpus": [],
        "iterations_per_cpu": ITERATIONS,
        "counts": {"openat": {}, "control": {}},
    }
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("Run on Linux as root (sudo python3).")
        cpus = sorted(os.sched_getaffinity(0))
        result["allowed_cpus"] = cpus
        if len(cpus) < 2:
            raise RuntimeError("At least two allowed CPUs are needed.")
        result["counts"] = trace(args.output, cpus)
        result["status"], result["reason"] = evaluate(cpus, result["counts"], ITERATIONS)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        result["reason"] = f"{type(error).__name__}: {error}"
        print(result["reason"], file=sys.stderr, flush=True)
    write_result(args.output, args.summary, result)
    return {"NOT_REPRODUCED": 0, "REPRODUCED": 1, "INCONCLUSIVE": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
