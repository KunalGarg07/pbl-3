"""Run a user's own unit tests against patched code inside an isolated Docker container.

This is the only place CodeGuard AI executes code. The container has no network, a read-only file
system (except /tmp), CPU/memory/process limits, runs as an unprivileged user and is removed afterwards.
If Docker is not running, tests are skipped and the fix cannot reach "passed_configured_checks" with tests.
"""
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

IMAGE = "python:3.13-slim"
TIMEOUT_S = 120


@dataclass
class SandboxResult:
    status: str          # "passed" | "failed" | "error" | "unavailable"
    detail: str
    output: str = ""


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True,
                              text=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_tests(module_name: str, patched_source: str, test_source: str) -> SandboxResult:
    if not docker_available():
        return SandboxResult("unavailable", "Docker is not running, so tests were not executed.")
    with tempfile.TemporaryDirectory(prefix="codeguard_sandbox_") as tmp:
        work = Path(tmp)
        (work / f"{module_name}.py").write_text(patched_source, encoding="utf-8")
        (work / "test_submitted.py").write_text(test_source, encoding="utf-8")
        command = [
            "docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp",
            "--memory", "512m", "--cpus", "1", "--pids-limit", "128", "--user", "65534:65534",
            "--security-opt", "no-new-privileges", "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-v", f"{work}:/work:ro", "-w", "/work", IMAGE,
            "python", "-m", "unittest", "discover", "-s", "/work", "-p", "test_*.py", "-v",
        ]
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=TIMEOUT_S, shell=False)
        except subprocess.TimeoutExpired:
            return SandboxResult("error", f"Tests timed out after {TIMEOUT_S} s")
        output = (done.stdout + done.stderr)[-4000:]
        if done.returncode == 0:
            return SandboxResult("passed", "All tests passed in the sandbox.", output)
        return SandboxResult("failed", f"Tests failed (exit code {done.returncode}).", output)
