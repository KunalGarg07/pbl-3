"""Runs Bandit on source text and returns its JSON results.

Safety rules:
- The submitted code is written to a temporary file with a fixed name; the user's filename never
  chooses a path.
- Bandit is started with an argument list (no shell) and a timeout.
- Bandit only parses the code. Nothing is executed.
"""
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from codeguard.config import settings

TEMP_FILENAME = "submitted_code.py"


class AnalyzerError(RuntimeError):
    """Bandit could not produce a usable result (timeout, missing, bad output)."""


@dataclass
class BanditReport:
    issues: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    version: str = ""


def bandit_version() -> str:
    try:
        from bandit import __version__
        return __version__
    except Exception:  # pragma: no cover - only when Bandit is missing
        return "unknown"


def run_bandit(source: str, timeout_s: int | None = None) -> BanditReport:
    timeout_s = timeout_s or settings.bandit_timeout_s
    with tempfile.TemporaryDirectory(prefix="codeguard_") as tmp:
        path = Path(tmp) / TEMP_FILENAME
        # newline="" writes the text unchanged; text mode on Windows would turn "\r\n" into "\r\r\n"
        # and shift every line number Bandit reports.
        path.write_text(source, encoding="utf-8", newline="")
        return _execute([sys.executable, "-m", "bandit", "-f", "json", "-q", str(path)], timeout_s)


def run_bandit_dir(directory: Path, timeout_s: int = 300) -> BanditReport:
    """Scan every .py file under a directory in one Bandit run. File paths in the report are absolute."""
    return _execute([sys.executable, "-m", "bandit", "-r", "-f", "json", "-q", str(directory)], timeout_s)


def _execute(command: list[str], timeout_s: int) -> BanditReport:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout_s, shell=False)
    except subprocess.TimeoutExpired as exc:
        raise AnalyzerError(f"Bandit timed out after {timeout_s} s") from exc
    except OSError as exc:
        raise AnalyzerError(f"Could not start Bandit: {exc}") from exc

    # Exit code 0 = no issues, 1 = issues found. Anything else is a failure.
    if completed.returncode not in (0, 1):
        message = (completed.stderr or "").strip().splitlines()[-1:] or ["no output"]
        raise AnalyzerError(f"Bandit failed (exit code {completed.returncode}): {message[0]}")
    try:
        data = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AnalyzerError("Bandit returned output that is not valid JSON") from exc

    return BanditReport(
        issues=data.get("results", []),
        errors=data.get("errors", []),
        version=bandit_version(),
    )
