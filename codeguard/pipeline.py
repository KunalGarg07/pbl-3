"""Runs one complete scan: validate -> Bandit -> ML -> normalize -> assess -> (save).

Submitted code is treated as text the whole way through. It is never imported or executed.
"""
import ast
import hashlib
import time
import unicodedata
import uuid
from pathlib import PurePath

from codeguard.config import settings
from codeguard.scanner import finding_normalizer as normalizer
from codeguard.scanner import context, ml_detector, risk_assessor
from codeguard.scanner.static_analyzer import AnalyzerError, run_bandit
from codeguard.schemas import EngineStatus, ScanResult


class InputError(ValueError):
    """The submitted input cannot be scanned. The message is safe to show to the user."""


def safe_display_name(filename: str | None) -> str:
    """Keep only a short, printable base name. It is used for display, never as a path."""
    name = PurePath((filename or "pasted_code.py").replace("\\", "/")).name
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C").strip()
    return (name or "pasted_code.py")[:100]


def validate(source: str | bytes, filename: str | None) -> tuple[str, str]:
    name = safe_display_name(filename)
    if not name.lower().endswith(settings.allowed_extensions):
        raise InputError(f"Unsupported file type '{PurePath(name).suffix or name}'. "
                         "CodeGuard AI currently scans Python (.py) files only.")

    raw = source.encode("utf-8") if isinstance(source, str) else source
    if len(raw) > settings.max_bytes:
        raise InputError(f"File is too large ({len(raw):,} bytes). The limit is {settings.max_bytes:,} bytes.")
    if b"\x00" in raw:
        raise InputError("The file looks binary (it contains null bytes). Please submit Python source text.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError("The file is not valid UTF-8 text.") from exc
    if not text.strip():
        raise InputError("The code is empty.")
    # Windows editors save "\r\n". Normalise once so Bandit, the AST checks and the UI count lines the same way.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    try:
        ast.parse(text)
    except SyntaxError as exc:
        raise InputError(f"This is not valid Python (syntax error on line {exc.lineno}: {exc.msg}). "
                         "Bandit and the ML model need code that parses.") from exc
    return text, name


def bandit_to_findings(issues: list[dict], text: str, path: str, start: int = 1) -> list:
    """Normalize Bandit issues for one file, add context, and apply the risk policy."""
    findings = [normalizer.from_bandit(issue, path, i) for i, issue in enumerate(issues, start=start)]
    findings = [risk_assessor.assess_bandit(f) for f in findings]
    context.annotate(text, findings, path)
    return [risk_assessor.apply_context(f) for f in findings]


def ml_to_findings(text: str, path: str, bandit_findings: list, start: int = 1) -> tuple[list, int]:
    """Score one file with the ML model; attach scores to Bandit findings; return ML-only findings."""
    unit_scores = ml_detector.score_units(ml_detector.extract_units(text))
    remaining = risk_assessor.merge(bandit_findings, unit_scores)
    findings = [risk_assessor.assess_ml(normalizer.from_ml(us, path, i)) for i, us in enumerate(remaining, start=start)]
    context.annotate(text, findings, path)
    return findings, len(unit_scores)


def scan(source: str | bytes, filename: str | None = None, *, use_ml: bool = True,
         store=None) -> ScanResult:
    """Scan one Python file. Pass a `ScanStore` as `store` to save the result in history."""
    started = time.perf_counter()
    text, name = validate(source, filename)
    engines: dict[str, EngineStatus] = {}

    # 1. Static analysis
    bandit_findings = []
    try:
        report = run_bandit(text)
        bandit_findings = bandit_to_findings(report.issues, text, name)
        detail = f"Bandit {report.version}"
        if report.errors:
            detail += f"; {len(report.errors)} warning(s) while parsing"
        engines["bandit"] = EngineStatus(status="ok", detail=detail)
    except AnalyzerError as exc:
        engines["bandit"] = EngineStatus(status="error", detail=str(exc))

    # 2. ML detector
    ml_findings, model_version = [], None
    if not use_ml:
        engines["ml"] = EngineStatus(status="unavailable", detail="Disabled for this scan")
    else:
        try:
            _, card = ml_detector.load_model()
            model_version = card.get("model_version")
            ml_findings, units = ml_to_findings(text, name, bandit_findings)
            engines["ml"] = EngineStatus(status="ok", detail=f"{units} code unit(s) scored")
        except ml_detector.ModelUnavailable as exc:
            engines["ml"] = EngineStatus(status="unavailable", detail=str(exc))
        except Exception as exc:  # a model problem must not break the whole scan
            engines["ml"] = EngineStatus(status="error", detail=f"ML detector failed: {exc}")

    findings = risk_assessor.sort_findings(bandit_findings + ml_findings)
    result = ScanResult(
        scan_id=uuid.uuid4().hex[:12],
        filename=name,
        source_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        lines_of_code=len(text.splitlines()),
        duration_ms=int((time.perf_counter() - started) * 1000),
        engines=engines,
        findings=findings,
        summary=risk_assessor.summarize(findings),
        model_version=model_version,
    )
    if store is not None:
        store.save(result, source=text if settings.store_source else None)
    return result
