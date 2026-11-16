"""Validate a proposed fix (week 9).

A fix is never labelled "secure". The validator re-checks the patched code and reports one of:
- passed_configured_checks: parses, the original rule no longer fires at that place, no new Medium-or-higher
  Bandit findings, and (if tests were supplied and Docker is running) the tests pass;
- requires_review: at least one check failed or could not run;
- candidate: proposed but not validated.
"""
import ast
from collections import Counter
from typing import Literal, Optional

from pydantic import BaseModel, Field

from codeguard.remediation import patcher, sandbox, templates
from codeguard.scanner import ml_detector
from codeguard.scanner.static_analyzer import AnalyzerError, run_bandit
from codeguard.schemas import Finding

SERIOUS = {"MEDIUM", "HIGH"}


class Check(BaseModel):
    name: str
    passed: Optional[bool]          # None = could not run
    detail: str


class FixResult(BaseModel):
    origin: Literal["rule_template", "llm"]
    status: Literal["candidate", "passed_configured_checks", "requires_review"]
    description: str = ""
    caveat: str = ""
    patched_source: str = ""
    diff: str = ""
    checks: list[Check] = Field(default_factory=list)
    ml_score_before: Optional[float] = None
    ml_score_after: Optional[float] = None
    tests_output: str = ""


def _bandit(source: str) -> list[dict]:
    return run_bandit(source).issues


def _function_score(source: str, line: int) -> Optional[float]:
    try:
        model, card = ml_detector.load_model()
    except ml_detector.ModelUnavailable:
        return None
    try:
        units = [u for u in ml_detector.extract_units(source, min_lines=1) if u.start_line <= line <= u.end_line]
    except SyntaxError:
        return None
    if not units:
        return None
    return ml_detector.score_units(units[:1], model=model, threshold=card.get("threshold"))[0].score


def validate(original: str, patched: str, finding: Finding, *, origin: str, filename: str,
             description: str = "", caveat: str = "", test_source: str | None = None) -> FixResult:
    result = FixResult(origin=origin, status="candidate", description=description, caveat=caveat,
                       patched_source=patched, diff=patcher.unified_diff(original, patched, filename))
    checks = result.checks

    # 1. The patched file must be valid Python.
    try:
        ast.parse(patched)
        checks.append(Check(name="Parses as Python", passed=True, detail="The patched file is valid Python."))
    except SyntaxError as exc:
        checks.append(Check(name="Parses as Python", passed=False, detail=f"Syntax error on line {exc.lineno}: {exc.msg}"))
        result.status = "requires_review"
        return result

    # 2 + 3. Re-run Bandit: original rule gone near the fix, nothing new and serious introduced.
    try:
        before, after = _bandit(original), _bandit(patched)
        shift = len(patched.splitlines()) - len(original.splitlines())
        window = range(finding.line - 1, (finding.end_line or finding.line) + max(shift, 0) + 2)
        still_there = [i for i in after if i["test_id"] == finding.rule_id and i["line_number"] in window]
        checks.append(Check(
            name=f"{finding.rule_id} no longer reported", passed=not still_there,
            detail="Bandit no longer reports this rule at the fixed location." if not still_there
            else f"Bandit still reports {finding.rule_id} on line {still_there[0]['line_number']}."))
        count_before = Counter(i["test_id"] for i in before if i["issue_severity"] in SERIOUS)
        count_after = Counter(i["test_id"] for i in after if i["issue_severity"] in SERIOUS)
        introduced = sorted((count_after - count_before).elements())
        checks.append(Check(
            name="No new Medium/High findings", passed=not introduced,
            detail="No new Medium or High Bandit findings." if not introduced
            else "New findings introduced: " + ", ".join(introduced)))
    except AnalyzerError as exc:
        checks.append(Check(name="Bandit re-scan", passed=None, detail=str(exc)))

    # 4. ML re-score (information only; never decides the status).
    result.ml_score_before = _function_score(original, finding.line)
    result.ml_score_after = _function_score(patched, finding.line)

    # 5. The user's tests, in the Docker sandbox.
    if test_source and test_source.strip():
        module = filename[:-3] if filename.endswith(".py") else filename
        run = sandbox.run_tests(module, patched, test_source)
        result.tests_output = run.output
        checks.append(Check(name="Your tests (sandbox)", passed={"passed": True, "failed": False}.get(run.status),
                            detail=run.detail))

    result.status = "passed_configured_checks" if all(c.passed for c in checks) else "requires_review"
    return result


def propose_template_fix(source: str, finding: Finding, filename: str, test_source: str | None = None) -> FixResult | None:
    applied = templates.apply_template(source, finding.rule_id, finding.line, finding.end_line)
    if applied is None:
        return None
    patched, template = applied
    return validate(source, patched, finding, origin="rule_template", filename=filename,
                    description=template.description, caveat=template.caveat, test_source=test_source)


def propose_llm_fix(source: str, finding: Finding, explanation_result, filename: str,
                    test_source: str | None = None) -> FixResult:
    expl = explanation_result.explanation
    try:
        patched = patcher.apply_llm_fix(source, expl.fix_code, explanation_result.region_start,
                                        explanation_result.region_end, finding.line)
    except (patcher.PatchError, SyntaxError) as exc:
        return FixResult(origin="llm", status="requires_review", description=expl.fix_explanation,
                         caveat="AI-generated code.",
                         checks=[Check(name="Fix can be applied", passed=False, detail=str(exc))])
    return validate(source, patched, finding, origin="llm", filename=filename,
                    description=expl.fix_explanation, caveat="AI-generated code — review before use.",
                    test_source=test_source)
