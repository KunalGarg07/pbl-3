"""Converts Bandit results and ML scores into the shared `Finding` schema."""
from codeguard.scanner.ml_detector import UnitScore
from codeguard.scanner.rules import CWE_OVERRIDES, category_for, recommendation_for
from codeguard.schemas import Finding, Severity

ML_RULE_ID = "ML-VULN-PRED"


def _clean_snippet(code: str | None) -> str | None:
    """Bandit prefixes each snippet line with its line number; keep that, drop the trailing newline."""
    return code.rstrip("\n") if code else None


def from_bandit(issue: dict, filename: str, index: int) -> Finding:
    rule_id = issue.get("test_id", "B000")
    category = category_for(rule_id)
    cwe_info = issue.get("issue_cwe") or {}
    cwe = CWE_OVERRIDES.get(rule_id, cwe_info.get("id"))
    cwe_link = (f"https://cwe.mitre.org/data/definitions/{cwe}.html" if cwe else None)
    line_range = issue.get("line_range") or [issue.get("line_number", 1)]
    return Finding(
        finding_id=f"B{index:03d}",
        source="bandit",
        rule_id=rule_id,
        rule_name=issue.get("test_name", ""),
        category=category,
        cwe=cwe,
        cwe_link=cwe_link,
        file=filename,
        line=int(issue.get("line_number", 1)),
        end_line=int(max(line_range)),
        col=issue.get("col_offset"),
        # Placeholder: the risk assessor sets the final severity.
        severity=Severity.INFO,
        severity_reason="",
        bandit_severity=issue.get("issue_severity"),
        bandit_confidence=issue.get("issue_confidence"),
        evidence=issue.get("issue_text", ""),
        code_snippet=_clean_snippet(issue.get("code")),
        more_info=issue.get("more_info"),
        recommendation=recommendation_for(category),
        confirmed=True,
    )


def from_ml(unit_score: UnitScore, filename: str, index: int) -> Finding:
    unit = unit_score.unit
    numbered = "\n".join(f"{unit.start_line + i} {text}"
                         for i, text in enumerate(unit.source.splitlines()[:12]))
    return Finding(
        finding_id=f"M{index:03d}",
        source="ml",
        rule_id=ML_RULE_ID,
        rule_name="ml_vulnerability_prediction",
        category="Model prediction",
        file=filename,
        line=unit.start_line,
        end_line=unit.end_line,
        severity=Severity.INFO,
        severity_reason="",
        ml_score=unit_score.score,
        evidence=(f"The ML model scored `{unit.name}` at {unit_score.score:.2f}: it resembles vulnerable "
                  "functions in its training data. No security rule matched, so this is unconfirmed."),
        code_snippet=numbered if unit.source else None,
        recommendation="Review this code manually; the model cannot point to the exact unsafe line.",
        confirmed=False,
    )
