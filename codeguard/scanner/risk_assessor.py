"""Documented severity policy (version 2). See Documents/Limitations.docx.

1. Bandit findings take their severity from Bandit: HIGH -> High, MEDIUM -> Medium, LOW -> Low.
2. Rules that allow direct code or command execution (rules.ESCALATE_TO_HIGH) are raised from
   Medium to High when Bandit's confidence is HIGH.
3. ML-only findings are always Informational and unconfirmed. An ML score never sets severity.
4. A Bandit finding inside a function the ML model scored gets that score attached (`ml_score`);
   no separate ML finding is created for that function, so the issue is not reported twice.
5. Context (version 2): a High finding becomes Critical only when the context check shows user input
   (input(), sys.argv, os.environ, a web request) flowing directly into the flagged statement, and
   the code is not test code. Agreement between the two engines never raises severity.
6. Findings in test code (test files, tests/ folders, test_* functions) are lowered one level
   (not below Low), because test code is not normally deployed.
"""
from codeguard.scanner.rules import ESCALATE_TO_HIGH
from codeguard.schemas import SEVERITY_ORDER, Finding, ScanSummary, Severity
from codeguard.scanner.ml_detector import UnitScore

BANDIT_TO_SEVERITY = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


def assess_bandit(finding: Finding) -> Finding:
    base = BANDIT_TO_SEVERITY.get((finding.bandit_severity or "").upper(), Severity.LOW)
    reason = f"Bandit severity {finding.bandit_severity}, confidence {finding.bandit_confidence}."
    if (base == Severity.MEDIUM and finding.rule_id in ESCALATE_TO_HIGH
            and (finding.bandit_confidence or "").upper() == "HIGH"):
        base = Severity.HIGH
        reason += " Raised to High: this call can execute code or commands if input is untrusted."
    finding.severity = base
    finding.severity_reason = reason
    return finding


LOWER = {Severity.CRITICAL: Severity.HIGH, Severity.HIGH: Severity.MEDIUM, Severity.MEDIUM: Severity.LOW}


def apply_context(finding: Finding) -> Finding:
    """Rules 5 and 6. Call after `context.annotate`."""
    if finding.source != "bandit":
        return finding
    if finding.in_test_code:
        if finding.severity in LOWER:
            finding.severity = LOWER[finding.severity]
            finding.severity_reason += " Lowered one level: the code is test code."
    elif finding.severity == Severity.HIGH and finding.user_input == "direct":
        finding.severity = Severity.CRITICAL
        finding.severity_reason += " Raised to Critical: user input flows directly into this call."
    return finding


def assess_ml(finding: Finding) -> Finding:
    finding.severity = Severity.INFO
    finding.severity_reason = "Model-only prediction; not confirmed by a security rule."
    return finding


def merge(bandit_findings: list[Finding], unit_scores: list[UnitScore]) -> list[UnitScore]:
    """Attach ML scores to Bandit findings. Return flagged units that still need their own finding."""
    remaining = []
    for us in unit_scores:
        inside = [f for f in bandit_findings if us.unit.contains(f.line)]
        for f in inside:
            f.ml_score = us.score
        if us.flagged and not inside:
            remaining.append(us)
    return remaining


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.severity.rank, f.line, f.rule_id))


def summarize(findings: list[Finding]) -> ScanSummary:
    summary = ScanSummary(total=len(findings))
    for f in findings:
        summary.by_severity[f.severity.value] += 1
        summary.by_source[f.source] += 1
    # Keep a stable key order for display.
    summary.by_severity = {s.value: summary.by_severity[s.value] for s in SEVERITY_ORDER}
    return summary
