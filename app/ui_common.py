"""Shared helpers for the Streamlit pages."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from codeguard.reporting.export import to_html, to_json  # noqa: E402
from codeguard.schemas import SEVERITY_ORDER, ScanResult  # noqa: E402
from codeguard.storage.db import ScanStore  # noqa: E402

SEVERITY_ICON = {"Critical": "🟥", "High": "🔴", "Medium": "🟠", "Low": "🔵", "Informational": "⚪"}

LIMITATIONS = (
    "CodeGuard AI never runs your code; it reads it as text. Bandit only finds patterns it has rules "
    "for, and the ML score shows how much a function resembles vulnerable training examples — it is "
    "not the probability that the code can be exploited. A clean scan does not prove the code is secure."
)


def page_setup(title: str, icon: str = "🛡️") -> None:
    st.set_page_config(page_title=f"{title} · CodeGuard AI", page_icon=icon, layout="wide")
    st.markdown("<style>textarea { font-family: ui-monospace, Consolas, monospace !important; }</style>",
                unsafe_allow_html=True)


@st.cache_resource
def get_store() -> ScanStore:
    return ScanStore()


def severity_metrics(result: ScanResult) -> None:
    cols = st.columns(len(SEVERITY_ORDER) + 1)
    cols[0].metric("Total findings", result.summary.total)
    for col, sev in zip(cols[1:], SEVERITY_ORDER):
        col.metric(f"{SEVERITY_ICON[sev.value]} {sev.value}", result.summary.by_severity[sev.value])


def engine_status(result: ScanResult) -> None:
    labels = {"bandit": "Static analysis (Bandit)", "ml": "ML detector"}
    cols = st.columns(len(result.engines))
    for col, (name, status) in zip(cols, result.engines.items()):
        text = f"**{labels.get(name, name)}:** {status.status}"
        if status.detail:
            text += f" — {status.detail}"
        if status.status == "ok":
            col.success(text, icon="✅")
        elif status.status == "error":
            col.error(text, icon="⚠️")
        else:
            col.info(text, icon="ℹ️")


USER_INPUT_LABEL = {"direct": "yes — user input reaches this call", "parameter": "possibly — via a function parameter",
                    "none": "no — only constants or local values", None: "not analysed for this rule"}


def source_for(sources, finding) -> str | None:
    """`sources` is the scanned text (single file) or {relative path: text} (repository)."""
    if isinstance(sources, dict):
        return sources.get(finding.file)
    return sources


def findings_frame(result: ScanResult) -> pd.DataFrame:
    rows = []
    for f in result.findings:
        row = {"Severity": f"{SEVERITY_ICON[f.severity.value]} {f.severity.value}", "Rule": f.rule_id,
               "Category": f.category}
        if result.kind == "repository":
            row["File"] = f.file
        row.update({
            "Line": f.line,
            "Evidence": f.evidence,
            "Engine": f.source if f.confirmed else f"{f.source} (unconfirmed)",
            "User input": {"direct": "yes", "parameter": "param", "none": "no"}.get(f.user_input, ""),
            "ML score": f.ml_score,
            "CWE": f"CWE-{f.cwe}" if f.cwe else "",
        })
        rows.append(row)
    return pd.DataFrame(rows)


def finding_detail(result: ScanResult, index: int, sources=None, key: str = "current") -> None:
    f = result.findings[index]
    source = source_for(sources, f)
    st.subheader(f"{SEVERITY_ICON[f.severity.value]} {f.rule_id} · {f.category}")
    left, right = st.columns([3, 2])
    with left:
        st.markdown(f"**What was found:** {f.evidence}")
        st.markdown(f"**Where:** `{f.file}`, line {f.line}"
                    + (f"–{f.end_line}" if f.end_line and f.end_line != f.line else ""))
        if source:
            lines = source.splitlines()
            start = max(1, f.line - 3)
            end = min(len(lines), (f.end_line or f.line) + 3)
            snippet = "\n".join(f"{'➤' if f.line <= n <= (f.end_line or f.line) else ' '} {n:>4}  {lines[n - 1]}"
                                for n in range(start, end + 1))
            st.code(snippet, language="python")
        elif f.code_snippet:
            st.code(f.code_snippet, language="python")
        if f.recommendation:
            st.markdown(f"**Suggested action:** {f.recommendation}")
    with right:
        st.markdown(f"**Severity:** {f.severity.value}")
        st.caption(f.severity_reason)
        if f.source == "bandit":
            st.markdown(f"**Bandit rating:** severity {f.bandit_severity}, confidence {f.bandit_confidence}")
            st.markdown(f"**Does user input reach it?** {USER_INPUT_LABEL[f.user_input]}")
        if f.in_test_code:
            st.caption("This is test code, so the finding was lowered one level.")
        if f.ml_score is not None:
            st.markdown(f"**ML score:** {f.ml_score:.2f}")
            st.caption("Resemblance to vulnerable training examples — not a probability of exploitability.")
        if not f.confirmed:
            st.warning("Unconfirmed: only the ML model flagged this. No security rule matched.")
        links = []
        if f.cwe_link:
            links.append(f"[CWE-{f.cwe}]({f.cwe_link})")
        if f.more_info:
            links.append(f"[Bandit rule docs]({f.more_info})")
        if links:
            st.markdown("**References:** " + " · ".join(links))

    if f.source == "bandit":
        ai_panel(result, f, source, key)


def ai_panel(result: ScanResult, f, source: str | None, key: str) -> None:
    """Explain with AI (RAG + LLM) and Propose fix (rule template or LLM, then validation)."""
    from codeguard.llm.explainer import explain
    from codeguard.rag.retriever import KnowledgeBaseUnavailable
    from codeguard.remediation import fix_validator

    st.markdown("---")
    if not source:
        st.caption("AI explanation and fixes need the source code, which is not stored for this scan "
                   "(set CODEGUARD_STORE_SOURCE=true to keep it).")
        return
    state_key = f"ai_{result.scan_id}_{f.finding_id}"
    c1, c2, _ = st.columns([2, 2, 1])
    explain_clicked = c1.button("💡 Explain with AI", key=f"{key}_{state_key}_explain", use_container_width=True)
    fix_clicked = c2.button("🛠️ Propose fix", key=f"{key}_{state_key}_fix", use_container_width=True)
    tests = st.text_area("Optional: unit tests to run against the fix (unittest style; they run only inside "
                         "a Docker sandbox)", key=f"{key}_{state_key}_tests", height=80,
                         placeholder=f"import unittest\nfrom {Path(f.file).stem} import ...")

    needs_explanation = explain_clicked or (
        fix_clicked and f"{state_key}_expl" not in st.session_state
        and fix_validator.templates.TEMPLATES.get(f.rule_id) is None)
    if needs_explanation:
        try:
            with st.spinner("Retrieving security guidance and asking the local model (can take a minute)…"):
                st.session_state[f"{state_key}_expl"] = explain(f, source, cache=get_store())
        except KnowledgeBaseUnavailable as exc:
            st.error(str(exc))
            return
    if fix_clicked:
        with st.spinner("Building and validating a fix (re-running Bandit)…"):
            fix = fix_validator.propose_template_fix(source, f, Path(f.file).name, tests)
            expl = st.session_state.get(f"{state_key}_expl")
            if fix is None and expl is not None and expl.mode == "llm":
                fix = fix_validator.propose_llm_fix(source, f, expl, Path(f.file).name, tests)
            st.session_state[f"{state_key}_fix"] = fix
            if fix is not None:
                get_store().save_fix_attempt(result.scan_id, f.finding_id, fix.status, fix.model_dump_json())

    expl = st.session_state.get(f"{state_key}_expl")
    if expl is not None:
        render_explanation(expl)
    if fix_clicked or f"{state_key}_fix" in st.session_state:
        render_fix(st.session_state.get(f"{state_key}_fix"), f, key=f"{key}_{state_key}")


def render_explanation(res) -> None:
    e = res.explanation
    with st.container(border=True):
        if res.mode == "llm":
            st.markdown(f"##### 💡 AI explanation  \n:gray[{res.provider} · {res.model} · {res.seconds:.0f} s"
                        f"{' · cached' if res.cached else ''} — AI-generated, review before relying on it]")
        else:
            st.markdown("##### 📚 Security guidance (no language model)")
            st.caption(res.note or "")
        if e.insufficient_evidence:
            st.info("The model judged the evidence insufficient to confirm this is exploitable.")
        st.markdown(f"**What is wrong:** {e.summary}")
        if e.why_dangerous:
            st.markdown(f"**Why it is dangerous:** {e.why_dangerous}")
        if e.exploit_conditions:
            st.markdown(f"**When it is exploitable:** {e.exploit_conditions}")
        if e.fix_explanation:
            st.markdown(f"**How to fix it:** {e.fix_explanation}")
        if e.caveats:
            st.caption(f"Caveats: {e.caveats}")
        cited = set(e.citations)
        st.markdown("**Sources**")
        for s in res.sources:
            mark = "✅ cited" if s.id in cited else "retrieved"
            section = f" — {s.section}" if s.section else ""
            st.markdown(f"- **{s.id}** [{s.title}{section}]({s.url}) · {s.publisher} · :gray[{mark}]")
        if res.invalid_citations:
            st.caption("Ignored citations to sources that were not provided: " + ", ".join(res.invalid_citations))


FIX_STATUS = {"passed_configured_checks": ("✅ Passed configured checks", "success"),
              "requires_review": ("⚠️ Requires review", "warning"),
              "candidate": ("📝 Candidate (not validated)", "info")}
CHECK_MARK = {True: "✅ pass", False: "❌ fail", None: "— not run"}


def render_fix(fix, f, key: str) -> None:
    with st.container(border=True):
        if fix is None:
            st.info(f"No automatic fix is available for {f.rule_id}. Use the explanation's guidance.")
            return
        label, kind = FIX_STATUS[fix.status]
        origin = "rule-based template" if fix.origin == "rule_template" else "AI-generated"
        st.markdown(f"##### 🛠️ Proposed fix · {origin}")
        getattr(st, kind)(label + " — this is not a guarantee that the code is secure.")
        if fix.description:
            st.markdown(fix.description)
        if fix.caveat:
            st.caption(f"Caveat: {fix.caveat}")
        st.dataframe(pd.DataFrame([{"Check": c.name, "Result": CHECK_MARK[c.passed], "Detail": c.detail}
                                   for c in fix.checks]), hide_index=True, use_container_width=True)
        if fix.ml_score_before is not None and fix.ml_score_after is not None:
            st.caption(f"ML score of the function: {fix.ml_score_before:.2f} → {fix.ml_score_after:.2f} "
                       "(information only)")
        if fix.diff:
            st.code(fix.diff, language="diff")
            st.download_button("Download patched file", fix.patched_source, file_name=Path(f.file).name,
                               mime="text/x-python", key=f"{key}_dl")
        if fix.tests_output:
            with st.expander("Test output"):
                st.code(fix.tests_output)


def render_result(result: ScanResult, sources=None, key: str = "current") -> None:
    """Summary cards, engine status, filterable findings table, detail panel and export."""
    st.markdown(f"#### Results for `{result.filename}`")
    extra = f" · {len(result.files)} Python files" if result.kind == "repository" else ""
    st.caption(f"Scan {result.scan_id} · {result.created_at:%Y-%m-%d %H:%M} UTC · "
               f"{result.lines_of_code} lines{extra} · {result.duration_ms} ms")
    severity_metrics(result)
    engine_status(result)

    if not result.findings:
        st.success("No findings. Remember: a clean scan does not prove the code is secure.")
    else:
        frame = findings_frame(result)
        c1, c2, c3 = st.columns([2, 2, 3])
        severities = c1.multiselect("Severity", [s.value for s in SEVERITY_ORDER], key=f"{key}_sev",
                                    placeholder="All severities")
        engines = c2.multiselect("Engine", sorted({f.source for f in result.findings}), key=f"{key}_eng",
                                 placeholder="All engines")
        query = c3.text_input("Search", key=f"{key}_q", placeholder="rule, category, file or evidence")
        mask = pd.Series(True, index=frame.index)
        if severities:
            mask &= frame["Severity"].str.split(" ", n=1).str[1].isin(severities)
        if engines:
            mask &= pd.Series([f.source in engines for f in result.findings], index=frame.index)
        if query:
            q = query.lower()
            cols = [c for c in ["Rule", "Category", "Evidence", "CWE", "File"] if c in frame]
            mask &= frame[cols].apply(lambda r: q in " ".join(map(str, r)).lower(), axis=1)
        shown = frame[mask]

        st.caption("Select a row to see its details, an AI explanation and a proposed fix.")
        event = st.dataframe(
            shown, hide_index=True, use_container_width=True, on_select="rerun",
            selection_mode="single-row", key=f"{key}_table",
            column_config={"ML score": st.column_config.NumberColumn(format="%.2f"),
                           "Evidence": st.column_config.TextColumn(width="large")},
        )
        rows = event.selection.rows if event and event.selection else []
        chosen = shown.index[rows[0]] if rows else (shown.index[0] if len(shown) else None)
        if chosen is not None:
            with st.container(border=True):
                finding_detail(result, int(chosen), sources, key)

    e1, e2, _ = st.columns([2, 3, 3])
    e1.download_button("⬇️ JSON", to_json(result), file_name=f"codeguard_{result.scan_id}.json",
                       mime="application/json", key=f"{key}_json", use_container_width=True)
    e2.download_button("⬇️ HTML report", to_html(result), file_name=f"codeguard_{result.scan_id}.html",
                       mime="text/html", key=f"{key}_html", use_container_width=True)
