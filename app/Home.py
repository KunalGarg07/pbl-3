"""CodeGuard AI · Streamlit entry point.  Run:  streamlit run app/Home.py"""
import ui_common
import streamlit as st

from codeguard import __version__
from codeguard.llm.client import LLMUnavailable, get_client
from codeguard.rag import retriever
from codeguard.remediation.sandbox import docker_available
from codeguard.scanner import ml_detector
from codeguard.scanner.static_analyzer import bandit_version

ui_common.page_setup("Home")

st.title("🛡️ CodeGuard AI")
st.markdown("**Find security bugs in Python code, understand why they matter, and get a checked fix.**")

st.markdown("""
| Step | What happens |
|---|---|
| 1. **Submit** | Paste Python code, upload a `.py` file, or upload a zipped project. It is read as text and **never executed**. |
| 2. **Static analysis** | [Bandit](https://bandit.readthedocs.io/) checks the code against known unsafe patterns and reports the exact line. |
| 3. **ML detector** | A model trained on real Python CVE fixes scores each function. Its predictions are shown separately and marked *unconfirmed*. |
| 4. **Risk assessment** | Findings are merged and rated with a written policy. A context check asks whether user input reaches the risky call (→ Critical) or whether it is test code (→ lower). |
| 5. **Explain** | Retrieval finds matching MITRE CWE, OWASP and Bandit guidance; a local language model explains the finding and must cite those sources. |
| 6. **Fix and verify** | A rule-based or AI-proposed fix is re-scanned, checked for new issues and (optionally) tested in a Docker sandbox. It is never called "secure". |
""")

c1, c2 = st.columns(2)
c1.page_link("pages/1_Scan.py", label="Scan a file", icon="🔍")
c2.page_link("pages/2_Repository_Scan.py", label="Scan a project (.zip)", icon="📦")

st.subheader("System status")
card = ml_detector.model_card()
try:
    kb = retriever.load_store()
    kb_status = f"{len(kb):,} passages"
except retriever.KnowledgeBaseUnavailable:
    kb_status = "not built"
try:
    llm = get_client()
    llm_status = f"{llm.model} ({llm.provider})"
except LLMUnavailable:
    llm_status = "none (guidance only)"
version = card.get("model_version", "") if card else ""
cols = st.columns(5)
cols[0].metric("Bandit", bandit_version())
cols[1].metric("ML model", ("v2" if "-v2-" in version else "v1") if card else "—")
cols[2].metric("Knowledge passages", kb_status.split()[0] if kb_status != "not built" else "—")
cols[3].metric("Language model", llm_status.split()[0])
cols[4].metric("Docker sandbox", "ready" if docker_available() else "off")
st.caption(f"CodeGuard AI {__version__} · ML model {version or 'not trained'} · knowledge base {kb_status} · "
           f"language model {llm_status}")
if kb_status == "not built":
    st.info("Build the knowledge base with `python scripts/ingest_kb.py` to enable explanations.", icon="ℹ️")

st.subheader("Supported input")
st.markdown("- **Python** only: `.py` files up to 200 KB, or a `.zip` project up to 10 MB / 500 Python files.\n"
            "- Explanations run on a local model through Ollama by default, so your code stays on this machine.")

st.caption(ui_common.LIMITATIONS)
