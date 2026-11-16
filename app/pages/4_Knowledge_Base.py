"""Knowledge base: what the AI explanations are grounded in, plus a search box."""
import ui_common
import pandas as pd
import streamlit as st

from codeguard.llm.client import LLMUnavailable, get_client
from codeguard.rag import retriever

ui_common.page_setup("Knowledge base", "📚")
st.title("📚 Security knowledge base")
st.markdown("AI explanations are **grounded** in these documents: the system retrieves the most relevant "
            "passages for a finding and the language model must cite them. The model never decides on its "
            "own that a vulnerability exists.")

try:
    store = retriever.load_store()
except retriever.KnowledgeBaseUnavailable as exc:
    st.warning(f"{exc}", icon="⚠️")
    st.stop()

info = store.info
c1, c2, c3 = st.columns(3)
c1.metric("Documents", sum(info.get("documents", {}).values()))
c2.metric("Chunks", len(store))
c3.metric("Built", info.get("built", "—"))
st.dataframe(pd.DataFrame([
    {"Source": "MITRE CWE", "Documents": info["documents"].get("cwe", 0), "Chunks": info["chunks"].get("cwe", 0),
     "Detail": info["sources"]["cwe"]},
    {"Source": "OWASP Cheat Sheets", "Documents": info["documents"].get("owasp", 0),
     "Chunks": info["chunks"].get("owasp", 0), "Detail": info["sources"]["owasp"]},
    {"Source": "Bandit docs", "Documents": info["documents"].get("bandit", 0),
     "Chunks": info["chunks"].get("bandit", 0), "Detail": info["sources"]["bandit"]},
]), hide_index=True, use_container_width=True)
st.caption(f"Embeddings: {info.get('embedding_model')}; exact cosine search with a boost for passages tagged "
           "with the finding's CWE or Bandit rule.")

try:
    client = get_client()
    st.success(f"Language model available: {client.provider} · {client.model} (runs locally)" if client.provider == "ollama"
               else f"Language model available: {client.provider} · {client.model}", icon="🤖")
except LLMUnavailable as exc:
    st.info(f"No language model available ({exc}). Explanations will show retrieved guidance only.", icon="ℹ️")

st.subheader("Search the knowledge base")
query = st.text_input("Ask about a weakness", placeholder="how do I prevent SQL injection in Python?")
cwe = st.number_input("Prefer passages for CWE (optional)", min_value=0, value=0, step=1)
if query:
    with st.spinner("Searching…"):
        passages = retriever.retrieve_for_text(query, store, k=5, cwe=cwe or None)
    for i, p in enumerate(passages, start=1):
        with st.expander(f"{i}. {p.citation}  ·  score {p.score:.2f}  ·  {p.reason}"):
            st.markdown(p.chunk.text[:2500])
            st.markdown(f"[Open source]({p.chunk.url}) · {p.chunk.publisher} · {p.chunk.license}")
