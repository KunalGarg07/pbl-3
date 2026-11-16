"""Evaluation: every number here is read from files written by the experiments notebooks."""
import json

import ui_common
import pandas as pd
import streamlit as st

from codeguard.config import settings

ui_common.page_setup("Evaluation", "🧪")
st.title("🧪 Evaluation results")
st.caption("All numbers are loaded from artifacts/metrics/, written by the notebooks in experiments/. "
           "Nothing on this page is typed by hand.")

M, F = settings.metrics_dir, settings.figures_dir


def load(name: str):
    path = M / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def figure(name: str) -> None:
    if (F / name).exists():
        st.image(str(F / name), use_container_width=True)


tab_sys, tab_ml, tab_rag, tab_expl = st.tabs(["Detection (system)", "ML models", "Retrieval", "Explanations & fixes"])

with tab_sys:
    system = load("system_evaluation.json")
    if not system:
        st.info("Run experiments/08_final_system_evaluation.ipynb.")
    else:
        st.markdown("##### A. Hand-labelled fixtures (12 vulnerable, 11 safe files)")
        st.dataframe(pd.DataFrame(system["fixtures"]).set_index("engine"), use_container_width=True)
        real = system["cvefixes_test"]
        st.markdown(f"##### B. Real CVE-fix code: {real['methods']} methods ({real['pairs']} vulnerable/fixed pairs)")
        st.dataframe(pd.DataFrame(real["engines"]).set_index("engine"), use_container_width=True)
        st.markdown("**Does the engine flag the vulnerable version but not its fix?**")
        st.dataframe(pd.DataFrame(real["pairs_outcomes"]).set_index("engine"), use_container_width=True)
        figure("system_detection.png")
        st.markdown("##### D. Speed and reliability")
        st.dataframe(pd.Series(system["speed"], name="value").astype(str), use_container_width=True)
        st.caption(system.get("environment", ""))

with tab_ml:
    v2, v1, codebert, devign = load("python_results_v2.json"), load("python_results.json"), load("codebert_results.json"), load("devign_results.json")
    rows = {}
    if devign:
        rows["Devign (C) · TF-IDF + LR"] = devign["test"]
    if v1:
        rows[f"Python v1 · {v1['model_version']}"] = v1["test_metrics"]
    if v2:
        rows[f"Python v2 · {v2['model_version']} (scanner)"] = v2["test_metrics"]
    if codebert:
        rows["Python v2 data · CodeBERT"] = codebert["test_metrics"]
    if rows:
        cols = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc", "false_positive_rate", "pairwise_accuracy"]
        st.dataframe(pd.DataFrame(rows).T.reindex(columns=cols), use_container_width=True)
        st.caption("Each model is evaluated on held-out repositories (Python) or commits (Devign). Baselines: "
                   "Devign accuracy 0.549; Python v1 accuracy 0.626; Python v2 accuracy/pairwise 0.5. "
                   "v2 and CodeBERT are a second look at held-out data after v1 (see the notebooks).")
    for name in ("python_v2_test_curves.png", "devign_cv_comparison.png"):
        figure(name)

with tab_rag:
    rag = load("retrieval_results.json")
    if rag:
        st.markdown(f"{rag['queries']} real Bandit findings used as queries ({rag['by_source']}).")
        st.dataframe(pd.DataFrame(rag["summary"]).set_index("setting"), use_container_width=True)
        st.caption("Relevant = tagged with the finding's CWE or documenting its Bandit rule. Boosted settings use "
                   "the same tags, so 'Semantic only' is the fair test of the embeddings.")
        figure("retrieval_eval.png")
    else:
        st.info("Run experiments/07_retrieval_evaluation.ipynb.")

with tab_expl:
    system = load("system_evaluation.json")
    if system and system.get("explanations"):
        st.markdown(f"Language model: **{system.get('llm') or 'none'}**")
        st.dataframe(pd.Series(system["explanations"], name="value").astype(str), use_container_width=True)
        sample = load("explanations_sample.json") or []
        for rec in sample:
            with st.expander(f"{rec['rule']} · {rec['file']} · grounded={rec['grounded']} · fix {rec['fix_status']}"):
                st.markdown(f"**Summary:** {rec['summary']}\n\n**Why dangerous:** {rec['why_dangerous']}\n\n"
                            f"**Exploit conditions:** {rec['exploit_conditions']}")
                st.caption("Sources: " + "; ".join(rec["sources"]) + " · cited: " + ", ".join(rec["citations"]))
                if rec["diff"]:
                    st.code(rec["diff"], language="diff")
        st.caption("Human scoring of these explanations is recorded in Documents/Explanation_Evaluation.docx.")
    else:
        st.info("Run experiments/08_final_system_evaluation.ipynb.")
