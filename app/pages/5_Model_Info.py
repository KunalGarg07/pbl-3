"""Model information: supported language, model card, experiment results, risk policy."""
import json

import ui_common
import pandas as pd
import streamlit as st

from codeguard.config import settings
from codeguard.scanner import ml_detector, risk_assessor
from codeguard.scanner.rules import ESCALATE_TO_HIGH

ui_common.page_setup("Model info", "📊")
st.title("📊 Models, results and limits")

st.subheader("Python ML model (used by the scanner)")
card = ml_detector.model_card()
if card:
    c1, c2, c3 = st.columns(3)
    c1.metric("Model version", card.get("model_version", "—"))
    c2.metric("Language", card.get("language", "python"))
    c3.metric("Decision threshold", card.get("threshold", 0.5))
    if card.get("test_metrics"):
        st.markdown("**Held-out test set**")
        st.dataframe(pd.DataFrame([card["test_metrics"]]), hide_index=True, use_container_width=True)
    st.caption(card.get("training_data", "") + " · threshold rule: " + card.get("threshold_method", ""))
    curves = settings.figures_dir / "python_v2_test_curves.png"
    if curves.exists():
        st.image(str(curves), use_container_width=True)
    with st.expander("Full model card"):
        st.json(card)
    v1_card = settings.model_path.parent / "v1" / "model_card.json"
    if v1_card.exists():
        v1 = json.loads(v1_card.read_text(encoding="utf-8"))
        with st.expander(f"Earlier version: {v1.get('model_version')} (all methods, F1 threshold)"):
            st.dataframe(pd.DataFrame([v1["test_metrics"], card.get("test_metrics", {})],
                                      index=[v1.get("model_version"), card.get("model_version")]).T,
                         use_container_width=True)
            st.caption("v1 flagged 83% of safe methods; v2 removed unpaired methods and test code and caps the "
                       "false-positive rate. v2's test is a second look at held-out repositories.")
else:
    st.info("Not trained yet. The scanner currently runs Bandit only. "
            "Create the model with `experiments/05_python_model_training_evaluation.ipynb`.", icon="ℹ️")

st.subheader("Devign experiment (C code — not used by the scanner)")
devign_path = settings.metrics_dir / "devign_results.json"
if devign_path.exists():
    devign = json.loads(devign_path.read_text(encoding="utf-8"))
    st.caption(f"{devign.get('dataset')} · {devign.get('split')}")
    st.markdown("**Cross-validation on the training set**")
    st.dataframe(pd.DataFrame(devign["cross_validation"]).set_index("Model"), use_container_width=True)
    st.markdown("**Best model on the held-out test set**")
    st.dataframe(pd.DataFrame([devign["test"]]), hide_index=True, use_container_width=True)
    for name in ("devign_cv_comparison.png", "devign_test_curves.png"):
        path = settings.figures_dir / name
        if path.exists():
            st.image(str(path), use_container_width=True)
else:
    st.caption("Run experiments/03_devign_model_evaluation.ipynb to see these results.")

st.subheader("Risk policy (version 2)")
st.markdown(risk_assessor.__doc__.split("\n", 2)[2])
st.caption("Rules raised from Medium to High at HIGH confidence: " + ", ".join(sorted(ESCALATE_TO_HIGH)))

st.subheader("Limitations")
st.markdown(f"""
- {ui_common.LIMITATIONS}
- Bandit works on single files and does not track data flow, so it cannot tell whether user input
  actually reaches a risky call. Some findings will be false alarms; some bugs match no rule.
- The ML model only says whether a whole function looks risky; it cannot point to the exact line.
- Only Python is supported.
""")
