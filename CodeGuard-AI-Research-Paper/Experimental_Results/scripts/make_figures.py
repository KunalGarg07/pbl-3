"""Paper figures drawn from the project's saved metrics (artifacts/metrics/*.json), in greyscale for print.
Run from the project root after validate_v2_model.py."""
import json
import shutil
from pathlib import Path

import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
PAPER = Path(__file__).resolve().parents[2]
FIG = PAPER / "Figures"
SRC = PAPER / "Experimental_Results" / "source_metrics"
FIG.mkdir(exist_ok=True)
SRC.mkdir(exist_ok=True)
for f in (ROOT / "artifacts" / "metrics").glob("*.json"):
    if f.name != "explanations_sample.json":
        shutil.copyfile(f, SRC / f.name)          # read-only copies of the original results
shutil.copyfile(ROOT / "artifacts" / "model" / "model_card.json", SRC / "model_card_v2.json")

M = {f.stem: json.loads(f.read_text()) for f in SRC.glob("*.json")}
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.linewidth": 0.6})


def box(ax, x, y, w, h, text, fill="white", bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06", fc=fill, ec="black", lw=0.7))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=7, weight="bold" if bold else "normal")


def arrow(ax, x1, y1, x2, y2, dashed=False):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", lw=0.7, color="black", ls="--" if dashed else "-", shrinkA=0, shrinkB=0))


# ---- Fig. 1: architecture -----------------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(7.0, 2.7))
ax.set_xlim(0, 10); ax.set_ylim(0, 4); ax.axis("off")
ax.text(0.05, 3.75, "Detection path (every scan)", fontsize=7.5, style="italic")
box(ax, 0.05, 2.55, 1.35, 0.8, "Python source\n(.py or .zip)")
box(ax, 1.75, 2.55, 1.45, 0.8, "Input validation\n(type, size, UTF-8,\nast.parse)")
box(ax, 3.55, 3.0, 1.85, 0.7, "Bandit static analysis\n(rule matches, CWE)", fill="#e6e6e6")
box(ax, 3.55, 2.05, 1.85, 0.7, "ML classifier\n(TF-IDF + LR,\nper function)", fill="#e6e6e6")
box(ax, 5.75, 2.55, 1.6, 0.8, "Risk policy + AST\ncontext check\n(severity)")
box(ax, 7.75, 2.55, 2.15, 0.8, "Findings, history (SQLite),\nJSON/HTML report")
arrow(ax, 1.40, 2.95, 1.75, 2.95); arrow(ax, 3.20, 2.95, 3.55, 3.35); arrow(ax, 3.20, 2.95, 3.55, 2.4)
arrow(ax, 5.40, 3.35, 5.75, 2.95); arrow(ax, 5.40, 2.4, 5.75, 2.95); arrow(ax, 7.35, 2.95, 7.75, 2.95)
ax.text(0.05, 1.55, "On request (per finding)", fontsize=7.5, style="italic")
box(ax, 1.5, 0.35, 2.1, 0.8, "Retriever: 4 passages\n(CWE, OWASP, Bandit;\nMiniLM + NumPy)")
box(ax, 3.95, 0.35, 2.1, 0.8, "Local LLM (Llama 3.2 3B)\ncited JSON explanation,\nschema-validated")
box(ax, 6.4, 0.35, 2.1, 0.8, "Fix: template or LLM;\nvalidator re-runs Bandit\n(input never executed)")
ax.plot([6.55, 6.55, 2.55], [2.55, 1.75, 1.75], color="black", lw=0.7, ls="--")   # routed below the ML box
arrow(ax, 2.55, 1.75, 2.55, 1.15, dashed=True)
arrow(ax, 3.60, 0.75, 3.95, 0.75); arrow(ax, 6.05, 0.75, 6.4, 0.75)
ax.text(8.65, 0.75, "The ML score is\nshown separately\nand never sets\nseverity.", fontsize=6.5, va="center")
plt.tight_layout(pad=0.2)
plt.savefig(FIG / "fig1_architecture.png", dpi=300)
plt.close()

# ---- Fig. 2: CVEfixes preparation pipeline -----------------------------------------------------------------
fig, ax = plt.subplots(figsize=(3.45, 2.9))
ax.set_xlim(0, 4); ax.set_ylim(0, 5.2); ax.axis("off")
steps = [
    "CVEfixes v1.0.8 (12.7 GB, MD5-verified)\nPython methods: 7,568 from 428 repos, 840 CVEs",
    "Model v1 data: de-duplicated, conflicting labels removed\n6,627 methods (36% vulnerable)",
    "Model v2 data: true before/after pairs, code changed,\ntest code removed: 1,460 pairs = 2,920 methods",
    "Repository-grouped 80/20 split (seed 42)\ntrain 2,194 methods | test 726 methods (363 pairs, 69 repos)",
]
for i, s in enumerate(steps):
    y = 4.25 - i * 1.3
    box(ax, 0.05, y, 3.9, 0.85, s, fill="#f0f0f0" if i == 2 else "white")
    if i:
        arrow(ax, 2.0, y + 1.3, 2.0, y + 0.85)
plt.tight_layout(pad=0.1)
plt.savefig(FIG / "fig2_data_pipeline.png", dpi=300)
plt.close()

# ---- Fig. 3: cross-validated model comparison on v2 training data ----------------------------------------------
cv = {r["Model"]: r for r in M["python_results_v2"]["cross_validation"]}
names = ["Baseline (majority)", "Logistic Regression", "Random Forest", "XGBoost"]
labels = ["Majority\nbaseline", "Logistic\nRegression", "Random\nForest", "XGBoost"]
metrics = [("roc_auc", "ROC-AUC", "white"), ("pr_auc", "PR-AUC", "#bdbdbd"), ("f1", "F1 (thr. 0.5)", "#525252")]
fig, ax = plt.subplots(figsize=(3.45, 2.2))
x = np.arange(len(names)); w = 0.26
for k, (key, lab, col) in enumerate(metrics):
    vals = [cv[n][key] for n in names]
    bars = ax.bar(x + (k - 1) * w, vals, w, color=col, edgecolor="black", lw=0.5, label=lab)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.3f}".lstrip("0"), ha="center", va="bottom", fontsize=5.5, rotation=90)
ax.axhline(0.5, color="black", ls=":", lw=0.6)
ax.set_xticks(x, labels); ax.set_ylim(0, 0.75); ax.set_ylabel("Score (5-fold GroupKFold mean)")
ax.legend(frameon=False, fontsize=6.5, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.13))
plt.tight_layout(pad=0.2)
plt.savefig(FIG / "fig3_cv_model_comparison.png", dpi=300)
plt.close()

# ---- Fig. 5: system-level detection on held-out CVE code ---------------------------------------------------
eng = M["system_evaluation"]["cvefixes_test"]["engines"]
short = {"Bandit (all rules)": "Bandit\n(all)", "Bandit (Medium+)": "Bandit\n(Medium+)", "ML v2": "ML v2",
         "Combined: Bandit Medium+ OR ML": "Bandit M+\nOR ML", "Combined: Bandit AND ML": "Bandit\nAND ML"}
fig, ax = plt.subplots(figsize=(3.45, 2.2))
x = np.arange(len(eng)); w = 0.26
for k, (key, lab, col) in enumerate([("precision", "Precision", "white"), ("recall", "Recall", "#bdbdbd"),
                                     ("false_positive_rate", "False-positive rate", "#525252")]):
    ax.bar(x + (k - 1) * w, [e[key] for e in eng], w, color=col, edgecolor="black", lw=0.5, label=lab)
ax.set_xticks(x, [short[e["engine"]] for e in eng], fontsize=6.5); ax.set_ylim(0, 1)
ax.set_ylabel("Value on 726 test methods")
ax.legend(frameon=False, fontsize=6.5, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.13))
plt.tight_layout(pad=0.2)
plt.savefig(FIG / "fig5_system_detection.png", dpi=300)
plt.close()
print("figures:", sorted(p.name for p in FIG.glob("*.png")))
