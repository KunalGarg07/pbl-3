"""Supplementary validation of the saved v2 scanner model (research paper, Nov 2026).

Rebuilds the repository-held-out test split exactly as experiments/05b and 08 do, scores it with the
saved model (read-only), and adds analyses the original notebooks did not report:
  1. a check that the saved test metrics are reproduced;
  2. 95% bootstrap confidence intervals (resampling vulnerable/fixed pairs, 2,000 replicates);
  3. the confusion matrix at the deployed threshold;
  4. a threshold sweep (precision, recall, false-positive rate).
Nothing in artifacts/ or datasets/ is modified. Outputs go next to this script's parent folder.

Run from the project root:  python CodeGuard-AI-Research-Paper/Experimental_Results/scripts/validate_v2_model.py
"""
import json
import re
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_curve, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parents[1]
FIG = OUT.parent / "Figures"
FIG.mkdir(exist_ok=True)

# ---- test split: same steps and seed as experiments/05b_python_model_v2.ipynb and 08 -------------------
raw = pd.read_csv(ROOT / "datasets" / "processed" / "python_functions.csv")
KEY = ["commit_hash", "file_path", "method_name"]
sizes = raw.groupby(KEY)["target"].agg(n="size", vulnerable="sum")
pairs = raw.set_index(KEY).loc[sizes[(sizes["n"] == 2) & (sizes["vulnerable"] == 1)].index].reset_index()
pairs["code_key"] = pairs["func"].str.replace(r"\s+", "", regex=True)
changed = pairs.groupby(KEY)["code_key"].nunique() == 2
pairs = pairs.set_index(KEY).loc[changed[changed].index].reset_index()
TEST_PATH = re.compile(r"(^|/)(tests?|testing|unit_tests)/|(^|/)test_[^/]*\.py$|_tests?\.py$|(^|/)conftest\.py$")
TEST_NAME = re.compile(r"^(test|_test|setUp|tearDown|setUpClass|tearDownClass)")
is_test = pairs["file_path"].str.contains(TEST_PATH) | pairs["method_name"].str.contains(TEST_NAME)
pairs = pairs[~pairs.groupby(KEY)["file_path"].transform(lambda s: is_test.loc[s.index].any())]
conflict = pairs.groupby("code_key")["target"].nunique()
pairs = pairs[~pairs["code_key"].isin(conflict[conflict > 1].index)]
pairs = pairs[pairs.groupby(KEY)["target"].transform("size") == 2].copy()
pairs["pair_id"] = pairs.groupby(KEY).ngroup()
df = pairs.reset_index(drop=True)
_, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42).split(df, df["target"], df["repo_url"]))
test = df.iloc[test_idx].reset_index(drop=True)

model = joblib.load(ROOT / "artifacts" / "model" / "python_vuln_model.joblib")
card = json.loads((ROOT / "artifacts" / "model" / "model_card.json").read_text())
thr = card["threshold"]
y = test["target"].to_numpy()
s = model.predict_proba(test["func"])[:, 1]
pred = s >= thr


def pairwise(frame):
    p = frame.pivot_table(index="pair_id", columns="target", values="score", aggfunc="first")
    return float((p[1] > p[0]).mean())


test["score"] = s
tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
point = {
    "roc_auc": roc_auc_score(y, s), "pr_auc": average_precision_score(y, s), "pairwise_accuracy": pairwise(test),
    "precision": tp / (tp + fp), "recall": tp / (tp + fn), "false_positive_rate": fp / (fp + tn),
    "f1": 2 * tp / (2 * tp + fp + fn),
}
saved = json.loads((ROOT / "artifacts" / "metrics" / "python_results_v2.json").read_text())["test_metrics"]
reproduced = {k: (round(point[k], 3), saved[k]) for k in ("roc_auc", "pr_auc", "pairwise_accuracy", "precision", "recall", "f1", "false_positive_rate")}

# ---- bootstrap over pairs ----------------------------------------------------------------------------------
rng = np.random.default_rng(42)
ids = test["pair_id"].unique()
by_pair = {pid: g.index.to_numpy() for pid, g in test.groupby("pair_id")}
boot = {"roc_auc": [], "pr_auc": [], "pairwise_accuracy": []}
for _ in range(2000):
    pick = rng.choice(ids, size=len(ids), replace=True)
    idx = np.concatenate([by_pair[p] for p in pick])
    yb, sb = y[idx], s[idx]
    boot["roc_auc"].append(roc_auc_score(yb, sb))
    boot["pr_auc"].append(average_precision_score(yb, sb))
    sub = test.iloc[idx].assign(pair_id=np.repeat(np.arange(len(pick)), 2))
    boot["pairwise_accuracy"].append(pairwise(sub))
ci = {k: [round(float(np.percentile(v, 2.5)), 3), round(float(np.percentile(v, 97.5)), 3)] for k, v in boot.items()}

# ---- threshold sweep ---------------------------------------------------------------------------------------
sweep = []
for t in np.round(np.arange(0.40, 0.66, 0.01), 2):
    pr = s >= t
    tp_, fp_ = int((pr & (y == 1)).sum()), int((pr & (y == 0)).sum())
    sweep.append({"threshold": float(t), "precision": round(tp_ / (tp_ + fp_), 3) if tp_ + fp_ else None,
                  "recall": round(tp_ / int((y == 1).sum()), 3), "false_positive_rate": round(fp_ / int((y == 0).sum()), 3)})

result = {
    "description": "Supplementary validation of the saved v2 model on the repository-held-out CVEfixes test split",
    "model_version": card.get("model_version"), "threshold": thr,
    "test_methods": int(len(test)), "test_pairs": int(len(ids)), "test_repositories": int(test["repo_url"].nunique()),
    "reproduced_vs_saved": reproduced,
    "point_estimates": {k: round(float(v), 3) for k, v in point.items()},
    "bootstrap_95ci_over_pairs": ci, "bootstrap_replicates": 2000, "bootstrap_seed": 42,
    "confusion_matrix_at_threshold": {"TP": int(tp), "FP": int(fp), "FN": int(fn), "TN": int(tn)},
    "threshold_sweep": sweep,
}
(OUT / "v2_supplementary_validation.json").write_text(json.dumps(result, indent=2))

# ---- figures -----------------------------------------------------------------------------------------------
plt.rcParams.update({"font.family": "serif", "font.size": 8})
fig, ax = plt.subplots(2, 1, figsize=(3.45, 4.3))
prec, rec, _ = precision_recall_curve(y, s)
ax[0].plot(rec, prec, color="black", lw=1)
ax[0].axhline(0.5, color="gray", ls="--", lw=0.8, label="chance (0.5)")
ax[0].scatter([point["recall"]], [point["precision"]], color="black", s=14, zorder=3, label=f"deployed threshold {thr}")
ax[0].set_xlabel("Recall"); ax[0].set_ylabel("Precision"); ax[0].set_title("(a) Precision-recall, test set")
ax[0].set_xlim(0, 1); ax[0].set_ylim(0.3, 1.0); ax[0].legend(frameon=False, fontsize=7)
ts = [r["threshold"] for r in sweep]
ax[1].plot(ts, [r["recall"] for r in sweep], color="black", lw=1, label="recall")
ax[1].plot(ts, [r["false_positive_rate"] for r in sweep], color="black", lw=1, ls="--", label="false-positive rate")
ax[1].plot(ts, [r["precision"] if r["precision"] is not None else np.nan for r in sweep], color="gray", lw=1, label="precision")
ax[1].axvline(thr, color="gray", ls=":", lw=0.8)
ax[1].set_xlabel("Decision threshold"); ax[1].set_title("(b) Threshold sweep, test set"); ax[1].set_ylim(0, 1)
ax[1].legend(frameon=False, fontsize=7)
plt.tight_layout()
plt.savefig(FIG / "fig4_v2_pr_threshold.png", dpi=300)

fig, ax = plt.subplots(figsize=(2.4, 2.1))
cm = np.array([[tn, fp], [fn, tp]])
ax.imshow(cm, cmap="Greys", vmin=0, vmax=cm.max() * 1.6)
for (i, j), v in np.ndenumerate(cm):
    ax.text(j, i, str(v), ha="center", va="center", fontsize=9)
ax.set_xticks([0, 1], ["fixed", "vulnerable"]); ax.set_yticks([0, 1], ["fixed", "vulnerable"])
ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
plt.tight_layout()
plt.savefig(FIG / "fig_v2_confusion.png", dpi=300)

print(json.dumps({k: result[k] for k in ("test_methods", "test_pairs", "test_repositories", "reproduced_vs_saved",
                                         "bootstrap_95ci_over_pairs", "confusion_matrix_at_threshold")}, indent=1))
