# Research Methodology — CodeGuard AI paper

This document records how the evidence in `CodeGuard_AI_Research_Paper.docx` was produced, so that every number can be traced to a file.

## 1. Research questions

| RQ | Question | Evidence |
|---|---|---|
| RQ1 | How much does the data split change the measured performance of a lightweight detector? | `experiments/03_devign_model_evaluation.ipynb`, `artifacts/metrics/devign_results.json` |
| RQ2 | Which lightweight classifier works best on Python methods under repository-grouped evaluation, and does a pretrained transformer help? | `experiments/05_python_model_training_evaluation.ipynb`, `05b_python_model_v2.ipynb`, `06_codebert_experiment.ipynb`; `python_results.json`, `python_results_v2.json`, `codebert_results.json` |
| RQ3 | How do Bandit, the classifier and their combinations compare on held-out real CVE code and on controlled fixtures? | `experiments/08_final_system_evaluation.ipynb`, `system_evaluation.json` |
| RQ4 | How reliable are retrieval and generated explanations? | `experiments/07_retrieval_evaluation.ipynb`, `retrieval_results.json`; explanation rubric in notebook 08 |

## 2. Data

| Dataset | Source | Processing | Final size |
|---|---|---|---|
| Devign | CodeXGLUE, all three splits (`scripts/download_devign.py`) | Whitespace-normalised duplicates removed (90 groups, 86 with conflicting labels) | 27,138 C functions |
| CVEfixes v1.0.8 | Zenodo, 12.7 GB, MD5-verified (`scripts/build_python_dataset.py --from-zip`) | Python methods streamed from the archive; before fix = 1, after fix = 0 | 7,568 methods, 428 repositories, 840 CVEs |
| CVEfixes v1 data | as above | de-duplication, conflicting labels removed | 6,627 methods (36% vulnerable) |
| CVEfixes v2 data | as above | true before/after pairs only, code changed, test files and test functions removed, no code string under both labels | 1,460 pairs = 2,920 methods, 341 repositories |
| Fixture suite | `tests/fixtures/` | hand-written | 12 vulnerable, 11 safe, 7 edge-case files |

## 3. Splits and model selection

- Devign: `GroupShuffleSplit` 80/20 grouped by commit, seed 42; five-fold `GroupKFold` on the training part. Test set: 5,237 functions.
- CVEfixes: `GroupShuffleSplit` 80/20 grouped by repository, seed 42; five-fold `GroupKFold` on the training part.
  - v2 train: 2,194 methods; test: 726 methods (363 pairs, 69 repositories).
- The model selection criterion for v2 (ROC-AUC) was fixed before testing.
- **Test reuse:** the v1 test set was evaluated once. The v2 test is a second look at the same repository-held-out split, after v1's shortcut was diagnosed. v1 and v2 are reported separately, and nothing was tuned on the v2 test.

## 4. Models

| Model | Configuration |
|---|---|
| Features | TF-IDF, token pattern `[A-Za-z_]\w*\|\d+\|==\|!=\|<=\|>=\|\*\*\|[%+\-*/=<>()\[\]{}.,:'"]`, 1–2-grams, `min_df=2`, `max_features=20000`, `sublinear_tf=True`, no lowercasing |
| Logistic Regression | `C=1.0`, `max_iter=3000` |
| Random Forest | 300 trees, `min_samples_leaf=2`, seed 42 |
| XGBoost | 300 trees, depth 6, learning rate 0.1, `hist` |
| CodeBERT | `microsoft/codebert-base`, 256 tokens, 3 epochs on CPU, 1,700 train / 494 validation, epoch chosen by validation ROC-AUC |
| Threshold (v2) | lowest threshold with out-of-fold training FPR ≤ 0.10, giving 0.5456 |

## 5. Metrics

Precision, recall, F1, false-positive rate, ROC-AUC, PR-AUC (average precision), and pairwise accuracy. Pairwise accuracy is the share of vulnerable/fixed pairs in which the vulnerable version scores higher.

## 6. Supplementary analysis added for the paper

`Experimental_Results/scripts/validate_v2_model.py` (new; it leaves `artifacts/` and `datasets/` untouched):

1. Rebuilds the v2 test split with the same code and seed as notebooks 05b and 08.
2. Loads the saved model and checks that every saved test metric is reproduced (`reproduced_vs_saved` in the output; all match).
3. Computes 95% percentile-bootstrap intervals with 2,000 replicates, resampling whole pairs (seed 42).
4. Records the confusion matrix and a threshold sweep from 0.40 to 0.65, and draws `Figures/fig4_v2_pr_threshold.png`.

Output: `Experimental_Results/v2_supplementary_validation.json`.

`Experimental_Results/scripts/make_figures.py` draws Figures 1, 2, 3 and 5 from read-only copies of the original metrics in `Experimental_Results/source_metrics/`.

## 7. Environment

Windows 11, CPU only, Python 3.13.5, scikit-learn 1.6.1, Bandit 1.8.6, Llama 3.2 3B through Ollama, all-MiniLM-L6-v2 embeddings.

## 8. How to reproduce

```bash
python CodeGuard-AI-Research-Paper/Experimental_Results/scripts/validate_v2_model.py
python CodeGuard-AI-Research-Paper/Experimental_Results/scripts/make_figures.py
```

Run both from the project root. The original experiments are the notebooks in `experiments/`, which need the datasets described in `Documents/Datasets_Guide.docx`.
