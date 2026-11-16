# Research Validation Checklist — CodeGuard AI paper

Checked on 6 November 2026 against the project files. ✅ means verified, ⚠️ means verified with a caveat stated in the paper, and ❌ means not verifiable, so the item is left out of the paper.

## 1. Reference values given in the brief vs project evidence

| Value in the brief | Evidence found | Status | Used in paper as |
|---|---|---|---|
| Devign ≈ 5,464 records → 5,458 after duplicate removal | Mentioned only in notebook 02's text as "an earlier version"; that version's outputs were not kept | ❌ | Not used. The paper reports the full Devign run instead: 27,318 → 27,138 |
| Devign grouped split, TF-IDF + LR, test F1 ≈ 0.497 | No saved output; only cited in the 12-week report | ❌ | Not used. The verified full-data result is test F1 0.529 |
| Comparison against an always-safe baseline | `devign_results.json` | ✅ | Accuracy 0.545 vs baseline 0.549 |
| CVEfixes ≈ 2,920 Python methods | `python_results_v2.json` (2,194 + 726) | ✅ | v2 data |
| Repository-grouped five-fold evaluation | notebook 05b, `GroupKFold(n_splits=5)` | ✅ | Section V |
| LR ROC-AUC ≈ 0.553 | `python_results_v2.json` cross_validation | ✅ | CV value (Table III). The v1 *test* ROC-AUC is also 0.553, in a different table |
| LR F1 ≈ 0.538 | same | ✅ | CV, threshold 0.5 |
| RF F1 ≈ 0.545 | same | ✅ | CV, threshold 0.5 |
| XGBoost F1 ≈ 0.540 | same | ✅ | CV, threshold 0.5 |
| CodeBERT ROC-AUC ≈ 0.521, F1 ≈ 0.173 | `codebert_results.json` test_metrics | ✅ | Test values (Table IV) |

## 2. Results kept apart in the paper

- **Cross-validation:** Tables II and III and Fig. 3, labelled CV.
- **Held-out test:** Table IV (v1, v2, CodeBERT, each with its own test size), Table V and Fig. 4.
- **Historical vs deployed:** v1 is labelled historical; v2 is the deployed model.
- **New for the paper:** bootstrap intervals and the threshold sweep (Table V, Fig. 4), described as an added analysis.
- **System level:** fixtures vs real CVE code (Table VI), kept separate from model-level results.

## 3. Methodology checks

| Check | Result |
|---|---|
| Duplicate handling | ✅ Devign duplicates removed; CVEfixes code strings under both labels removed |
| Data leakage | ✅ Grouped splits by commit or repository; leakage quantified on Devign (F1 0.581 random vs 0.529 grouped) |
| Repository separation | ✅ GroupShuffleSplit and GroupKFold by repository |
| Class balance | ✅ v2 is balanced (pairs); the baseline is reported |
| Shortcut learning | ✅ v1 test-code shortcut found and fixed in v2 (FPR 0.833 → 0.080) |
| Test reuse | ⚠️ The v2 test is a second look at held-out repositories; disclosed in Section V |
| Saved metrics reproducible | ✅ `validate_v2_model.py` reproduces all seven saved v2 test metrics exactly |
| Statistical uncertainty | ✅ Pair-level bootstrap intervals; all exclude 0.5 |
| False positives and negatives | ✅ Confusion matrix (37 / 29 / 326 / 334), pair outcomes and per-CWE recall |
| Explanation evaluation | ⚠️ Automatic rubric only; human scoring not done (stated as a limitation) |
| LLM-alone vs RAG comparison | ❌ Not run; stated as a limitation, no result claimed |
| Docker sandbox | ⚠️ Implemented, not exercised; stated as a limitation |

## 4. Technical claims checked against the code

- **Bandit runs as a subprocess:** argument list, no shell, 30 s timeout (`codeguard/scanner/static_analyzer.py`).
- **Input validation:** 200,000-byte limit, UTF-8, `ast.parse` (`codeguard/pipeline.py`); submitted code is never executed (canary test).
- **Severity escalation set:** B102, B301, B302, B307, B506, B602, B605 (`codeguard/scanner/rules.py`).
- **Context check:** input sources, Critical rule and test-code lowering (`codeguard/scanner/context.py`, `risk_assessor.py`).
- **Classifier settings:** token pattern and TF-IDF and model parameters (notebook 05b); threshold 0.5456 (`model_card.json`).
- **Retrieval:** 3,320 passages; boosts +0.25 for CWE and +0.30 for rule; diverse slots (`codeguard/rag/retriever.py`).
- **Explanation:** JSON schema, one retry, citations filtered (`codeguard/llm/explainer.py`).
- **Test suite:** 116 tests pass (last run 29 Oct 2026 after the ML-score fix).

## 5. Citations

- **Coverage:** 26 references, all cited in the text and listed in citation order.
- **DOIs:** all 16 checked on Crossref (title, authors, venue, year, pages).
- **arXiv:** the 5 arXiv IDs were checked with the arXiv API.
- **No DOI:** scikit-learn (JMLR) and Efron and Tibshirani (book) are standard references. Bandit, CWE and OWASP are cited as documentation websites.
- **Venue detail:** PrimeVul is cited as an arXiv preprint because its conference version was not verified.

## 6. Formatting

- **Layout:** US Letter, two columns of 3.5 in with a 0.25 in gap, Times New Roman 10 pt, IEEE-style headings, captions and numeric citations.
- **Not the official template:** the paper was **not** built from the official IEEE Word template, so it should not be described as IEEE-compliant until it has been transferred into the template required by the target venue.
- **Rendered check:** all 7 pages were rendered. No tables or figures overflow, and Tables I–VII and Figs. 1–5 are numbered in order and referenced in the text.

## 7. Placeholders still to fill

1. Author email addresses (4 × "[email address]").
2. Author order and the supervisor's position (currently: the three students, then Dr Kanwalpreet Kour).
3. Acknowledgment text.
4. Target venue and page limit; adjust the layout to that venue's template.

## 8. Reviewer-style weaknesses (acknowledged in the paper)

- The headline classifier result is weak (ROC-AUC 0.544); the contribution is the system design and the honest evaluation, not a new model.
- Small dataset, and a v2 test that reuses held-out repositories.
- No human evaluation of explanations, and no LLM-with-vs-without-retrieval comparison.
- The context check covers one function only; the CodeBERT run was constrained (CPU, 256 tokens).
- Per-CWE counts are small (10–94 methods), so complementarity is only indicated.
- No sample paper was found in the workspace or conversation, so a standard IEEE conference structure was used.
