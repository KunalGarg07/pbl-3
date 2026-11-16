# CodeGuard AI

AI-assisted vulnerability detection for Python code. It answers seven questions for every finding:
what is the problem, where is it, why is it unsafe, how serious is it, how sure is the system, how do we
fix it, and does the fix hold up.

| Layer | What it does |
|---|---|
| **Static analysis** | [Bandit](https://bandit.readthedocs.io/) finds known unsafe patterns, with exact lines |
| **ML detector** | TF-IDF + Logistic Regression trained on real Python CVE fixes (CVEfixes) scores every function |
| **Risk policy** | Documented severity rules, plus a context check: does user input reach the call? Is it test code? |
| **RAG explanations** | Retrieves MITRE CWE, OWASP Cheat Sheet and Bandit guidance; a local LLM (Ollama) explains and cites it |
| **Fix validation** | Rule-based or AI fixes are re-scanned, checked for new issues and optionally unit-tested in Docker |
| **Repository scan** | Safely scans a zipped project (path-traversal checks and size limits) |

Technologies: Python 3.13, Bandit, scikit-learn, sentence-transformers, NumPy, Ollama (Llama 3.2 3B),
Streamlit, SQLite, pytest, Jupyter.

## Prerequisites

- Python 3.13 (tested with 3.13.5 on Windows 11)
- Optional: [Ollama](https://ollama.com) for AI explanations, Docker Desktop for running unit tests of a fix

## Setup

```bash
pip install -r requirements.txt
```

Optional settings: copy `.env.example` to `.env` and edit it. Every setting has a default, so this step can
be skipped. Never commit `.env`.

| Variable | Default | Meaning |
|---|---|---|
| `CODEGUARD_STORE_SOURCE` | `false` | Keep submitted code in the history database (otherwise only a SHA-256) |
| `CODEGUARD_DB_PATH` | `codeguard_data/scans.db` | SQLite history database |
| `CODEGUARD_MAX_BYTES` | `200000` | Largest accepted `.py` file |
| `CODEGUARD_LLM_PROVIDER` | `ollama` | `ollama` or `anthropic` |
| `OLLAMA_MODEL` | `llama3.2` | Local model used for explanations |
| `ANTHROPIC_API_KEY` | empty | Only for the optional hosted model |

Build the security knowledge base (downloads the OWASP Cheat Sheets and CWE once, about 1–2 minutes):

```bash
python scripts/ingest_kb.py
```

Optional, for AI explanations:

```bash
ollama pull llama3.2
```

## Run

```bash
streamlit run app/Home.py
```

The app opens at http://localhost:8501. The Scan page has example files to load, including
`04_shop_backend.py`, a 245-line file with planted issues for manual testing.

Create the two archives used to demo the Repository Scan page (written to `codeguard_data/demo/`):

```bash
python scripts/make_demo_zips.py
```

The scanner still works without Ollama (explanations show the retrieved guidance only), without Docker (unit
tests of a fix are skipped) and without the ML model (Bandit only).

## Tests

```bash
pytest -q
```

116 tests, about 1 minute. The fixture evaluation writes `reports/evaluation_suite.md`:

```bash
python scripts/run_eval.py
```

## Rebuilding the data and models

Raw and processed data are not committed. See `Documents/Datasets_Guide.docx` for details.

| Step | Command | Output |
|---|---|---|
| Devign (C) | `python scripts/download_devign.py` | `datasets/raw/devign_*.parquet` |
| CVEfixes v1.0.8 | download the 12.7 GB zip from Zenodo into `datasets/raw/CVEfixes/` | |
| Python dataset | `python scripts/build_python_dataset.py --from-zip datasets/raw/CVEfixes/CVEfixes_v1.0.8.zip` | `datasets/processed/python_functions.csv` |
| Experiments | run the notebooks in `experiments/` in order, `01` … `08` | models in `artifacts/model/`, metrics in `artifacts/metrics/` |

## Project structure

| Path | What is in it |
|---|---|
| `codeguard/` | The package: `scanner/`, `rag/`, `llm/`, `remediation/`, `repo/`, `storage/`, `reporting/`, `pipeline.py`, `config.py` |
| `app/` | Streamlit interface (`Home.py`, `pages/`) and example files (`examples/`) |
| `scripts/` | Data download/build, knowledge-base ingestion, evaluation, demo archives |
| `tests/` | pytest suite and code fixtures (vulnerable, safe, edge cases, adversarial) |
| `experiments/` | Jupyter notebooks: datasets, cleaning/EDA, model training, CodeBERT, retrieval and system evaluation; `archive/` holds the first, invalid notebook |
| `artifacts/` | Saved models with model cards, metrics (JSON) and figures |
| `knowledge_base/` | `sources.yaml`; the downloaded documents and the search index are rebuilt by `scripts/ingest_kb.py` |
| `datasets/` | `raw/` and `processed/` data (not committed) |
| `codeguard_data/` | Runtime data: scan history and demo archives (not committed) |
| `Documents/` | All project documents in Word format (see below) |
| `docs/` | Project proposal (PDF) and app screenshots |
| `slides/` | Presentation sources (`deck.json` and one HTML file per slide) |

## Documents

| File in `Documents/` | Content |
|---|---|
| `Project_Report.docx` | Full project report |
| `12_Week_Report.docx` | Week-by-week progress |
| `Project_Plan.docx` | 12-week plan, technology choices, risks |
| `Final_Report_Summary.docx` | Short results summary |
| `Model_Evaluation.docx`, `Evaluation_Suite.docx`, `Explanation_Evaluation.docx` | Evaluation results; the explanation sheet has the human scoring table |
| `Limitations.docx` | What the system cannot do, and the documented severity policy |
| `Demonstration_Script.docx`, `Demo_Script_Short.docx` | Live demo, step by step |
| `Project_Evaluation_Handbook.docx`, `Project_Evaluation_Guide.docx` | Viva preparation |
| `Project_Audit_Report.docx` | 29 Oct 2026 audit: tests, fixes, open issues |
| `Datasets_Guide.docx`, `Experiments_Guide.docx`, `Experiments_Archive_Note.docx`, `Slides_Speaker_Notes.docx` | Guides to the data, notebooks and slides |
| `README.docx` | This README in Word format |

## Safety

CodeGuard AI never runs the code you submit. The only execution is your own unit tests, and only inside a
locked-down Docker container. A clean scan does not prove that code is secure.
