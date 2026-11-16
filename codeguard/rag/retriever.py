"""Retrieve security guidance for a finding.

Query = the finding's rule name, category, CWE and evidence. Ranking = cosine similarity plus a
boost for chunks tagged with the finding's CWE or Bandit rule, so the authoritative page for the
weakness is preferred over a merely similar-sounding one. Results are de-duplicated per document.
For findings, one slot each is reserved for the Bandit rule page, the CWE entry and an OWASP cheat
sheet tagged with the CWE ("diverse" mode), chosen after experiment 07 showed the boosts alone often
returned definitions without practical guidance.
"""
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

from codeguard.config import settings
from codeguard.rag.chunker import Chunk
from codeguard.rag.store import VectorStore
from codeguard.schemas import Finding

CWE_BOOST = 0.25
RULE_BOOST = 0.30
# Bump when ranking changes, so cached explanations built from older retrieval are not reused.
RETRIEVAL_VERSION = "diverse-1"


class KnowledgeBaseUnavailable(RuntimeError):
    """The vector index has not been built yet (run scripts/ingest_kb.py)."""


@dataclass
class Passage:
    chunk: Chunk
    score: float
    reason: str

    @property
    def citation(self) -> str:
        section = f" — {self.chunk.section}" if self.chunk.section else ""
        return f"{self.chunk.title}{section}"


@lru_cache(maxsize=1)
def get_embedder(model_name: str | None = None):
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(model_name or settings.embedding_model, device="cpu")


def embed(texts: list[str], model_name: str | None = None) -> np.ndarray:
    return get_embedder(model_name).encode(texts, normalize_embeddings=True, batch_size=64,
                                           show_progress_bar=False, convert_to_numpy=True)


@lru_cache(maxsize=1)
def load_store(directory: Path | None = None) -> VectorStore:
    directory = directory or settings.kb_index_dir
    if not (directory / "vectors.npy").exists():
        raise KnowledgeBaseUnavailable("Knowledge base not built. Run: python scripts/ingest_kb.py")
    return VectorStore.load(directory)


def finding_query(f: Finding) -> str:
    parts = [f.category, f.rule_name.replace("_", " "), f.evidence]
    if f.cwe:
        parts.append(f"CWE-{f.cwe}")
    return ". ".join(p for p in parts if p)


def retrieve_for_text(query: str, store: VectorStore, k: int = 4, cwe: int | None = None,
                      rule_id: str | None = None, query_vector: np.ndarray | None = None,
                      diverse: bool = False) -> list[Passage]:
    qv = embed([query])[0] if query_vector is None else query_vector
    scores = store.similarities(qv)
    reasons = {}
    for i in store.indices_for_cwe(cwe):
        scores[i] += CWE_BOOST
        reasons[i] = f"tagged CWE-{cwe}"
    for i in store.indices_for_rule(rule_id):
        scores[i] += RULE_BOOST
        reasons[i] = f"documents rule {rule_id}"
    ranked = np.argsort(-scores)
    chosen: list[int] = []
    if diverse:
        # Reserve one slot each for the rule's Bandit page, the CWE entry and practical OWASP guidance
        # tagged with the CWE, so the model sees a definition *and* advice (see experiment 07).
        rule_set, cwe_set = set(store.indices_for_rule(rule_id)), set(store.indices_for_cwe(cwe))
        for wanted in (lambda i: i in rule_set,
                       lambda i: i in cwe_set and store.chunks[i].kind == "cwe",
                       lambda i: i in cwe_set and store.chunks[i].kind == "owasp"):
            pick = next((int(i) for i in ranked if wanted(i)), None)
            if pick is not None and pick not in chosen:
                chosen.append(pick)
    passages, seen_docs = [], set()
    for i in chosen + [int(i) for i in ranked]:
        chunk = store.chunks[i]
        if chunk.doc_id in seen_docs:
            continue
        seen_docs.add(chunk.doc_id)
        passages.append(Passage(chunk, float(scores[i]), reasons.get(i, "semantic match")))
        if len(passages) == k:
            break
    return sorted(passages, key=lambda p: -p.score)


def retrieve(finding: Finding, k: int = 4, store: VectorStore | None = None) -> list[Passage]:
    store = store or load_store()
    rule = finding.rule_id if finding.source == "bandit" else None
    return retrieve_for_text(finding_query(finding), store, k=k, cwe=finding.cwe, rule_id=rule, diverse=True)
