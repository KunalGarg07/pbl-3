"""A small persistent vector store: normalised embeddings in a .npy file plus chunk metadata in JSON.

The knowledge base has a few thousand chunks, so exact cosine search with NumPy is fast (milliseconds)
and needs no database server. Metadata (CWE ids, Bandit rule ids) supports filtering and boosting.
"""
import json
from dataclasses import asdict
from pathlib import Path

import numpy as np

from codeguard.rag.chunker import Chunk


class VectorStore:
    def __init__(self, vectors: np.ndarray, chunks: list[Chunk], info: dict | None = None):
        if len(vectors) != len(chunks):
            raise ValueError(f"Index is inconsistent: {len(vectors)} vectors for {len(chunks)} chunks. "
                             "Rebuild it with scripts/ingest_kb.py.")
        self.vectors = vectors.astype(np.float32)
        self.chunks = chunks
        self.info = info or {}
        self._by_cwe: dict[int, list[int]] = {}
        self._by_rule: dict[str, list[int]] = {}
        for i, c in enumerate(chunks):
            for cwe in c.cwe_ids:
                self._by_cwe.setdefault(cwe, []).append(i)
            for rule in c.rule_ids:
                self._by_rule.setdefault(rule, []).append(i)

    def __len__(self) -> int:
        return len(self.chunks)

    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        np.save(directory / "vectors.npy", self.vectors)
        (directory / "chunks.json").write_text(json.dumps([asdict(c) for c in self.chunks]), encoding="utf-8")
        (directory / "info.json").write_text(json.dumps(self.info, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, directory: Path) -> "VectorStore":
        vectors = np.load(directory / "vectors.npy")
        chunks = [Chunk(**c) for c in json.loads((directory / "chunks.json").read_text(encoding="utf-8"))]
        info_path = directory / "info.json"
        info = json.loads(info_path.read_text(encoding="utf-8")) if info_path.exists() else {}
        return cls(vectors, chunks, info)

    def similarities(self, query_vector: np.ndarray) -> np.ndarray:
        return self.vectors @ query_vector.astype(np.float32)

    def indices_for_cwe(self, cwe: int | None) -> list[int]:
        return self._by_cwe.get(cwe, []) if cwe is not None else []

    def indices_for_rule(self, rule_id: str | None) -> list[int]:
        return self._by_rule.get(rule_id, []) if rule_id else []
