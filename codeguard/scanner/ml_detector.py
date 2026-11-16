"""Scores Python functions with the trained ML model (built in experiments/05).

The code is split into units with `ast`, which parses text and never executes it. Each function
(or method) is one unit; code outside any function is one `<module>` unit.
"""
import ast
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import joblib

from codeguard.config import settings


@dataclass
class CodeUnit:
    name: str
    start_line: int
    end_line: int
    source: str
    # The exact lines a unit covers when it is not one contiguous block (the `<module>` unit).
    lines: frozenset[int] | None = None

    def contains(self, line: int) -> bool:
        if self.lines is not None:
            return line in self.lines
        return self.start_line <= line <= self.end_line


@dataclass
class UnitScore:
    unit: CodeUnit
    score: float
    flagged: bool


class ModelUnavailable(RuntimeError):
    """No trained Python model has been saved yet."""


def extract_units(source: str, min_lines: int | None = None) -> list[CodeUnit]:
    """Split source into outermost functions plus the remaining module-level code.

    Raises SyntaxError if the source is not valid Python.
    """
    min_lines = settings.ml_min_lines if min_lines is None else min_lines
    tree = ast.parse(source)
    lines = source.splitlines()
    units: list[CodeUnit] = []
    covered: set[int] = set()

    def visit(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                end = child.end_lineno or child.lineno
                units.append(CodeUnit(f"{prefix}{child.name}", start, end,
                                      "\n".join(lines[start - 1:end])))
                covered.update(range(start, end + 1))
                # Nested functions stay part of their parent unit.
            elif isinstance(child, ast.ClassDef):
                visit(child, prefix=f"{prefix}{child.name}.")

    visit(tree)

    module_lines = [(i, text) for i, text in enumerate(lines, start=1)
                    if i not in covered and text.strip() and not text.strip().startswith("#")]
    if module_lines:
        units.append(CodeUnit("<module>", module_lines[0][0], module_lines[-1][0],
                              "\n".join(text for _, text in module_lines),
                              lines=frozenset(i for i, _ in module_lines)))

    return [u for u in units
            if sum(1 for t in u.source.splitlines() if t.strip()) >= min_lines]


@lru_cache(maxsize=1)
def load_model(model_path: Path | None = None, card_path: Path | None = None):
    model_path = model_path or settings.model_path
    card_path = card_path or settings.model_card_path
    if not model_path.exists():
        raise ModelUnavailable(
            "No Python model found at artifacts/model/python_vuln_model.joblib. "
            "Run experiments/05_python_model_training_evaluation.ipynb to create it."
        )
    model = joblib.load(model_path)
    card = json.loads(card_path.read_text(encoding="utf-8")) if card_path.exists() else {}
    return model, card


def model_card() -> dict | None:
    try:
        return load_model()[1]
    except ModelUnavailable:
        return None


def score_units(units: list[CodeUnit], model=None, threshold: float | None = None) -> list[UnitScore]:
    if not units:
        return []
    if model is None:
        model, card = load_model()
        threshold = card.get("threshold", 0.5) if threshold is None else threshold
    threshold = 0.5 if threshold is None else threshold
    scores = model.predict_proba([u.source for u in units])[:, 1]
    return [UnitScore(u, round(float(s), 4), bool(s >= threshold)) for u, s in zip(units, scores)]
