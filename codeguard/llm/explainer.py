"""Grounded explanations for existing findings (week 8).

The explainer never creates findings. It receives one finding plus the source code, retrieves security
guidance, and asks the LLM for a structured explanation and a candidate fix. If no LLM is available it
returns a retrieval-only explanation built from the rule metadata and the retrieved passages.
"""
import hashlib
import time
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationError

from codeguard.llm import prompts
from codeguard.llm.client import LLMUnavailable, get_client, parse_json_object
from codeguard.rag import retriever
from codeguard.scanner import ml_detector
from codeguard.schemas import Finding


class Explanation(BaseModel):
    summary: str
    why_dangerous: str = ""
    exploit_conditions: str = ""
    fix_code: str = ""
    fix_explanation: str = ""
    citations: list[str] = Field(default_factory=list)
    caveats: str = ""
    insufficient_evidence: bool = False


class SourceRef(BaseModel):
    id: str
    title: str
    section: str
    url: str
    publisher: str
    score: float


class ExplanationResult(BaseModel):
    mode: Literal["llm", "retrieval_only"]
    explanation: Explanation
    sources: list[SourceRef]
    region_start: int
    region_end: int
    provider: Optional[str] = None
    model: Optional[str] = None
    seconds: float = 0.0
    invalid_citations: list[str] = Field(default_factory=list)
    note: Optional[str] = None
    cached: bool = False


def code_region(source: str, line: int) -> tuple[int, int, str]:
    """The function containing `line`, or a window of lines around it for module-level code."""
    lines = source.splitlines()
    try:
        for unit in ml_detector.extract_units(source, min_lines=1):
            if unit.name != "<module>" and unit.start_line <= line <= unit.end_line:
                return unit.start_line, unit.end_line, "\n".join(lines[unit.start_line - 1:unit.end_line])
    except SyntaxError:
        pass
    start, end = max(1, line - 6), min(len(lines), line + 6)
    return start, end, "\n".join(lines[start - 1:end])


def cache_key(finding: Finding, region: str, model: str, kb_built: str) -> str:
    raw = "|".join([finding.rule_id, finding.evidence, region, model, kb_built, retriever.RETRIEVAL_VERSION])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sources(passages) -> list[SourceRef]:
    return [SourceRef(id=f"S{i}", title=p.chunk.title, section=p.chunk.section, url=p.chunk.url,
                      publisher=p.chunk.publisher, score=round(p.score, 3))
            for i, p in enumerate(passages, start=1)]


def retrieval_only(finding: Finding, passages, start: int, end: int, note: str) -> ExplanationResult:
    expl = Explanation(
        summary=finding.evidence,
        why_dangerous=f"{finding.category} ({'CWE-' + str(finding.cwe) if finding.cwe else 'no CWE'}). "
                      "See the cited guidance below for how this weakness is exploited.",
        exploit_conditions="Depends on whether untrusted input can reach this code; not analysed in this mode.",
        fix_code="",
        fix_explanation=finding.recommendation or "",
        citations=[f"S{i}" for i in range(1, len(passages) + 1)],
        caveats="No language model was used. This is the analyzer's message plus retrieved guidance.",
    )
    return ExplanationResult(mode="retrieval_only", explanation=expl, sources=_sources(passages),
                             region_start=start, region_end=end, note=note)


def explain(finding: Finding, source: str, *, k: int = 4, store=None, client=None,
            cache=None) -> ExplanationResult:
    """Explain one finding. `cache` is an object with get_explanation/save_explanation (ScanStore)."""
    start, end, region = code_region(source, finding.line)
    passages = retriever.retrieve(finding, k=k)
    try:
        client = client or get_client()
    except LLMUnavailable as exc:
        return retrieval_only(finding, passages, start, end, note=str(exc))

    kb_built = retriever.load_store().info.get("built", "")
    key = cache_key(finding, region, f"{client.provider}:{client.model}", kb_built)
    if cache is not None:
        hit = cache.get_explanation(key)
        if hit:
            result = ExplanationResult.model_validate_json(hit)
            result.cached = True
            return result

    prompt = prompts.build_prompt(finding, region, start, end, passages)
    started, last_error = time.time(), None
    for _ in range(2):  # one retry if the reply is not valid JSON
        try:
            reply = client.generate_json(prompts.SYSTEM, prompt)
            expl = Explanation.model_validate(parse_json_object(reply.text))
            break
        except LLMUnavailable as exc:
            return retrieval_only(finding, passages, start, end, note=str(exc))
        except (ValueError, ValidationError) as exc:
            last_error = exc
    else:
        return retrieval_only(finding, passages, start, end,
                              note=f"The model's reply could not be parsed ({type(last_error).__name__}).")

    valid_ids = {f"S{i}" for i in range(1, len(passages) + 1)}
    cited = [c.strip() for c in expl.citations if isinstance(c, str)]
    invalid = [c for c in cited if c not in valid_ids]
    expl.citations = [c for c in cited if c in valid_ids]
    result = ExplanationResult(
        mode="llm", explanation=expl, sources=_sources(passages), region_start=start, region_end=end,
        provider=client.provider, model=client.model, seconds=round(time.time() - started, 1),
        invalid_citations=invalid,
    )
    if cache is not None:
        cache.save_explanation(key, result.model_dump_json())
    return result
