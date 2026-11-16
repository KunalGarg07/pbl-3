"""Split documents into heading-aware chunks of roughly `max_chars` characters."""
import re
from dataclasses import dataclass, field

from codeguard.rag.sources import Document


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    kind: str
    title: str
    section: str
    url: str
    publisher: str
    license: str
    text: str
    cwe_ids: list[int] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


HEADING = re.compile(r"^(#{1,4})\s+(.+?)\s*#*\s*$", re.MULTILINE)


def _sections(text: str) -> list[tuple[str, str]]:
    """Split markdown into (heading path, body) pairs."""
    matches = list(HEADING.finditer(text))
    if not matches:
        return [("", text)]
    out = []
    if matches[0].start() > 0 and text[:matches[0].start()].strip():
        out.append(("", text[:matches[0].start()]))
    path: list[str] = []
    for i, m in enumerate(matches):
        level = len(m.group(1))
        path = path[:level - 1] + [m.group(2).strip()]
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[m.end():end].strip()
        if body:
            out.append((" > ".join(path[1:] or path), body))
    return out


def _split_long(body: str, max_chars: int) -> list[str]:
    if len(body) <= max_chars:
        return [body]
    pieces, current = [], ""
    for para in re.split(r"\n\s*\n", body):
        if len(current) + len(para) + 2 > max_chars and current:
            pieces.append(current.strip())
            current = ""
        while len(para) > max_chars:  # very long paragraph or code block
            pieces.append(para[:max_chars])
            para = para[max_chars:]
        current += para + "\n\n"
    if current.strip():
        pieces.append(current.strip())
    return pieces


# Sections that list links or credits rather than guidance.
SKIP_SECTION = re.compile(r"\b(references?|further reading|related (articles|cheat ?sheets)|authors?|"
                          r"contributors|table of contents)\b", re.IGNORECASE)


def chunk_document(doc: Document, max_chars: int = 1500, min_chars: int = 80) -> list[Chunk]:
    chunks = []
    # Merge very small sections into the next one so chunks carry enough context.
    carry_heading, carry = "", ""
    for heading, body in _sections(doc.text):
        if heading and SKIP_SECTION.search(heading.split(" > ")[-1]):
            continue
        if len(carry) + len(body) < min_chars:
            carry_heading, carry = carry_heading or heading, (carry + "\n\n" + body).strip()
            continue
        if carry:
            body, heading = carry + "\n\n" + body, heading or carry_heading
            carry_heading, carry = "", ""
        for piece in _split_long(body, max_chars):
            chunks.append(Chunk(
                chunk_id=f"{doc.doc_id}#{len(chunks)}", doc_id=doc.doc_id, kind=doc.kind, title=doc.title,
                section=heading, url=doc.url, publisher=doc.publisher, license=doc.license,
                text=piece, cwe_ids=doc.cwe_ids, rule_ids=doc.rule_ids,
            ))
    if carry:
        chunks.append(Chunk(f"{doc.doc_id}#{len(chunks)}", doc.doc_id, doc.kind, doc.title, carry_heading,
                            doc.url, doc.publisher, doc.license, carry, doc.cwe_ids, doc.rule_ids))
    return chunks
