"""Load security documents (CWE, OWASP Cheat Sheets, Bandit docs) into a common `Document` form."""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Document:
    doc_id: str
    kind: str            # "cwe" | "owasp" | "bandit"
    title: str
    url: str
    publisher: str
    license: str
    text: str
    cwe_ids: list[int] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def load_cwe(xml_bytes: bytes, meta: dict) -> list[Document]:
    """One document per CWE weakness: description, consequences and mitigations."""
    root = ET.fromstring(xml_bytes)
    ns = {"c": root.tag.split("}")[0].strip("{")}
    docs = []
    for w in root.iterfind(".//c:Weaknesses/c:Weakness", ns):
        if w.get("Status") == "Deprecated":
            continue
        cwe_id = int(w.get("ID"))
        parts = [f"CWE-{cwe_id}: {w.get('Name')}."]
        desc = w.find("c:Description", ns)
        if desc is not None:
            parts.append(_clean("".join(desc.itertext())))
        ext = w.find("c:Extended_Description", ns)
        if ext is not None:
            parts.append(_clean(" ".join(ext.itertext())))
        consequences = [
            _clean(" ".join(c.itertext()))
            for c in w.iterfind("c:Common_Consequences/c:Consequence", ns)
        ]
        if consequences:
            parts.append("## Common consequences\n" + "\n".join(f"- {c}" for c in consequences[:6]))
        mitigations = []
        for m in w.iterfind("c:Potential_Mitigations/c:Mitigation", ns):
            phase = ", ".join(_clean(p.text) for p in m.iterfind("c:Phase", ns))
            body = _clean(" ".join(d for d in m.find("c:Description", ns).itertext())) if m.find("c:Description", ns) is not None else ""
            if body:
                mitigations.append(f"- ({phase}) {body}" if phase else f"- {body}")
        if mitigations:
            parts.append("## Potential mitigations\n" + "\n".join(mitigations[:8]))
        docs.append(Document(
            doc_id=f"cwe-{cwe_id}", kind="cwe", title=f"CWE-{cwe_id}: {w.get('Name')}",
            url=meta["page_url"].format(id=cwe_id), publisher=meta["publisher"], license=meta["license"],
            text="\n\n".join(parts), cwe_ids=[cwe_id],
        ))
    return docs


def load_owasp(name: str, markdown: str, cwe_ids: list[int], meta: dict) -> Document:
    title = name.replace("_", " ")
    first = re.search(r"^#\s+(.+)$", markdown, re.MULTILINE)
    if first:
        title = first.group(1).strip()
    return Document(
        doc_id=f"owasp-{name}", kind="owasp", title=f"OWASP {title}",
        url=meta["page_url"].format(name=name), publisher=meta["publisher"], license=meta["license"],
        text=markdown, cwe_ids=list(cwe_ids),
    )


def _rst_to_text(text: str) -> str:
    text = re.sub(r"^[=\-~^]{3,}\s*$", "", text, flags=re.MULTILINE)       # underline rows
    text = re.sub(r"^\+[-=+]+\+\s*$", "", text, flags=re.MULTILINE)          # table borders
    text = re.sub(r"^\.\. (code-block|seealso|versionadded|versionchanged)::.*$", "", text, flags=re.MULTILINE)
    text = text.replace("**", "").replace("``", "`")
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def load_bandit(meta: dict) -> list[Document]:
    """Bandit's own documentation, read from the installed package (plugins and blacklists)."""
    from bandit.core import extension_loader
    import bandit.blacklists.calls as bl_calls
    import bandit.blacklists.imports as bl_imports
    from codeguard.scanner.rules import CWE_OVERRIDES

    docs = []
    import sys

    for ext in extension_loader.MANAGER.plugins:
        func = ext.plugin
        rule_id = getattr(func, "_test_id", None)
        # Most plugins document themselves in the module docstring, some on the function.
        doc = func.__doc__ or getattr(sys.modules.get(func.__module__), "__doc__", None)
        if not rule_id or not doc:
            continue
        docs.append(Document(
            doc_id=f"bandit-{rule_id}", kind="bandit", title=f"Bandit {rule_id}: {ext.name}",
            url=f"{meta['page_url']}plugins/{rule_id.lower()}_{ext.name}.html",
            publisher=meta["publisher"], license=meta["license"],
            text=_rst_to_text(doc), rule_ids=[rule_id],
            cwe_ids=[CWE_OVERRIDES[rule_id]] if rule_id in CWE_OVERRIDES else [],
        ))
    for module, page in ((bl_calls, "blacklists/blacklist_calls.html"), (bl_imports, "blacklists/blacklist_imports.html")):
        sections = re.split(r"\n(?=B\d{3}: )", module.__doc__ or "")
        for section in sections:
            match = re.match(r"(B\d{3}): (.+)", section)
            if not match:
                continue
            rule_id = match.group(1)
            docs.append(Document(
                doc_id=f"bandit-{rule_id}", kind="bandit", title=f"Bandit {rule_id}: {match.group(2).strip()}",
                url=f"{meta['page_url']}{page}", publisher=meta["publisher"], license=meta["license"],
                text=_rst_to_text(section), rule_ids=[rule_id],
                cwe_ids=[CWE_OVERRIDES[rule_id]] if rule_id in CWE_OVERRIDES else [],
            ))
    return docs


def read_local(path: Path) -> str:
    return path.read_text(encoding="utf-8")
