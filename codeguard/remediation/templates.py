"""Deterministic, rule-based fixes for well-understood Bandit findings.

Each template rewrites only the reported line(s) and may add an import. They are *candidates*: every
patch still goes through the fix validator, and some carry a caveat because they can change behaviour.
"""
import re
from dataclasses import dataclass


@dataclass
class TemplateFix:
    rule_id: str
    description: str
    caveat: str
    pattern: re.Pattern
    replacement: object  # str template or callable(match) -> str
    needs_import: str | None = None


TEMPLATES: dict[str, TemplateFix] = {t.rule_id: t for t in [
    TemplateFix("B307", "Replace eval() with ast.literal_eval(), which only accepts Python literals.",
                "literal_eval rejects expressions such as 2+3*x; if the code needs those, parse them explicitly.",
                re.compile(r"(?<![\w.])eval\("), "ast.literal_eval(", needs_import="ast"),
    TemplateFix("B506", "Use yaml.safe_load(), which cannot construct arbitrary Python objects.",
                "Custom YAML tags that relied on the full loader will no longer load.",
                re.compile(r"yaml\.load\(\s*([^,()]+?)\s*(?:,\s*Loader\s*=\s*[\w.]+\s*)?\)"), r"yaml.safe_load(\1)"),
    TemplateFix("B324", "Replace MD5/SHA-1 with SHA-256.",
                "Stored hashes made with the old algorithm will no longer match. For passwords use a "
                "password hash (bcrypt, scrypt, argon2) instead of any plain hash.",
                re.compile(r"hashlib\.(md5|sha1)\("), "hashlib.sha256("),
    TemplateFix("B501", "Re-enable TLS certificate verification.",
                "Requests to servers with self-signed certificates will now fail until the CA is trusted.",
                re.compile(r"verify\s*=\s*False"), "verify=True"),
    TemplateFix("B602", "Run the command without a shell: split it into an argument list and set shell=False.",
                "Splitting a string built from user input still lets the user add extra arguments; prefer "
                "building the list explicitly and validating each value.",
                re.compile(r"(subprocess\.\w+\()\s*([^,]+?)\s*,(.*?)shell\s*=\s*True", re.DOTALL),
                r"\1shlex.split(\2),\3shell=False", needs_import="shlex"),
    TemplateFix("B105", "Read the secret from an environment variable instead of the source code.",
                "The environment variable must be set wherever the code runs.",
                re.compile(r"^([ \t]*)(\w+)[ \t]*=[ \t]*(['\"]).*?\3[ \t]*$", re.MULTILINE),
                lambda m: f'{m.group(1)}{m.group(2)} = os.environ["{m.group(2).upper()}"]',
                needs_import="os"),
]}


def apply_template(source: str, rule_id: str, line: int, end_line: int | None = None) -> tuple[str, TemplateFix] | None:
    """Return (patched_source, template) or None if no template applies to this finding."""
    template = TEMPLATES.get(rule_id)
    if template is None:
        return None
    lines = source.splitlines(keepends=True)
    first, last = line - 1, (end_line or line) - 1
    # Bandit may report the line of an argument (shell=True) rather than the start of the call, so widen
    # the region to the whole statement that contains the finding.
    try:
        from codeguard.remediation.patcher import innermost_statement
        start, end = innermost_statement(source, line)
        first, last = min(first, start - 1), max(last, end - 1)
    except (SyntaxError, ValueError):
        pass
    region = "".join(lines[first:last + 1])
    patched_region, count = template.pattern.subn(template.replacement, region, count=1)
    if count == 0:
        return None
    patched = "".join(lines[:first]) + patched_region + "".join(lines[last + 1:])
    if template.needs_import:
        patched = ensure_import(patched, template.needs_import)
    return patched, template


def ensure_import(source: str, module: str) -> str:
    if re.search(rf"^\s*import\s+([\w, ]*\b)?{re.escape(module)}\b", source, re.MULTILINE):
        return source
    lines = source.splitlines(keepends=True)
    # Insert after the module docstring / __future__ imports / leading comments.
    insert_at = 0
    for i, text in enumerate(lines):
        stripped = text.strip()
        if stripped.startswith(("import ", "from ")):
            insert_at = i + 1
    if insert_at == 0:
        while insert_at < len(lines) and (lines[insert_at].lstrip().startswith("#") or not lines[insert_at].strip()):
            insert_at += 1
    return "".join(lines[:insert_at]) + f"import {module}\n" + "".join(lines[insert_at:])
