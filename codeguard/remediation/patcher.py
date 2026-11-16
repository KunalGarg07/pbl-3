"""Apply a code fix to a source file and produce a readable diff."""
import ast
import difflib
import textwrap


class PatchError(ValueError):
    """The proposed fix cannot be applied to the source."""


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def innermost_statement(source: str, line: int) -> tuple[int, int]:
    """Line range of the smallest simple statement that contains `line`."""
    tree = ast.parse(source)
    best = None
    for node in ast.walk(tree):
        if isinstance(node, ast.stmt) and not isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.While,
                       ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)):
            end = node.end_lineno or node.lineno
            if node.lineno <= line <= end and (best is None or end - node.lineno < best[1] - best[0]):
                best = (node.lineno, end)
    if best is None:
        raise PatchError(f"No statement found at line {line}")
    return best


def apply_llm_fix(source: str, fix_code: str, region_start: int, region_end: int, line: int) -> str:
    """Replace the function region if the fix is a whole function, otherwise the statement at `line`."""
    fix = textwrap.dedent(fix_code.strip("\n"))
    if not fix.strip():
        raise PatchError("The model did not propose any code")
    try:
        fix_tree = ast.parse(fix)
    except SyntaxError as exc:
        raise PatchError(f"The proposed code is not valid Python (line {exc.lineno}: {exc.msg})") from exc

    lines = source.splitlines(keepends=True)
    is_function = any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in fix_tree.body)
    if is_function:
        start, end = region_start, region_end
    else:
        start, end = innermost_statement(source, line)
    indent = _indent_of(lines[start - 1])
    new_block = textwrap.indent(fix, indent, lambda _: True).rstrip("\n") + "\n"
    new_block = "\n".join(l if l.strip() else "" for l in new_block.split("\n"))
    return "".join(lines[:start - 1]) + new_block + "".join(lines[end:])


def unified_diff(before: str, after: str, filename: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{filename}", tofile=f"b/{filename}", n=3,
    ))
