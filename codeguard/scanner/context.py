"""Context analysis for findings (week 10): does user input reach the flagged call? Is it test code?

This is a deliberately simple, intra-function data-flow check on the AST (the code is parsed, never run):
- "direct":    a value from input(), sys.argv, os.environ/os.getenv or a web request object flows,
               through assignments in the same function, into the flagged statement;
- "parameter": a function parameter flows into it (untrusted only if callers pass untrusted data);
- "none":      only constants or local values reach it;
- None:        not analysed (the rule does not depend on input, e.g. weak hash, hard-coded password).
It does not follow calls between functions or files, so it can miss flows (see Documents/Limitations.docx).
"""
import ast
import re
from pathlib import PurePosixPath

from codeguard.schemas import Finding

# Rules whose risk depends on attacker-controlled data reaching the call.
INPUT_RELEVANT = {
    "B102", "B307", "B301", "B302", "B506", "B310", "B308", "B701", "B703",
    "B601", "B602", "B603", "B604", "B605", "B606", "B607", "B608", "B609", "B610", "B611",
    *{f"B{n}" for n in range(313, 321)},
}
REQUEST_NAMES = re.compile(r"(^|_)request$|^req$|^flask_request$")
REQUEST_ATTRS = {"args", "form", "values", "json", "data", "files", "cookies", "headers", "GET", "POST",
                 "body", "query_params", "path_params", "get_json", "getvalue", "query"}
TEST_PATH = re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]*\.py$|_tests?\.py$|(^|/)conftest\.py$")


def is_test_path(path: str) -> bool:
    return bool(TEST_PATH.search(PurePosixPath(path.replace("\\", "/")).as_posix()))


def _root_name(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else None


def _is_direct_source(node: ast.AST) -> bool:
    """True if this expression node itself reads user-controlled input."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id in {"input", "raw_input"}:
            return True
        if isinstance(func, ast.Attribute):
            if func.attr == "getenv" and _root_name(func) == "os":
                return True
            if func.attr in REQUEST_ATTRS | {"get", "getlist"} and REQUEST_NAMES.search(_root_name(func) or ""):
                return True
            if func.attr == "getvalue":  # cgi.FieldStorage().getvalue(...)
                return True
    if isinstance(node, ast.Attribute):
        root = _root_name(node)
        if root == "sys" and node.attr == "argv":
            return True
        if root == "os" and node.attr == "environ":
            return True
        if node.attr in REQUEST_ATTRS and REQUEST_NAMES.search(root or ""):
            return True
    return False


def _taint_level(expr: ast.AST, direct: set[str], params: set[str]) -> str:
    level = "none"
    for node in ast.walk(expr):
        if _is_direct_source(node):
            return "direct"
        if isinstance(node, ast.Name):
            if node.id in direct:
                return "direct"
            if node.id in params:
                level = "parameter"
    return level


def _targets(target: ast.AST) -> list[str]:
    return [n.id for n in ast.walk(target) if isinstance(n, ast.Name)]


def _propagate(scope: ast.AST, params: set[str]) -> tuple[set[str], set[str]]:
    """Names that hold direct user input / parameter-derived values within one function."""
    direct, from_params = set(), set(params)
    assigns = sorted((n for n in ast.walk(scope) if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign,
                                                                     ast.For, ast.With, ast.NamedExpr))),
                     key=lambda n: (n.lineno, n.col_offset))
    for _ in range(2):  # second pass catches values used in loops before their textual assignment
        for node in assigns:
            if isinstance(node, ast.For):
                value, targets = node.iter, _targets(node.target)
            elif isinstance(node, ast.With):
                for item in node.items:
                    if item.optional_vars is not None:
                        level = _taint_level(item.context_expr, direct, from_params)
                        (direct if level == "direct" else from_params if level == "parameter" else set()).update(
                            _targets(item.optional_vars))
                continue
            elif isinstance(node, ast.NamedExpr):
                value, targets = node.value, _targets(node.target)
            else:
                value = node.value
                if value is None:
                    continue
                targets = [t for tgt in (node.targets if isinstance(node, ast.Assign) else [node.target])
                           for t in _targets(tgt)]
            level = _taint_level(value, direct, from_params)
            if level == "direct":
                direct.update(targets)
            elif level == "parameter":
                from_params.update(targets)
    return direct, from_params


def _innermost_function(tree: ast.AST, line: int):
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = node.end_lineno or node.lineno
            if node.lineno <= line <= end and (best is None or node.lineno >= best.lineno):
                best = node
    return best


def _statement_at(scope: ast.AST, line: int):
    best = None
    for node in ast.walk(scope):
        if isinstance(node, ast.stmt) and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            end = node.end_lineno or node.lineno
            if node.lineno <= line <= end and (best is None or end - node.lineno <= (best.end_lineno or best.lineno) - best.lineno):
                best = node
    return best


def annotate(source: str, findings: list[Finding], path: str) -> list[Finding]:
    """Set `user_input` and `in_test_code` on each finding (in place)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return findings
    test_file = is_test_path(path)
    for f in findings:
        func = _innermost_function(tree, f.line)
        f.in_test_code = test_file or bool(func and func.name.startswith("test"))
        if f.rule_id not in INPUT_RELEVANT:
            continue
        scope = func or tree
        params = set()
        if func is not None:
            args = func.args
            params = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs} - {"self", "cls"}
            params |= {a.arg for a in (args.vararg, args.kwarg) if a is not None}
        direct, from_params = _propagate(scope, params)
        stmt = _statement_at(scope, f.line)
        f.user_input = _taint_level(stmt, direct, from_params) if stmt is not None else None
    return findings
