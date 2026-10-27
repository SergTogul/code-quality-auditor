"""Language discovery and adapters. New languages register an adapter; they do not fork the skill."""

from __future__ import annotations

import ast
import hashlib
import os
import re
import tokenize
from io import BytesIO
from pathlib import Path

from cqa import ENGINE_VERSION

EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".h": "cpp",
}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "coverage",
}
ENTRY_DECORATORS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
    "head",
    "task",
    "command",
    "cli",
    "cron",
    "schedule",
    "job",
    "periodic_task",
    "api_view",
    "app.route",
    "router.get",
    "router.post",
}
BUILTIN_NAMES = set(dir(__builtins__)) if isinstance(__builtins__, dict) else set(dir(__builtins__))
MAX_BYTES = 1_000_000


def language_of(path):
    suffix = Path(path).suffix.lower()
    if suffix in EXTENSIONS:
        return EXTENSIONS[suffix]
    for adapter in ADAPTERS:
        if suffix in adapter.extensions:
            return adapter.language
    return None


def discover(root, languages=None, directories=None):
    """Return ``(files, language_counts)`` without executing repository code."""
    root = Path(root).resolve()
    selected = set(languages or [])
    prefixes = None
    if directories:
        prefixes = []
        for directory in directories:
            candidate = Path(directory)
            if not candidate.is_absolute():
                candidate = root / candidate
            prefixes.append(candidate.resolve())
    files = []
    counts = {}
    if not root.exists():
        return files, counts
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS and name != ".venv")
        current = Path(dirpath)
        if prefixes and not any(current == prefix or prefix in current.parents or current in prefix.parents for prefix in prefixes):
            continue
        for name in sorted(filenames):
            path = current / name
            if prefixes and not any(path == prefix or prefix in path.parents for prefix in prefixes):
                continue
            language = language_of(path)
            if language is None:
                continue
            if selected and language not in selected:
                continue
            files.append(path)
            counts[language] = counts.get(language, 0) + 1
    return files, counts


def _read(path):
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return None, f"unreadable: {exc}"
    if len(raw) > MAX_BYTES:
        return None, "file exceeds the static size limit"
    if b"\0" in raw[:1024]:
        return None, "binary file"
    return raw.decode("utf-8", errors="replace"), None


def _rel(root, path):
    path = Path(path).resolve()
    try:
        return path.relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _blank_analysis(path, language, line_count, limit=None):
    return {
        "path": path,
        "language": language,
        "line_count": line_count,
        "syntax_errors": [],
        "symbols": [],
        "imports": [],
        "module_refs": [],
        "attr_refs": [],
        "entries": [],
        "routes": [],
        "entry_module": False,
        "dynamic": [],
        "unresolved": [],
        "dead_branches": [],
        "handlers": [],
        "calls": [],
        "limits": [limit] if limit else [],
        "normalized_lines": [],
        "tokens": [],
        "structures": [],
        "style": {"long_lines": 0, "mixed_indent": 0, "indent_kind": None},
        "comments": [],
        "text_hash": "",
        "skipped": bool(limit),
    }


def _quote_kind(text):
    single = double = 0
    index = 0
    limit = len(text)
    while index < limit:
        ch = text[index]
        if ch == "#" or (ch == "/" and index + 1 < limit and text[index + 1] == "/"):
            end = text.find("\n", index)
            index = limit if end < 0 else end
            continue
        if ch == "/" and index + 1 < limit and text[index + 1] == "*":
            end = text.find("*/", index + 2)
            index = limit if end < 0 else end + 2
            continue
        if ch in {"'", '"'}:
            if ch == "'":
                single += 1
            else:
                double += 1
            quote = ch
            index += 1
            while index < limit and text[index] not in {quote, "\n"}:
                if text[index] == "\\":
                    index += 2
                    continue
                index += 1
            index += 1
            continue
        index += 1
    if single == 0 and double == 0:
        return None
    return "double" if double >= single else "single"


def _style(text):
    long_lines = 0
    mixed = 0
    indents = []
    trailing = False
    for line in text.splitlines():
        if len(line) > 120:
            long_lines += 1
        if line.rstrip(" \t") != line:
            trailing = True
        stripped = line.lstrip(" \t")
        prefix = line[: len(line) - len(stripped)]
        if prefix:
            if "\t" in prefix and " " in prefix:
                mixed += 1
            indents.append("tab" if "\t" in prefix else "space")
    kind = None
    if indents:
        kind = "tab" if indents.count("tab") >= indents.count("space") else "space"
    return {
        "long_lines": long_lines,
        "mixed_indent": mixed,
        "indent_kind": kind,
        "quote_kind": _quote_kind(text),
        "trailing": "trailing" if trailing else "clean",
    }


def _normalized(text):
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        lines.append(" ".join(stripped.split()))
    return lines


def _decorator_name(node):
    current = node
    while isinstance(current, ast.Call):
        current = current.func
    if isinstance(current, ast.Name):
        return current.id
    if isinstance(current, ast.Attribute):
        parts = []
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def _const_bool(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _complexity(node):
    score = 1
    for child in ast.walk(node):
        if child is node:
            continue
        if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += max(0, len(child.values) - 1)
        elif isinstance(child, ast.Match):
            score += max(1, len(child.cases))
    return score


def _nesting(node):
    peak = 0

    def walk(current, depth):
        nonlocal peak
        peak = max(peak, depth)
        for child in ast.iter_child_nodes(current):
            next_depth = depth
            if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)):
                next_depth += 1
            walk(child, next_depth)

    walk(node, 0)
    return peak


def _python(path, text):
    analysis = _blank_analysis(path, "python", text.count("\n") + 1 if text else 0)
    analysis["style"] = _style(text)
    analysis["normalized_lines"] = _normalized(text)
    analysis["text_hash"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    analysis["comments"] = [line.strip() for line in text.splitlines() if line.strip().startswith("#")]
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        analysis["syntax_errors"].append({"line": exc.lineno or 1, "message": exc.msg})
        analysis["limits"].append("syntax error stopped symbol extraction")
        return analysis
    try:
        tokens = tokenize.tokenize(BytesIO(text.encode("utf-8")).readline)
        names = []
        lines = []
        for token in tokens:
            if token.type == tokenize.NAME:
                names.append(token.string)
                lines.append(token.start[0])
            elif token.type == tokenize.NUMBER:
                names.append(token.string)
                lines.append(token.start[0])
            elif token.type == tokenize.OP:
                names.append(token.string)
                lines.append(token.start[0])
        analysis["tokens"] = names
        analysis["token_lines"] = lines
    except tokenize.TokenError as exc:
        analysis["syntax_errors"].append({"line": 1, "message": str(exc)})

    class Index(ast.NodeVisitor):
        def __init__(self):
            self.scope = []
            self.class_stack = []
            self.loop_depth = 0

        def _add_symbol(self, node, kind):
            name = node.name
            qual = ".".join([*(self.class_stack), name]) if kind == "method" else name
            decorators = [_decorator_name(item) for item in node.decorator_list]
            symbol = {
                "id": f"{path}::{kind}::{qual}::{node.lineno}",
                "kind": kind,
                "name": name,
                "qualified": qual,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
                "params": len(getattr(getattr(node, "args", None), "args", []) or []),
                "complexity": _complexity(node),
                "cognitive": _complexity(node) + _nesting(node),
                "nesting": _nesting(node),
                "exported": not name.startswith("_"),
                "decorators": [item for item in decorators if item],
                "doc": bool(ast.get_docstring(node)),
                "refs": [],
                "attr_refs": [],
                "private": name.startswith("_") and not name.startswith("__"),
                "parent": self.class_stack[-1] if self.class_stack else None,
            }
            analysis["symbols"].append(symbol)
            for decorator in symbol["decorators"]:
                leaf = decorator.split(".")[-1]
                if leaf in ENTRY_DECORATORS or decorator in ENTRY_DECORATORS:
                    analysis["entries"].append(
                        {"symbol": name, "kind": "framework", "reason": f"decorator {decorator}", "line": node.lineno}
                    )
                elif decorator and decorator not in {"staticmethod", "classmethod", "property", "abstractmethod"}:
                    analysis["dynamic"].append(
                        {"line": node.lineno, "kind": "unknown_decorator", "detail": decorator, "symbol": name}
                    )
            if name == "main" or name.startswith("test_") or name.startswith("Test"):
                analysis["entries"].append({"symbol": name, "kind": "convention", "reason": name, "line": node.lineno})
            types = []
            local_tokens = []

            class Shape(ast.NodeVisitor):
                def generic_visit(self, child):
                    types.append(type(child).__name__)
                    if isinstance(child, ast.Name):
                        local_tokens.append(child.id)
                    self.generic_visit_children(child)

                def generic_visit_children(self, child):
                    for item in ast.iter_child_nodes(child):
                        self.visit(item)

            Shape().visit(node)
            analysis["structures"].append(
                {
                    "name": qual,
                    "hash": hashlib.sha256("".join(types).encode("utf-8")).hexdigest(),
                    "size": len(types),
                    "tokens": local_tokens[:80],
                }
            )
            self.scope.append(symbol)
            if kind == "class":
                self.class_stack.append(name)
            self.generic_visit(node)
            if kind == "class":
                self.class_stack.pop()
            self.scope.pop()

        def visit_FunctionDef(self, node):
            self._add_symbol(node, "method" if self.class_stack else "function")

        def visit_AsyncFunctionDef(self, node):
            self._add_symbol(node, "method" if self.class_stack else "function")

        def visit_ClassDef(self, node):
            self._add_symbol(node, "class")

        def visit_Import(self, node):
            for alias in node.names:
                analysis["imports"].append(
                    {
                        "line": node.lineno,
                        "module": alias.name,
                        "bindings": [{"local": alias.asname or alias.name.split(".")[0], "remote": "*"}],
                        "resolved": None,
                        "unresolved": False,
                    }
                )

        def visit_ImportFrom(self, node):
            module = node.module or ""
            bindings = []
            for alias in node.names:
                bindings.append({"local": alias.asname or alias.name, "remote": alias.name})
            analysis["imports"].append(
                {
                    "line": node.lineno,
                    "module": ("." * node.level) + module,
                    "bindings": bindings,
                    "resolved": None,
                    "unresolved": False,
                    "level": node.level,
                }
            )

        def visit_Assign(self, node):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__" and isinstance(node.value, (ast.List, ast.Tuple)):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            analysis["entries"].append(
                                {"symbol": elt.value, "kind": "export", "reason": "__all__", "line": node.lineno}
                            )
            self.generic_visit(node)

        def visit_If(self, node):
            test = node.test
            if (
                isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
                and any(isinstance(item, ast.Constant) and item.value == "__main__" for item in test.comparators)
            ):
                analysis["entry_module"] = True
                analysis["entries"].append({"symbol": "<module>", "kind": "main", "reason": "__main__ guard", "line": node.lineno})
            value = _const_bool(test)
            if value is False:
                analysis["dead_branches"].append({"line": node.lineno, "message": "constant false branch"})
            elif value is True and node.orelse:
                analysis["dead_branches"].append({"line": node.orelse[0].lineno, "message": "constant true branch makes else unreachable"})
            self.generic_visit(node)

        def visit_For(self, node):
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

        def visit_While(self, node):
            self.loop_depth += 1
            self.generic_visit(node)
            self.loop_depth -= 1

        def visit_ExceptHandler(self, node):
            empty = False
            if len(node.body) == 1:
                statement = node.body[0]
                ellipsis = isinstance(statement, ast.Expr) and isinstance(getattr(statement, "value", None), ast.Constant) and statement.value.value is Ellipsis
                empty = isinstance(statement, ast.Pass) or ellipsis
            analysis["handlers"].append({"line": node.lineno, "bare": node.type is None, "empty": empty})
            self.generic_visit(node)

        def visit_Call(self, node):
            name = None
            if isinstance(node.func, ast.Name):
                name = node.func.id
                self._ref(name)
                if name in {"eval", "exec", "__import__"}:
                    analysis["dynamic"].append({"line": node.lineno, "kind": "eval" if name != "__import__" else "dynamic_import", "detail": name})
            elif isinstance(node.func, ast.Attribute):
                attr = node.func.attr
                owner = node.func.value
                if isinstance(owner, ast.Name):
                    self._attr(owner.id, attr, node.lineno)
                    if owner.id in {"importlib"} and attr == "import_module":
                        literal = None
                        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                            literal = node.args[0].value
                        if literal:
                            analysis["imports"].append(
                                {
                                    "line": node.lineno,
                                    "module": literal,
                                    "bindings": [{"local": literal.split(".")[-1], "remote": "*"}],
                                    "resolved": None,
                                    "unresolved": False,
                                }
                            )
                        else:
                            analysis["dynamic"].append({"line": node.lineno, "kind": "dynamic_import", "detail": "importlib.import_module"})
                    if attr in {"load", "loads"} and isinstance(owner, ast.Name) and owner.id in {"pickle", "yaml"}:
                        analysis["calls"].append({"line": node.lineno, "name": f"{owner.id}.{attr}", "in_loop": self.loop_depth > 0})
                if attr in {"system"} and isinstance(owner, ast.Name) and owner.id == "os":
                    analysis["calls"].append({"line": node.lineno, "name": "os.system", "in_loop": self.loop_depth > 0})
            if name:
                analysis["calls"].append({"line": node.lineno, "name": name, "in_loop": self.loop_depth > 0})
            self.generic_visit(node)

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load):
                self._ref(node.id)
            self.generic_visit(node)

        def visit_Attribute(self, node):
            if isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Name):
                self._attr(node.value.id, node.attr, node.lineno)
            if isinstance(node.ctx, ast.Load) and isinstance(node.value, ast.Call):
                analysis["dynamic"].append({"line": node.lineno, "kind": "reflection", "detail": "dynamic attribute"})
            self.generic_visit(node)

        def _ref(self, name):
            if self.scope:
                if name not in self.scope[-1]["refs"]:
                    self.scope[-1]["refs"].append(name)
            elif name not in analysis["module_refs"]:
                analysis["module_refs"].append(name)

        def _attr(self, owner, attr, line):
            item = {"object": owner, "attr": attr, "line": line}
            if self.scope:
                self.scope[-1]["attr_refs"].append(item)
            else:
                analysis["attr_refs"].append(item)
            if owner == "getattr":
                analysis["dynamic"].append({"line": line, "kind": "reflection", "detail": "getattr"})

    Index().visit(tree)
    if any(entry["kind"] == "convention" and entry["symbol"].startswith("test_") for entry in analysis["entries"]):
        analysis["entry_module"] = True
    if path.startswith("tests/") or "/tests/" in f"/{path}" or Path(path).name.startswith("test_"):
        analysis["entry_module"] = True
    return analysis


_REGEX_PREFIX_IDS = {"return", "throw", "case", "typeof", "void", "delete", "await", "else", "do", "yield", "new", "in", "of", "instanceof"}


def _regex_literal(text, index, limit, tokens):
    """Consume a JavaScript regex literal when `/` is not division or a comment."""
    if index + 1 < limit and text[index + 1] in {"/", "*"}:
        return None
    if index + 1 < limit and text[index + 1] == ">" and not (index + 2 < limit and text[index + 2] == "/"):
        return None
    if tokens:
        kind, previous, _line = tokens[-1]
        if kind in {"num", "string"} or (kind == "op" and previous in {")", "]"}):
            return None
        if kind == "sym" and previous == "<":
            return None
        if previous == "}":
            line_start = text.rfind("\n", 0, index) + 1
            if text[line_start:index].strip():
                return None
        if kind == "id" and previous not in _REGEX_PREFIX_IDS:
            return None
    cursor = index + 1
    in_class = False
    while cursor < limit:
        ch = text[cursor]
        if ch == "\n":
            return "unterminated"
        if ch == "\\":
            cursor += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
            cursor += 1
            if cursor < limit and text[cursor] == "^":
                cursor += 1
            if cursor < limit and text[cursor] == "]":
                cursor += 1
            continue
        if ch == "]" and in_class:
            in_class = False
            cursor += 1
            continue
        if ch == "/" and not in_class:
            cursor += 1
            while cursor < limit and text[cursor].isalpha():
                cursor += 1
            return cursor
        cursor += 1
    return "unterminated"


def _scan_tokens(text):
    tokens = []
    comments = []
    i = 0
    n = len(text)
    line = 1
    stack = []
    error = None
    pairs = {")": "(", "]": "[", "}": "{"}
    while i < n:
        ch = text[i]
        if ch == "\n":
            line += 1
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            end = text.find("\n", i)
            if end < 0:
                end = n
            comments.append(text[i:end])
            i = end
            continue
        if ch == "#" and (not tokens or tokens[-1][0] != "string"):
            end = text.find("\n", i)
            if end < 0:
                end = n
            comments.append(text[i:end])
            i = end
            continue
        if ch == "/":
            regex_end = _regex_literal(text, i, n, tokens)
            if regex_end == "unterminated":
                error = {"line": line, "message": "unterminated regex literal"}
                break
            if isinstance(regex_end, int):
                tokens.append(("string", text[i:regex_end], line))
                i = regex_end
                continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            end = text.find("*/", i + 2)
            if end < 0:
                error = {"line": line, "message": "unterminated block comment"}
                break
            comments.append(text[i : end + 2])
            line += text[i:end].count("\n")
            i = end + 2
            continue
        if ch in {"'", '"', "`"}:
            quote = ch
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "\n" and quote != "`":
                    error = {"line": line, "message": "unterminated string"}
                    break
                if text[j] == quote:
                    break
                if text[j] == "\n":
                    line += 1
                j += 1
            else:
                error = {"line": line, "message": "unterminated string"}
                break
            if error:
                break
            tokens.append(("string", text[i : j + 1], line))
            i = j + 1
            continue
        if ch in "([{":
            stack.append((ch, line))
            tokens.append(("op", ch, line))
            i += 1
            continue
        if ch in pairs:
            if not stack or stack[-1][0] != pairs[ch]:
                error = {"line": line, "message": f"mismatched delimiter {ch}"}
                break
            stack.pop()
            tokens.append(("op", ch, line))
            i += 1
            continue
        if ch.isalpha() or ch == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            tokens.append(("id", text[i:j], line))
            i = j
            continue
        if ch.isdigit():
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            tokens.append(("num", text[i:j], line))
            i = j
            continue
        if not ch.isspace():
            tokens.append(("sym", ch, line))
        i += 1
    if error is None and stack:
        error = {"line": stack[-1][1], "message": f"unclosed delimiter {stack[-1][0]}"}
    return tokens, error, comments


def _empty_catches(tokens):
    """Catch blocks whose body is empty or only a semicolon."""
    handlers = []
    index = 0
    while index < len(tokens):
        kind, text, line = tokens[index]
        if kind == "id" and text == "catch":
            cursor = index + 1
            if cursor < len(tokens) and tokens[cursor][0] == "op" and tokens[cursor][1] == "(":
                depth = 0
                while cursor < len(tokens):
                    token = tokens[cursor]
                    if token[0] == "op" and token[1] == "(":
                        depth += 1
                    elif token[0] == "op" and token[1] == ")":
                        depth -= 1
                        if depth == 0:
                            cursor += 1
                            break
                    cursor += 1
            if cursor < len(tokens) and tokens[cursor][0] == "op" and tokens[cursor][1] == "{":
                body = cursor + 1
                if body < len(tokens) and tokens[body][0] == "sym" and tokens[body][1] == ";":
                    body += 1
                if body < len(tokens) and tokens[body][0] == "op" and tokens[body][1] == "}":
                    handlers.append({"line": line, "bare": True, "empty": True})
        index += 1
    return handlers


_CONTROL_NAMES = {
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "else",
    "return",
    "new",
    "function",
    "class",
    "struct",
    "case",
    "do",
    "try",
    "throw",
    "sizeof",
    "typeof",
}
_DECISION_NAMES = {"if", "for", "while", "case", "catch"}


def _params_and_end(tokens, index):
    depth = 0
    commas = 0
    saw = False
    cursor = index
    while cursor < len(tokens):
        kind, text, _line = tokens[cursor]
        if kind == "op" and text == "(":
            depth += 1
        elif kind == "op" and text == ")":
            depth -= 1
            if depth == 0:
                return commas + (1 if saw else 0), cursor + 1
        elif depth == 1 and kind == "sym" and text == ",":
            commas += 1
        elif depth == 1 and kind == "id":
            saw = True
        cursor += 1
    return None, None


def _close_brace(tokens, index):
    depth = 0
    cursor = index
    while cursor < len(tokens):
        kind, text, _line = tokens[cursor]
        if kind == "op" and text == "{":
            depth += 1
        elif kind == "op" and text == "}":
            depth -= 1
            if depth == 0:
                return cursor
        cursor += 1
    return None


def _matching_body(tokens, index):
    params = 0
    cursor = index
    if cursor < len(tokens) and tokens[cursor][0] == "op" and tokens[cursor][1] == "(":
        params, cursor = _params_and_end(tokens, cursor)
        if cursor is None:
            return None
    allowed = {"const", "override", "noexcept", "volatile", "&", "*"}
    while cursor < len(tokens) and tokens[cursor][1] in allowed:
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor][0] != "op" or tokens[cursor][1] != "{":
        return None
    close = _close_brace(tokens, cursor)
    if close is None:
        return None
    return params, cursor, close


def _body_metrics(tokens):
    complexity = 1
    nesting = 0
    depth = 0
    cursor = 0
    while cursor < len(tokens):
        kind, text, _line = tokens[cursor]
        if kind == "op" and text == "{":
            depth += 1
            nesting = max(nesting, depth - 1)
        elif kind == "op" and text == "}":
            depth = max(0, depth - 1)
        elif depth >= 1 and kind == "id" and text in _DECISION_NAMES:
            complexity += 1
        elif depth >= 1 and kind == "op" and text == "?":
            complexity += 1
        elif depth >= 1 and kind == "sym" and text in {"&", "|"} and cursor + 1 < len(tokens) and tokens[cursor + 1][1] == text:
            complexity += 1
            cursor += 1
        cursor += 1
    end_line = tokens[-1][2] if tokens else 1
    return {"complexity": complexity, "nesting": nesting, "cognitive": complexity + nesting, "end_line": end_line}


def _iter_script_functions(tokens):
    found = []
    cursor = 0
    while cursor < len(tokens):
        kind, text, line = tokens[cursor]
        name = None
        name_line = line
        start = None
        if kind == "id" and text == "function" and cursor + 1 < len(tokens) and tokens[cursor + 1][0] == "id":
            name = tokens[cursor + 1][1]
            name_line = line
            start = cursor + 2
        elif (
            kind == "id"
            and text not in _CONTROL_NAMES
            and cursor + 1 < len(tokens)
            and tokens[cursor + 1][0] == "op"
            and tokens[cursor + 1][1] == "("
            and not (cursor > 0 and tokens[cursor - 1][1] in {".", ">", "new"})
        ):
            name = text
            name_line = line
            start = cursor + 1
        if name is None:
            cursor += 1
            continue
        body = _matching_body(tokens, start)
        if body is None:
            cursor += 1
            continue
        params, open_index, close_index = body
        body_tokens = tokens[open_index : close_index + 1]
        item = {"name": name, "line": name_line, "params": params}
        item.update(_body_metrics(body_tokens))
        kinds = [token[0] for token in body_tokens]
        item["structure"] = {
            "hash": hashlib.sha256("".join(kinds).encode("utf-8")).hexdigest(),
            "size": len(kinds),
            "tokens": [token[1] for token in body_tokens if token[0] == "id"][:80],
        }
        found.append(item)
        cursor = close_index + 1
    return found


def _script_symbol(path, item):
    return {
        "id": f"{path}::function::{item['name']}::{item['line']}",
        "kind": "function",
        "name": item["name"],
        "qualified": item["name"],
        "line": item["line"],
        "end_line": item["end_line"],
        "params": item["params"],
        "complexity": item["complexity"],
        "cognitive": item["cognitive"],
        "nesting": item["nesting"],
        "exported": False,
        "decorators": [],
        "doc": False,
        "refs": [],
        "attr_refs": [],
        "private": item["name"].startswith("_"),
        "parent": None,
    }


def _apply_script_metrics(analysis, tokens, header=False):
    functions = [symbol for symbol in analysis["symbols"] if symbol["kind"] == "function"]
    used = set()
    for item in _iter_script_functions(tokens):
        symbol = None
        for candidate in functions:
            if candidate["name"] == item["name"] and id(candidate) not in used:
                symbol = candidate
                break
        if symbol is None:
            symbol = _script_symbol(analysis["path"], item)
            symbol["exported"] = header
            analysis["symbols"].append(symbol)
            functions.append(symbol)
            if item["name"] == "main" or item["name"].startswith("test"):
                analysis["entries"].append({"symbol": item["name"], "kind": "convention", "reason": item["name"], "line": item["line"]})
                analysis["entry_module"] = True
        used.add(id(symbol))
        symbol["params"] = item["params"]
        symbol["complexity"] = item["complexity"]
        symbol["cognitive"] = item["cognitive"]
        symbol["nesting"] = item["nesting"]
        symbol["end_line"] = item["end_line"]
        analysis["structures"].append({"name": item["name"], **item["structure"]})
    _attach_methods(analysis, tokens)


def _type_spans(tokens):
    spans = []
    cursor = 0
    while cursor < len(tokens):
        kind, text, _line = tokens[cursor]
        if kind == "id" and text in {"class", "struct"} and cursor + 1 < len(tokens) and tokens[cursor + 1][0] == "id":
            name = tokens[cursor + 1][1]
            look = cursor + 2
            while look < len(tokens) and not (tokens[look][0] == "op" and tokens[look][1] == "{"):
                if tokens[look][0] == "sym" and tokens[look][1] == ";":
                    look = None
                    break
                look += 1
            if look is None or look >= len(tokens):
                cursor += 1
                continue
            close = _close_brace(tokens, look)
            if close is None:
                cursor += 1
                continue
            spans.append({"name": name, "start": tokens[look][2], "end": tokens[close][2]})
            cursor = close + 1
            continue
        cursor += 1
    return spans


def _attach_methods(analysis, tokens):
    spans = _type_spans(tokens)
    for symbol in analysis["symbols"]:
        if symbol["kind"] != "function":
            continue
        containing = [span for span in spans if span["start"] <= symbol["line"] <= span["end"]]
        if not containing:
            continue
        span = min(containing, key=lambda item: item["end"] - item["start"])
        symbol["kind"] = "method"
        symbol["parent"] = span["name"]
        symbol["qualified"] = f"{span['name']}.{symbol['name']}"


def _string_value(token):
    if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"', "`"}:
        return token[1:-1]
    return token


def _parse_import(tokens, index):
    line = tokens[index][2]
    cursor = index + 1
    bindings = []
    if cursor < len(tokens) and tokens[cursor][0] == "string":
        module = _string_value(tokens[cursor][1])
        return {"line": line, "module": module, "bindings": [], "resolved": None, "unresolved": False, "external": True}, cursor + 1
    if cursor < len(tokens) and tokens[cursor][0] == "id" and tokens[cursor][1] == "type":
        cursor += 1
    if cursor < len(tokens) and tokens[cursor][0] == "op" and tokens[cursor][1] == "{":
        cursor += 1
        while cursor < len(tokens) and not (tokens[cursor][0] == "op" and tokens[cursor][1] == "}"):
            if tokens[cursor][0] != "id":
                cursor += 1
                continue
            remote = tokens[cursor][1]
            local = remote
            cursor += 1
            if remote == "type" and cursor < len(tokens) and tokens[cursor][0] == "id":
                remote = tokens[cursor][1]
                local = remote
                cursor += 1
            if cursor + 1 < len(tokens) and tokens[cursor][1] == "as" and tokens[cursor + 1][0] == "id":
                local = tokens[cursor + 1][1]
                cursor += 2
            bindings.append({"local": local, "remote": remote})
        if cursor < len(tokens) and tokens[cursor][1] == "}":
            cursor += 1
    elif cursor < len(tokens) and tokens[cursor][1] == "*":
        if cursor + 2 < len(tokens) and tokens[cursor + 1][1] == "as" and tokens[cursor + 2][0] == "id":
            bindings.append({"local": tokens[cursor + 2][1], "remote": "*"})
            cursor += 3
    elif cursor < len(tokens) and tokens[cursor][0] == "id":
        bindings.append({"local": tokens[cursor][1], "remote": "default"})
        cursor += 1
    while cursor < len(tokens) and tokens[cursor][1] != "from":
        if tokens[cursor][1] in {";", "}"}:
            break
        cursor += 1
    module = ""
    if cursor < len(tokens) and tokens[cursor][1] == "from":
        cursor += 1
        if cursor < len(tokens) and tokens[cursor][0] == "string":
            module = _string_value(tokens[cursor][1])
            cursor += 1
    if not bindings and not module:
        return None, index + 1
    return {
        "line": line,
        "module": module,
        "bindings": bindings,
        "resolved": None,
        "unresolved": False,
        "external": True,
    }, cursor


def _script_imports(tokens):
    imports = []
    cursor = 0
    while cursor < len(tokens):
        kind, text, line = tokens[cursor]
        if kind == "id" and text == "import":
            parsed, cursor = _parse_import(tokens, cursor)
            if parsed:
                imports.append(parsed)
            continue
        if (
            kind == "id"
            and text in {"const", "let", "var"}
            and cursor + 3 < len(tokens)
            and tokens[cursor + 1][0] == "id"
            and tokens[cursor + 2][1] == "="
            and tokens[cursor + 3][0] == "id"
            and tokens[cursor + 3][1] == "require"
        ):
            module = ""
            look = cursor + 4
            while look < len(tokens) and tokens[look][0] != "string":
                if tokens[look][1] == ";":
                    break
                look += 1
            if look < len(tokens) and tokens[look][0] == "string":
                module = _string_value(tokens[look][1])
            imports.append(
                {
                    "line": line,
                    "module": module,
                    "bindings": [{"local": tokens[cursor + 1][1], "remote": "*"}],
                    "resolved": None,
                    "unresolved": False,
                    "external": True,
                }
            )
        cursor += 1
    counts = {}
    for kind, text, _line in tokens:
        if kind == "id":
            counts[text] = counts.get(text, 0) + 1
    for item in imports:
        for binding in item["bindings"]:
            binding["unused"] = counts.get(binding["local"], 0) <= 1
    return imports


def _const_condition(tokens, index):
    if index + 2 >= len(tokens):
        return None, index
    if tokens[index][0] != "op" or tokens[index][1] != "(":
        return None, index
    if tokens[index + 1][0] == "id" and tokens[index + 1][1] in {"true", "false"} and tokens[index + 2][0] == "op" and tokens[index + 2][1] == ")":
        return tokens[index + 1][1], index + 3
    return None, index


def _skip_statement(tokens, index):
    if index >= len(tokens):
        return index
    if tokens[index][0] == "op" and tokens[index][1] == "{":
        close = _close_brace(tokens, index)
        return None if close is None else close + 1
    depth = 0
    while index < len(tokens):
        text = tokens[index][1]
        if text == "(":
            depth += 1
        elif text == ")":
            depth -= 1
        elif text == ";" and depth == 0:
            return index + 1
        elif text == "{" and depth == 0:
            close = _close_brace(tokens, index)
            return None if close is None else close + 1
        index += 1
    return index


def _constant_branches(tokens):
    branches = []
    index = 0
    while index < len(tokens):
        kind, text, line = tokens[index]
        if kind == "id" and text in {"if", "while"}:
            condition, after = _const_condition(tokens, index + 1)
            if condition == "false":
                branches.append({"line": line, "message": "constant false branch"})
                index = after
                continue
            if condition == "true" and text == "if":
                nxt = _skip_statement(tokens, after)
                if nxt is not None and nxt < len(tokens) and tokens[nxt][1] == "else":
                    branches.append({"line": tokens[nxt][2], "message": "constant true branch makes else unreachable"})
                index = after
                continue
        index += 1
    return branches


def _cpp_includes(text):
    imports = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped.startswith("#include"):
            continue
        rest = stripped[len("#include") :].strip()
        if len(rest) < 2 or rest[0] != '"':
            continue
        end = rest.find('"', 1)
        if end < 0:
            continue
        imports.append(
            {
                "line": number,
                "module": rest[1:end],
                "bindings": [],
                "resolved": None,
                "unresolved": False,
            }
        )
    return imports


_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "head", "route"}
_ROUTE_RECEIVERS = {"app", "router", "application", "api", "server"}
_ROUTE_AUTH = re.compile(r"login_required|permission_required|requires_auth|authorize|current_user|Depends")


def _matching_paren(tokens, open_index):
    depth = 0
    for index in range(open_index, len(tokens)):
        kind, text, _line = tokens[index]
        if kind == "op" and text == "(":
            depth += 1
        elif kind == "op" and text == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _script_routes(tokens):
    """HTTP route calls such as app.post("/items", handler)."""
    routes = []
    index = 0
    while index < len(tokens):
        kind, text, line = tokens[index]
        if not (
            kind == "id"
            and text in _ROUTE_METHODS
            and index >= 2
            and tokens[index - 1][1] == "."
            and tokens[index - 2][0] == "id"
            and tokens[index - 2][1] in _ROUTE_RECEIVERS
            and index + 1 < len(tokens)
            and tokens[index + 1][1] == "("
        ):
            index += 1
            continue
        close = _matching_paren(tokens, index + 1)
        if close is None:
            index += 1
            continue
        arguments = tokens[index + 2 : close]
        path = arguments[0][1] if arguments and arguments[0][0] == "string" else ""
        inner = path[1:-1] if len(path) >= 2 and path[0] == path[-1] else ""
        if not inner.startswith("/"):
            index = close + 1
            continue
        routes.append(
            {
                "line": line,
                "method": text,
                "object": tokens[index - 2][1],
                "authorized": any(token[0] == "id" and _ROUTE_AUTH.search(token[1]) for token in arguments),
            }
        )
        index = close + 1
    return routes


def _script_like(path, text, language):
    analysis = _blank_analysis(path, language, text.count("\n") + 1 if text else 0)
    analysis["style"] = _style(text)
    analysis["normalized_lines"] = _normalized(text)
    analysis["text_hash"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    tokens, error, comments = _scan_tokens(text)
    analysis["comments"] = comments
    chosen = [token for token in tokens if token[0] in {"id", "num", "op", "sym"}]
    analysis["tokens"] = [token[1] for token in chosen]
    analysis["token_lines"] = [token[2] for token in chosen]
    analysis["handlers"].extend(_empty_catches(tokens))
    analysis["imports"].extend(_script_imports(tokens))
    analysis["dead_branches"].extend(_constant_branches(tokens))
    analysis["routes"] = _script_routes(tokens)
    for route in analysis["routes"]:
        analysis["entries"].append(
            {
                "symbol": f"{route['object']}.{route['method']}",
                "kind": "framework",
                "reason": f"route {route['method']}",
                "line": route["line"],
            }
        )
        analysis["entry_module"] = True
    if error:
        analysis["syntax_errors"].append(error)
    if language == "cpp":
        analysis["imports"].extend(_cpp_includes(text))
    if language == "cpp" and "#if" in text:
        analysis["limits"].append("preprocessor conditions are not evaluated; affected branches stay uncertain")
        analysis["dynamic"].append({"line": 1, "kind": "preprocessor", "detail": "#if"})
    ids = [(token[1], token[2]) for token in tokens if token[0] == "id"]
    exported = set()
    header = language == "cpp" and Path(path).suffix in {".h", ".hpp", ".hh", ".hxx"}
    export_keywords = {"function", "class", "default", "const", "let", "var", "async"}
    i = 0
    while i < len(ids):
        name, line = ids[i]
        nxt = ids[i + 1][0] if i + 1 < len(ids) else ""
        if name in {"function", "class", "struct"} and nxt and nxt not in {"if", "for", "while", "switch"}:
            kind = "class" if name in {"class", "struct"} else "function"
            analysis["symbols"].append(
                {
                    "id": f"{path}::{kind}::{nxt}::{line}",
                    "kind": kind,
                    "name": nxt,
                    "qualified": nxt,
                    "line": line,
                    "end_line": line,
                    "params": 0,
                    "complexity": 1,
                    "cognitive": 1,
                    "nesting": 0,
                    "exported": header,
                    "decorators": [],
                    "doc": False,
                    "refs": [],
                    "attr_refs": [],
                    "private": nxt.startswith("_"),
                    "parent": None,
                }
            )
            if nxt == "main" or nxt.startswith("test"):
                analysis["entries"].append({"symbol": nxt, "kind": "convention", "reason": nxt, "line": line})
                analysis["entry_module"] = True
        if name == "export":
            cursor = i + 1
            while cursor < len(ids) and ids[cursor][0] in export_keywords:
                cursor += 1
            declared = ids[cursor][0] if cursor < len(ids) else ""
            if declared:
                exported.add(declared)
            analysis["entries"].append({"symbol": declared or nxt, "kind": "export", "reason": "export", "line": line})
            analysis["entry_module"] = True
        if name in {"eval", "Function"}:
            analysis["dynamic"].append({"line": line, "kind": "eval", "detail": name})
        if name in {"require", "import"} and nxt == "":
            analysis["dynamic"].append({"line": line, "kind": "dynamic_import", "detail": name})
        i += 1
    _apply_script_metrics(analysis, tokens, header=header)
    defined = {symbol["name"] for symbol in analysis["symbols"]}
    for name, line in ids:
        if name in defined:
            analysis["module_refs"].append(name)
    # A name mentioned only at its definition should not count as a use.
    definitions = {}
    for symbol in analysis["symbols"]:
        definitions.setdefault(symbol["name"], 0)
        definitions[symbol["name"]] += 1
    uses = {}
    for name in analysis["module_refs"]:
        uses[name] = uses.get(name, 0) + 1
    analysis["module_refs"] = [name for name, count in uses.items() if count > definitions.get(name, 0)]
    for symbol in analysis["symbols"]:
        if symbol["name"] in exported:
            symbol["exported"] = True
    if language in {"javascript", "typescript"}:
        analysis["limits"].append(
            "JavaScript and TypeScript symbols come from a conservative scanner. Type checking is unavailable unless tsc is an approved tool."
        )
    if language == "cpp":
        analysis["limits"].append("C++ symbols come from a conservative scanner unless clang syntax checking is approved.")
    if any(symbol["name"] == "main" for symbol in analysis["symbols"]):
        analysis["entry_module"] = True
    return analysis


class LanguageAdapter:
    language = ""
    extensions = ()

    def analyze(self, root, path):
        raise NotImplementedError


class PythonAdapter(LanguageAdapter):
    language = "python"
    extensions = (".py",)

    def analyze(self, root, path):
        rel = _rel(root, path)
        text, problem = _read(path)
        if problem:
            analysis = _blank_analysis(rel, self.language, 0, problem)
            return analysis
        return _python(rel, text)


class JavaScriptAdapter(LanguageAdapter):
    language = "javascript"
    extensions = (".js", ".jsx", ".mjs", ".cjs")

    def analyze(self, root, path):
        rel = _rel(root, path)
        text, problem = _read(path)
        if problem:
            return _blank_analysis(rel, self.language, 0, problem)
        return _script_like(rel, text, self.language)


class TypeScriptAdapter(JavaScriptAdapter):
    language = "typescript"
    extensions = (".ts", ".tsx")

    def analyze(self, root, path):
        analysis = super().analyze(root, path)
        analysis["language"] = self.language
        return analysis


class CppAdapter(LanguageAdapter):
    language = "cpp"
    extensions = (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".h")

    def analyze(self, root, path):
        rel = _rel(root, path)
        text, problem = _read(path)
        if problem:
            return _blank_analysis(rel, self.language, 0, problem)
        return _script_like(rel, text, self.language)


ADAPTERS = [PythonAdapter(), JavaScriptAdapter(), TypeScriptAdapter(), CppAdapter()]


def register_adapter(adapter):
    """Add a language without copying the policy engine, catalogs, or report formats."""
    ADAPTERS.append(adapter)


def adapter_for(path):
    suffix = Path(path).suffix.lower()
    for adapter in ADAPTERS:
        if suffix in adapter.extensions:
            return adapter
    return None


def analyze_path(root, path):
    adapter = adapter_for(path)
    if adapter is None:
        return _blank_analysis(_rel(root, path), "unknown", 0, "no adapter")
    return adapter.analyze(root, path)


def source_static(root, files):
    """Confirmed syntax findings from the language adapters."""
    findings = []
    evidence = []
    for path in files:
        analysis = analyze_path(root, path)
        evidence.append({"file": analysis["path"], "language": analysis["language"], "limits": analysis["limits"]})
        for error in analysis["syntax_errors"]:
            findings.append(
                {
                    "file": str(path),
                    "line": error["line"],
                    "confidence": "confirmed",
                    "message": error["message"],
                    "check_id": "syntax_static",
                    "metric_ids": ["REL-004"],
                    "tool": {"name": "cqa-builtin", "version": ENGINE_VERSION},
                    "observation": error["message"],
                }
            )
    return findings, evidence
