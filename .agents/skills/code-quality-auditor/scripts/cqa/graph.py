"""Cross-language code graph, reachability, and completeness."""

from __future__ import annotations

import os
from pathlib import Path


def _module_name(path):
    rel = Path(path)
    if rel.name == "__init__.py":
        return ".".join(rel.parent.parts)
    if rel.suffix == ".py":
        return ".".join(rel.with_suffix("").parts)
    return None


def _resolve_modules(analyses):
    by_path = {analysis["path"]: analysis for analysis in analyses}
    by_module = {}
    for analysis in analyses:
        module = _module_name(analysis["path"])
        if module is not None:
            by_module[module] = analysis["path"]
    symbols = {}
    for analysis in analyses:
        for symbol in analysis["symbols"]:
            symbols.setdefault(analysis["path"], {})[symbol["name"]] = symbol
    for analysis in analyses:
        package = ""
        if analysis["language"] == "python":
            rel = Path(analysis["path"])
            package = ".".join(rel.parent.parts) if rel.name != "__init__.py" else ".".join(rel.parent.parts)
        for imp in analysis["imports"]:
            module = imp.get("module") or ""
            if analysis.get("language") != "python":
                _bind_import(imp, _resolve_source_path(analysis, module, by_path), symbols)
                continue
            level = imp.get("level") or 0
            if module.startswith("."):
                level = len(module) - len(module.lstrip("."))
                module = module.lstrip(".")
            if level:
                parts = [part for part in package.split(".") if part]
                if level > len(parts):
                    imp["unresolved"] = True
                    continue
                base = parts[: len(parts) - level + (0 if module else 0)]
                # `from . import x` has level 1 and empty module; the binding is a sibling.
                if module:
                    target_name = ".".join([*parts[: len(parts) - (level - 1) if level else len(parts)], module]) if False else ".".join([*parts[: max(0, len(parts) - level + 1)], module])
                else:
                    target_name = ".".join(parts[: max(0, len(parts) - level + 1)])
            else:
                target_name = module
            # Simplify absolute and relative lookups to a file we indexed.
            resolved = by_module.get(target_name)
            if resolved is None and module and not level:
                resolved = by_module.get(module)
            if resolved is None:
                resolved = _resolve_source_path(analysis, module, by_path)
            if resolved is None and imp["bindings"] and not module.startswith("."):
                # `import app` binds the top package.
                top = (module or "").split(".")[0]
                resolved = by_module.get(top) or by_module.get(module)
            _bind_import(imp, resolved, symbols)
    return by_path, symbols


def _bind_import(imp, resolved, symbols):
    imp["resolved"] = resolved
    imp["symbol_map"] = {}
    if resolved is None:
        if imp.get("unresolved"):
            return
        # External libraries are resolved as external, not as uncertain local edges.
        imp["external"] = True
        return
    target_symbols = symbols.get(resolved, {})
    for binding in imp["bindings"]:
        remote = binding["remote"]
        if remote == "*":
            continue
        symbol = target_symbols.get(remote)
        if symbol:
            imp["symbol_map"][binding["local"]] = symbol["id"]
        else:
            imp["unresolved"] = True


def _posix(path):
    text = Path(path).as_posix()
    return text[2:] if text.startswith("./") else text


def _resolve_source_path(analysis, module, by_path):
    """Resolve a relative JavaScript, TypeScript, or quoted C++ include to an indexed file."""
    language = analysis.get("language")
    module = str(module or "")
    if language in {"javascript", "typescript"}:
        if not module.startswith("."):
            return None
    elif language == "cpp":
        if not module or module.startswith("<"):
            return None
    else:
        return None
    normalized = _posix(os.path.normpath(str(Path(analysis["path"]).parent / module)))
    candidates = [normalized]
    if language in {"javascript", "typescript"}:
        for suffix in (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"):
            candidates.append(normalized + suffix)
        for name in ("index.js", "index.ts", "index.tsx"):
            candidates.append(_posix(Path(normalized) / name))
    for candidate in candidates:
        if candidate in by_path:
            return candidate
    return None


def _resolve_local(analysis, name):
    for symbol in analysis["symbols"]:
        if symbol["name"] == name:
            return symbol["id"]
    for imp in analysis["imports"]:
        mapped = (imp.get("symbol_map") or {}).get(name)
        if mapped:
            return mapped
    return None


def build_graph(analyses):
    by_path, symbols_by_file = _resolve_modules(analyses)
    nodes = []
    edges = []
    for analysis in analyses:
        nodes.append(
            {
                "id": f"module:{analysis['path']}",
                "kind": "module",
                "name": analysis["path"],
                "language": analysis["language"],
                "file": analysis["path"],
                "line": 1,
                "uncertainty": analysis["limits"][:],
            }
        )
        for symbol in analysis["symbols"]:
            nodes.append(
                {
                    "id": symbol["id"],
                    "kind": symbol["kind"],
                    "name": symbol["name"],
                    "language": analysis["language"],
                    "file": analysis["path"],
                    "line": symbol["line"],
                    "uncertainty": [],
                }
            )
            edges.append(
                {
                    "source": f"module:{analysis['path']}",
                    "target": symbol["id"],
                    "kind": "contains",
                    "file": analysis["path"],
                    "line": symbol["line"],
                    "confidence": "static",
                    "unresolved": False,
                }
            )
        for imp in analysis["imports"]:
            target = f"module:{imp['resolved']}" if imp.get("resolved") else imp.get("module")
            edges.append(
                {
                    "source": f"module:{analysis['path']}",
                    "target": target,
                    "kind": "import",
                    "file": analysis["path"],
                    "line": imp["line"],
                    "confidence": "external" if imp.get("external") else "static",
                    "unresolved": bool(imp.get("unresolved")),
                }
            )
        for branch in analysis["dead_branches"]:
            edges.append(
                {
                    "source": f"module:{analysis['path']}",
                    "target": f"branch:{analysis['path']}:{branch['line']}",
                    "kind": "control",
                    "file": analysis["path"],
                    "line": branch["line"],
                    "confidence": "static",
                    "unresolved": False,
                    "detail": branch["message"],
                }
            )
        for ref_owner in (None,):
            for item in analysis["attr_refs"]:
                edges.append(
                    {
                        "source": f"module:{analysis['path']}",
                        "target": f"{item['object']}.{item['attr']}",
                        "kind": "reference",
                        "file": analysis["path"],
                        "line": item["line"],
                        "confidence": "static",
                        "unresolved": False,
                    }
                )
        for symbol in analysis["symbols"]:
            for name in symbol["refs"]:
                target = _resolve_local(analysis, name)
                edges.append(
                    {
                        "source": symbol["id"],
                        "target": target or name,
                        "kind": "call" if target else "reference",
                        "file": analysis["path"],
                        "line": symbol["line"],
                        "confidence": "static" if target else "name",
                        "unresolved": False,
                    }
                )
            for item in symbol["attr_refs"]:
                edges.append(
                    {
                        "source": symbol["id"],
                        "target": f"{item['object']}.{item['attr']}",
                        "kind": "data",
                        "file": analysis["path"],
                        "line": item["line"],
                        "confidence": "static",
                        "unresolved": False,
                    }
                )
        for site in analysis["dynamic"]:
            edges.append(
                {
                    "source": f"module:{analysis['path']}",
                    "target": site.get("detail", site["kind"]),
                    "kind": "dynamic",
                    "file": analysis["path"],
                    "line": site["line"],
                    "confidence": "uncertain",
                    "unresolved": True,
                    "reason": site["kind"],
                }
            )

    entry_points = []
    entry_modules = set()
    entry_symbols = set()
    for analysis in analyses:
        if analysis.get("entry_module"):
            entry_modules.add(analysis["path"])
            entry_points.append(
                {"id": f"module:{analysis['path']}", "kind": "module", "reason": "entry module", "file": analysis["path"]}
            )
        for entry in analysis["entries"]:
            if entry["symbol"] == "<module>":
                entry_modules.add(analysis["path"])
                continue
            symbol = symbols_by_file.get(analysis["path"], {}).get(entry["symbol"])
            if symbol:
                entry_symbols.add(symbol["id"])
                entry_points.append(
                    {
                        "id": symbol["id"],
                        "kind": entry["kind"],
                        "reason": entry["reason"],
                        "file": analysis["path"],
                        "line": entry["line"],
                    }
                )

    used_symbols = set(entry_symbols)
    used_modules = set(entry_modules)
    imported_modules = set()
    for analysis in analyses:
        for imp in analysis["imports"]:
            if imp.get("resolved"):
                imported_modules.add(imp["resolved"])
    changed = True
    while changed:
        changed = False
        for analysis in analyses:
            if analysis["path"] not in used_modules:
                continue
            for name in analysis["module_refs"]:
                target = _resolve_local(analysis, name)
                if target and target not in used_symbols:
                    used_symbols.add(target)
                    changed = True
            for imp in analysis["imports"]:
                if imp.get("resolved") and imp["resolved"] not in used_modules:
                    used_modules.add(imp["resolved"])
                    changed = True
                for binding in imp["bindings"]:
                    target = (imp.get("symbol_map") or {}).get(binding["local"])
                    if target and target not in used_symbols:
                        used_symbols.add(target)
                        changed = True
            for item in analysis["attr_refs"]:
                owner = item["object"]
                for imp in analysis["imports"]:
                    local_names = {binding["local"] for binding in imp["bindings"]}
                    if owner in local_names and imp.get("resolved"):
                        symbol = symbols_by_file.get(imp["resolved"], {}).get(item["attr"])
                        if symbol and symbol["id"] not in used_symbols:
                            used_symbols.add(symbol["id"])
                            changed = True
        for analysis in analyses:
            for symbol in analysis["symbols"]:
                if symbol["id"] not in used_symbols:
                    continue
                for name in symbol["refs"]:
                    target = _resolve_local(analysis, name)
                    if target and target not in used_symbols:
                        used_symbols.add(target)
                        changed = True
                for item in symbol["attr_refs"]:
                    if item["object"] in {"self", "cls"} and symbol.get("parent"):
                        method = symbols_by_file.get(analysis["path"], {}).get(item["attr"])
                        if method and method["id"] not in used_symbols:
                            used_symbols.add(method["id"])
                            changed = True

    project_dynamic = [
        site
        for analysis in analyses
        for site in analysis["dynamic"]
        if site["kind"] in {"dynamic_import", "eval", "reflection", "preprocessor"}
    ]
    uncertain_symbols = set()
    for analysis in analyses:
        for site in analysis["dynamic"]:
            if site["kind"] == "unknown_decorator" and site.get("symbol"):
                symbol = symbols_by_file.get(analysis["path"], {}).get(site["symbol"])
                if symbol:
                    uncertain_symbols.add(symbol["id"])
    if project_dynamic:
        for analysis in analyses:
            for symbol in analysis["symbols"]:
                uncertain_symbols.add(symbol["id"])

    dead_functions = []
    dead_classes = []
    dead_modules = []
    confirm = not project_dynamic and bool(entry_points)
    for analysis in analyses:
        for symbol in analysis["symbols"]:
            if symbol["id"] in used_symbols:
                continue
            if symbol["kind"] == "method":
                parent = next((item for item in analysis["symbols"] if item["kind"] == "class" and item["name"] == symbol.get("parent")), None)
                if parent and parent["id"] not in used_symbols:
                    continue
                if not symbol.get("private"):
                    continue
            library_api = analysis["path"] in imported_modules and symbol.get("exported") and not symbol.get("private")
            confirmed = confirm and symbol["id"] not in uncertain_symbols and not library_api
            reason = "no entry point or reference"
            if not confirm:
                reason = "graph is too uncertain to confirm unreachability"
            elif library_api:
                reason = "imported module may expose this symbol; not confirmed dead"
            record = {
                "symbol": symbol,
                "file": analysis["path"],
                "line": symbol["line"],
                "confirmed": confirmed,
                "reason": reason,
            }
            if symbol["kind"] == "class":
                dead_classes.append(record)
            elif symbol["kind"] in {"function", "method"}:
                dead_functions.append(record)
        if len(analyses) > 1 and analysis["path"] not in used_modules and not analysis.get("entry_module"):
            dead_modules.append(
                {
                    "file": analysis["path"],
                    "confirmed": confirm and not project_dynamic,
                    "reason": "module is not imported from an entry point" if confirm else "import reachability is uncertain",
                }
            )

    unresolved = [edge for edge in edges if edge.get("unresolved")]
    indexed = [analysis for analysis in analyses if not analysis.get("skipped")]
    completeness = {
        "indexed_files": len(indexed),
        "discovered_files": len(analyses),
        "symbols": sum(len(analysis["symbols"]) for analysis in analyses),
        "unresolved_edges": len(unresolved),
        "entry_point_count": len(entry_points),
        "entry_point_coverage": (100.0 * len(entry_modules) / len(analyses)) if analyses else 0,
        "limits": sorted({limit for analysis in analyses for limit in analysis["limits"]}),
        "dynamic_sites": len(project_dynamic) + sum(1 for analysis in analyses for site in analysis["dynamic"] if site["kind"] == "unknown_decorator"),
        "can_confirm_dead_code": confirm,
    }
    return {
        "nodes": nodes,
        "edges": edges,
        "entry_points": entry_points,
        "completeness": completeness,
        "dead_functions": dead_functions,
        "dead_classes": dead_classes,
        "dead_modules": dead_modules,
        "dead_branches": [
            {"file": analysis["path"], "line": branch["line"], "message": branch["message"], "confirmed": True}
            for analysis in analyses
            for branch in analysis["dead_branches"]
        ],
        "uncertain_symbols": sorted(uncertain_symbols),
    }
