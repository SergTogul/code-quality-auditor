"""Exact, token, structural, and semantic duplication.

Semantic similarity is a candidate with rationale and uncertainty. It is not
confirmation that two copies behave the same.
"""

from __future__ import annotations

import hashlib


def _groups(items, key):
    grouped = {}
    for item in items:
        grouped.setdefault(key(item), []).append(item)
    return [group for group in grouped.values() if len(group) > 1]


def exact_duplicates(analyses, window=6):
    blocks = []
    for analysis in analyses:
        lines = analysis.get("normalized_lines") or []
        for start in range(0, max(0, len(lines) - window + 1)):
            chunk = lines[start : start + window]
            if len(chunk) < window:
                continue
            digest = hashlib.sha256("\n".join(chunk).encode("utf-8")).hexdigest()
            blocks.append({"file": analysis["path"], "line": start + 1, "hash": digest, "language": analysis["language"]})
    groups = []
    for group in _groups(blocks, lambda item: item["hash"]):
        locations = {(item["file"], item["line"]) for item in group}
        files = {item["file"] for item in group}
        if len(locations) < 2 or len(files) < 2 and len(locations) < 2:
            continue
        # Overlapping windows in one file are not two implementations.
        if len(files) < 2:
            continue
        groups.append(
            {
                "kind": "exact",
                "confirmed": True,
                "hash": group[0]["hash"],
                "locations": [{"file": item["file"], "line": item["line"]} for item in group[:8]],
                "justified": False,
                "languages": sorted({item["language"] for item in group}),
            }
        )
    return groups


def _winnow_fingerprints(tokens, k, window):
    """Select the rightmost minimum hash in each window of k-gram hashes."""
    grams = []
    for start in range(0, len(tokens) - k + 1):
        digest = hashlib.sha256(" ".join(tokens[start : start + k]).encode("utf-8")).hexdigest()
        grams.append((digest, start))
    if not grams:
        return []
    if len(grams) <= window:
        minimum = min(item[0] for item in grams)
        chosen = max(index for index, item in enumerate(grams) if item[0] == minimum)
        return [grams[chosen]]
    selected = {}
    for start in range(0, len(grams) - window + 1):
        chunk = grams[start : start + window]
        minimum = min(item[0] for item in chunk)
        chosen = max(offset for offset, item in enumerate(chunk) if item[0] == minimum)
        fingerprint = chunk[chosen]
        selected[fingerprint] = fingerprint
    return list(selected.values())


def token_duplicates(analyses, window=24):
    k = min(12, window)
    winnow = max(1, window - k + 1)
    blocks = []
    for analysis in analyses:
        tokens = [token for token in analysis.get("tokens") or [] if str(token).strip()]
        lines = analysis.get("token_lines") or []
        for digest, start in _winnow_fingerprints(tokens, k, winnow):
            line = lines[start] if start < len(lines) else 1
            blocks.append({"file": analysis["path"], "line": line, "hash": digest, "language": analysis["language"], "start": start})
    groups = []
    for group in _groups(blocks, lambda item: item["hash"]):
        files = {item["file"] for item in group}
        if len(files) < 2:
            continue
        groups.append(
            {
                "kind": "token",
                "confirmed": True,
                "hash": group[0]["hash"],
                "locations": [{"file": item["file"], "line": item["line"], "token_index": item["start"]} for item in group[:8]],
                "justified": False,
                "languages": sorted({item["language"] for item in group}),
            }
        )
    return groups


def structural_duplicates(analyses):
    items = []
    for analysis in analyses:
        for structure in analysis.get("structures") or []:
            if structure["size"] < 8:
                continue
            items.append({**structure, "file": analysis["path"], "language": analysis["language"]})
    groups = []
    for group in _groups(items, lambda item: item["hash"]):
        names = {(item["file"], item["name"]) for item in group}
        if len(names) < 2:
            continue
        groups.append(
            {
                "kind": "structural",
                "confirmed": True,
                "hash": group[0]["hash"],
                "locations": [{"file": item["file"], "name": item["name"]} for item in group],
                "justified": False,
                "languages": sorted({item["language"] for item in group}),
            }
        )
    return groups


def _jaccard(left, right):
    a = set(left)
    b = set(right)
    if not a or not b:
        return 0
    return len(a & b) / len(a | b)


def semantic_candidates(analyses, threshold=0.8):
    functions = []
    for analysis in analyses:
        for structure in analysis.get("structures") or []:
            tokens = structure.get("tokens") or []
            if len(tokens) < 6:
                continue
            functions.append({**structure, "file": analysis["path"], "language": analysis["language"]})
    candidates = []
    for index, left in enumerate(functions):
        for right in functions[index + 1 :]:
            if left["file"] == right["file"] and left["name"] == right["name"]:
                continue
            score = _jaccard(left["tokens"], right["tokens"])
            if score < threshold:
                continue
            if left["hash"] == right["hash"]:
                continue
            candidates.append(
                {
                    "kind": "semantic",
                    "confirmed": False,
                    "confirmed_by_tests": False,
                    "score": round(score, 3),
                    "locations": [
                        {"file": left["file"], "name": left["name"], "language": left["language"]},
                        {"file": right["file"], "name": right["name"], "language": right["language"]},
                    ],
                    "cross_language": left["language"] != right["language"],
                    "rationale": "Normalized token sets are similar, which can mean copied behavior or a coincidence.",
                    "uncertainty": "Similarity does not prove equivalent behavior. A differential test or shared contract is required before confirmation.",
                    "sources": [left["file"], right["file"]],
                    "justified": False,
                }
            )
    return candidates


def apply_justifications(groups, analyses):
    notes = []
    for analysis in analyses:
        for index, comment in enumerate(analysis.get("comments") or []):
            if "cqa-justified-duplicate" in comment:
                notes.append(analysis["path"])
    for group in groups:
        files = [location["file"] for location in group.get("locations") or []]
        if any(path in notes for path in files):
            group["justified"] = True
            group["confirmed"] = False
            group["justification"] = "cqa-justified-duplicate comment"
    return groups
