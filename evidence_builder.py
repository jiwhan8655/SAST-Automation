# evidence_builder.py
from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

@dataclass(frozen=True)
class SnippetWindow:
    before: int = 20
    after: int = 20

def read_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def make_snippet(lines: List[str], start_line: int, end_line: int,
                 window: SnippetWindow) -> Tuple[Dict[str, int], str]:
    # lines is 0-indexed in memory; start_line/end_line are 1-indexed from SARIF
    total = len(lines)
    start_line = clamp(start_line, 1, total)
    end_line = clamp(end_line, start_line, total)

    from_line = clamp(start_line - window.before, 1, total)
    to_line = clamp(end_line + window.after, 1, total)

    out = []
    for ln in range(from_line, to_line + 1):
        out.append(f"{ln:6d} | {lines[ln - 1]}")
    region = {"startLine": start_line, "endLine": end_line, "fromLine": from_line, "toLine": to_line}
    return region, "\n".join(out)

def guess_primary_symbol(primary_line_text: str) -> Tuple[str, float]:
    # very simple heuristic: pick first foo( pattern
    m = re.search(r"\b([A-Za-z_$][\w$]*)\s*\(", primary_line_text)
    if not m:
        return ("unknown", 0.0)
    name = m.group(1)
    # discount common keywords
    if name in {"if", "for", "while", "switch", "catch", "function"}:
        return ("unknown", 0.2)
    return (name, 0.6)

def find_symbol_definitions(repo_root: str, symbol: str, max_hits: int = 10) -> List[Dict[str, Any]]:
    # lightweight grep-like scan (no external deps)
    patterns = [
        re.compile(rf"\bfunction\s+{re.escape(symbol)}\b"),
        re.compile(rf"\b{re.escape(symbol)}\s*=\s*\("),
        re.compile(rf"\b{re.escape(symbol)}\s*\([^)]*\)\s*\{{"),
        re.compile(rf"\bexport\s+function\s+{re.escape(symbol)}\b"),
    ]
    hits = []
    for root, _, files in os.walk(repo_root):
        for fn in files:
            if not fn.endswith((".js", ".ts", ".jsx", ".tsx", ".py", ".java", ".go", ".rb", ".php")):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, repo_root).replace("\\", "/")
            try:
                lines = read_lines(path)
            except Exception:
                continue
            for idx, line in enumerate(lines, start=1):
                if any(p.search(line) for p in patterns):
                    hits.append({"uri": rel, "line": idx, "lineText": line.strip()})
                    if len(hits) >= max_hits:
                        return hits
    return hits

def find_callers(repo_root: str, symbol: str, max_hits: int = 30) -> List[Dict[str, Any]]:
    pat = re.compile(rf"\b{re.escape(symbol)}\s*\(")
    hits = []
    for root, _, files in os.walk(repo_root):
        for fn in files:
            if not fn.endswith((".js", ".ts", ".jsx", ".tsx")):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, repo_root).replace("\\", "/")
            try:
                lines = read_lines(path)
            except Exception:
                continue
            for idx, line in enumerate(lines, start=1):
                if pat.search(line):
                    hits.append({"uri": rel, "line": idx, "lineText": line.strip()})
                    if len(hits) >= max_hits:
                        return hits
    return hits

def build_evidence(issue: Dict[str, Any], repo_root: str) -> Dict[str, Any]:
    primary = issue["locations"]["primary"]
    uri = primary["uri"]
    abs_path = os.path.join(repo_root, uri)
    lines = read_lines(abs_path)

    start = primary["region"]["startLine"]
    end = primary["region"].get("endLine", start)
    region_info, primary_snip = make_snippet(lines, start, end, SnippetWindow(20, 20))

    primary_line_text = lines[start - 1] if 1 <= start <= len(lines) else ""
    sym, conf = guess_primary_symbol(primary_line_text)

    related_blocks = []
    for r in issue.get("locations", {}).get("related", []) or []:
        r_uri = r["uri"]
        r_start = r["region"]["startLine"]
        r_end = r["region"].get("endLine", r_start)
        dedup_key = f"{r_uri}:{r_start}:{r.get('role','')}"
        related_blocks.append((dedup_key, r))

    # dedup
    seen = set()
    related_out = []
    for dedup_key, r in related_blocks:
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        r_abs = os.path.join(repo_root, r["uri"])
        if not os.path.exists(r_abs):
            continue
        r_lines = read_lines(r_abs)
        r_region_info, r_snip = make_snippet(r_lines, r["region"]["startLine"], r["region"].get("endLine", r["region"]["startLine"]),
                                             SnippetWindow(10, 10))
        related_out.append({
            "uri": r["uri"],
            "region": {"startLine": r["region"]["startLine"], "endLine": r["region"].get("endLine")},
            "role": r.get("role"),
            "window": {"before": 10, "after": 10},
            "snippet": r_snip,
            "dedup_key": dedup_key
        })

    defs = [] if sym == "unknown" else find_symbol_definitions(repo_root, sym, max_hits=8)
    callers = [] if sym == "unknown" else find_callers(repo_root, sym, max_hits=20)

    return {
        "evidence_id": f"ev-{issue['issue_id']}",
        "issue_id": issue["issue_id"],
        "meta": {
            "tool": issue.get("tool", {}),
            "rule": issue.get("rule", {}),
            "severity": (issue.get("sast", {}) or {}).get("severity"),
            "message": issue.get("message"),
        },
        "code_context": {
            "primary": {
                "uri": uri,
                "region": {"startLine": start, "endLine": end},
                "window": {"before": 20, "after": 20},
                "snippet": primary_snip,
            },
            "related": related_out,
        },
        "symbols": {
            "primary_symbol_guess": {
                "kind": "unknown",
                "name": sym,
                "confidence": conf,
            },
            "definition_candidates": defs,
            "caller_candidates": callers,
        },
        "entrypoints": {
            "http_routes": [],   # TODO: add route extractors
            "cli_jobs_or_workers": [],
        },
        "config_hints": [],
    }

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", required=True)
    ap.add_argument("--parsed-issues", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    issues = json.load(open(args.parsed_issues, "r", encoding="utf-8"))
    out = []
    for issue in issues:
        out.append(build_evidence(issue, args.repo_root))

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
