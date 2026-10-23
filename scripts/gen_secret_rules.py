#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Convert gitleaks' config into internal/detect/secret_rules.json.

The config is downloaded at the tag in third_party/gitleaks/VERSION, in
memory; nothing but the JSON is written. Only the fields Basilisk uses are
kept. Basilisk scans text, so path-only rules, and the `paths` and `commits`
fields of allowlists, are dropped.
"""

import json
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "third_party" / "gitleaks"
OUT = ROOT / "internal" / "detect" / "secret_rules.json"

TARGETS = {"secret", "match", "line"}


def fetch_config(version):
    url = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{version}/config/gitleaks.toml"
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            return resp.read().decode("utf-8")
    except OSError as e:
        sys.exit(f"cannot download {url}: {e}")


def as_list(v):
    """Allowlists are a single table or an array of tables, by release."""
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def convert_allowlist(a, where):
    """Return a runtime allowlist, or None when it cannot apply to text."""
    cond = a.get("condition", "OR").upper()
    if cond == "AND" and a.get("paths"):
        print(f"dropped allowlist (AND with paths) on {where}", file=sys.stderr)
        return None
    if cond != "OR":
        sys.exit(f"unsupported allowlist condition {cond!r} on {where}")
    target = a.get("regexTarget", "secret")
    if target not in TARGETS:
        sys.exit(f"unsupported regexTarget {target!r} on {where}")
    regexes = list(a.get("regexes", []))
    stopwords = list(a.get("stopwords", []))
    if not regexes and not stopwords:
        return None  # paths/commits only
    return {"regexTarget": target, "regexes": regexes, "stopwords": stopwords}


def convert_allowlists(raw, where):
    out = [convert_allowlist(a, where) for a in as_list(raw)]
    return [a for a in out if a]


def main():
    version = (SRC / "VERSION").read_text().strip()
    cfg = tomllib.loads(fetch_config(version))

    glob = []
    glob += convert_allowlists(cfg.get("allowlist"), "global")
    glob += convert_allowlists(cfg.get("allowlists"), "global")

    rules = []
    for r in cfg["rules"]:
        if "regex" not in r:
            continue
        rid = r["id"]
        al = convert_allowlists(r.get("allowlists"), rid)
        al += convert_allowlists(r.get("allowlist"), rid)
        rules.append(
            {
                "id": rid,
                "regex": r["regex"],
                "secretGroup": r.get("secretGroup", 0),
                "entropy": r.get("entropy", 0),
                "keywords": list(r.get("keywords", [])),
                "allowlists": al,
            }
        )
    rules.sort(key=lambda r: r["id"])

    def line(v):
        return json.dumps(v, separators=(",", ":"), sort_keys=True, ensure_ascii=False)

    out = (
        f'{{"version":{line(version)},\n'
        f' "allowlists":{line(glob)},\n'
        ' "rules":[\n'
        + ",\n".join(line(r) for r in rules)
        + "\n]}\n"
    )
    OUT.write_text(out, encoding="utf-8")


main()
