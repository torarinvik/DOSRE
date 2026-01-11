#!/usr/bin/env python3
"""Cluster LE fixups from DOSRE's -LEFIXUPSJSON export.

Usage:
  python tools/cluster_fixups.py Artifacts/test-exports/HELLO.fixups.json

By default, clusters only fixups with targetKind == "unknown".
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _get(d: Dict[str, Any], key: str) -> Optional[Any]:
    v = d.get(key)
    return v if v is not None else None


def _prefix(s: Optional[str], n: int) -> Optional[str]:
    if not s:
        return None
    return s[:n]


def _iter_fixups(doc: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    fixups = doc.get("fixups")
    if not isinstance(fixups, list):
        return []
    return fixups


def _cluster_key(f: Dict[str, Any], record_prefix_len: int) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    return (
        _get(f, "type"),
        _get(f, "flags"),
        _get(f, "specU16"),
        _get(f, "specU16b"),
        _prefix(_get(f, "recordBytes"), record_prefix_len),
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Cluster DOSRE LE fixups JSON by common fields.")
    ap.add_argument("json", type=Path, help="Path to -LEFIXUPSJSON output")
    ap.add_argument("--kind", default="unknown", help="Filter by targetKind (default: unknown). Use '*' for all.")
    ap.add_argument("--prefix", type=int, default=8, help="RecordBytes prefix length (hex chars, default: 8)")
    ap.add_argument("--top", type=int, default=25, help="Number of clusters to print (default: 25)")
    ap.add_argument("--samples", type=int, default=3, help="Samples per cluster (default: 3)")
    ap.add_argument(
        "--show",
        default="site,recordStreamOffset,siteValue32,instructionLinear,delta",
        help="Comma-separated sample fields to show",
    )
    args = ap.parse_args()

    doc = _load_json(args.json)
    all_fixups = list(_iter_fixups(doc))

    want_kind = args.kind
    if want_kind != "*":
        fixups = [f for f in all_fixups if (f.get("targetKind") or "unknown") == want_kind]
    else:
        fixups = all_fixups

    key_to_fixups: Dict[Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]], List[Dict[str, Any]]] = defaultdict(list)
    for f in fixups:
        key_to_fixups[_cluster_key(f, args.prefix)].append(f)

    counts = Counter({k: len(v) for k, v in key_to_fixups.items()})

    print(f"input: {doc.get('input')}")
    print(f"fixups total: {len(all_fixups)}")
    print(f"fixups filtered: {len(fixups)} (targetKind={want_kind})")
    print(f"clusters: {len(counts)}")

    show_fields = [x.strip() for x in str(args.show).split(",") if x.strip()]

    def fmt_key(k: Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]) -> str:
        t, fl, s0, s1, pref = k
        return f"type={t} flags={fl} specU16={s0} specU16b={s1} recPrefix={pref}"

    printed = 0
    for key, n in counts.most_common(args.top):
        printed += 1
        print()
        print(f"#{printed}  count={n}  {fmt_key(key)}")
        # deterministic sample ordering
        sample_list = sorted(
            key_to_fixups[key],
            key=lambda f: (
                f.get("site") or "",
                f.get("recordStreamOffset") or 0,
            ),
        )
        for i, f in enumerate(sample_list[: args.samples]):
            parts = []
            for field in show_fields:
                parts.append(f"{field}={f.get(field)}")
            print(f"  sample{i+1}: " + " ".join(parts))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
