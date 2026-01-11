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


def _cluster_key(
    f: Dict[str, Any],
    group_fields: List[str],
    record_prefix_len: int,
) -> Tuple[Optional[str], ...]:
    out: List[Optional[str]] = []
    for field in group_fields:
        if field == "recordBytes":
            out.append(_prefix(_get(f, "recordBytes"), record_prefix_len))
        else:
            out.append(_get(f, field))
    return tuple(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Cluster DOSRE LE fixups JSON by common fields.")
    ap.add_argument("json", type=Path, help="Path to -LEFIXUPSJSON output")
    ap.add_argument("--kind", default="unknown", help="Filter by targetKind (default: unknown). Use '*' for all.")
    ap.add_argument(
        "--group",
        default="type,flags",
        help="Comma-separated fields to group by (default: type,flags). Useful extras: specU16,specU16b,recordBytes",
    )
    ap.add_argument("--prefix", type=int, default=8, help="RecordBytes prefix length (hex chars, default: 8)")
    ap.add_argument("--top", type=int, default=25, help="Number of clusters to print (default: 25)")
    ap.add_argument("--samples", type=int, default=3, help="Samples per cluster (default: 3)")
    ap.add_argument(
        "--show",
        default="site,recordStreamOffset,siteValue32,instructionLinear,delta",
        help="Comma-separated sample fields to show",
    )
    ap.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Write a machine-readable cluster summary JSON to this path",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable cluster summary JSON to stdout (disables human output)",
    )
    args = ap.parse_args()

    doc = _load_json(args.json)
    all_fixups = list(_iter_fixups(doc))

    want_kind = args.kind
    if want_kind != "*":
        fixups = [f for f in all_fixups if (f.get("targetKind") or "unknown") == want_kind]
    else:
        fixups = all_fixups

    group_fields = [x.strip() for x in str(args.group).split(",") if x.strip()]
    # Normalize some common aliases.
    aliases = {
        "rec": "recordBytes",
        "record": "recordBytes",
        "spec0": "specU16",
        "spec1": "specU16b",
    }
    group_fields = [aliases.get(x, x) for x in group_fields]

    key_to_fixups: Dict[Tuple[Optional[str], ...], List[Dict[str, Any]]] = defaultdict(list)
    for f in fixups:
        key_to_fixups[_cluster_key(f, group_fields, args.prefix)].append(f)

    counts = Counter({k: len(v) for k, v in key_to_fixups.items()})

    print(f"input: {doc.get('input')}")
    print(f"fixups total: {len(all_fixups)}")
    print(f"fixups filtered: {len(fixups)} (targetKind={want_kind})")
    print(f"clusters: {len(counts)}")

    show_fields = [x.strip() for x in str(args.show).split(",") if x.strip()]

    # Build deterministic JSON summary (useful for diffs).
    summary: Dict[str, Any] = {
        "input": doc.get("input"),
        "fixupCount": len(all_fixups),
        "filteredFixupCount": len(fixups),
        "targetKind": want_kind,
        "group": group_fields,
        "recordBytesPrefixLen": int(args.prefix) if "recordBytes" in group_fields else 0,
        "clusterCount": len(counts),
        "clusters": [],
    }

    # Deterministic ordering: count desc, then key values.
    ordered_keys = sorted(
        counts.items(),
        key=lambda kv: (
            -kv[1],
            tuple("" if x is None else str(x) for x in kv[0]),
        ),
    )

    total_n = max(1, len(fixups))
    cum = 0
    for key, n in ordered_keys:
        cum += n
        entry: Dict[str, Any] = {"count": n, "key": {}}
        for i, field in enumerate(group_fields):
            entry["key"][field] = key[i]

        # Stable bucket id for diffs/automation.
        entry["id"] = "|".join(f"{field}={entry['key'][field]}" for field in group_fields)

        # Percentages relative to the filtered set.
        entry["percent"] = round(n / total_n, 6)
        entry["cumulativePercent"] = round(cum / total_n, 6)

        summary["clusters"].append(entry)

    if args.json_out is not None or args.json:
        payload = json.dumps(summary, indent=2, sort_keys=True)
        if args.json:
            print(payload)
        if args.json_out is not None:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(payload + "\n", encoding="utf-8")
        if args.json:
            return 0

    def fmt_key(k: Tuple[Optional[str], ...]) -> str:
        parts = []
        for i, field in enumerate(group_fields):
            parts.append(f"{field}={k[i]}")
        return " ".join(parts)

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
