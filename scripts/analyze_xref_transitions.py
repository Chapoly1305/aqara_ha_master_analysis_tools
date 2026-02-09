#!/usr/bin/env python3
import argparse
import csv
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Tuple


XREF = "found_with_xref"
NO_XREF = "found_no_xref"


@dataclass(frozen=True)
class Row:
    source_bin: str
    system_run: str
    system_command: str
    status: str
    report_or_info: str
    model: str
    version: Optional[str]


def parse_summary_md(path: Path) -> List[Row]:
    rows: List[Row] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.startswith("| "):
            continue
        if line.startswith("| ---"):
            continue
        parts = [p.strip() for p in line.split("|")[1:-1]]
        if len(parts) != 5:
            continue
        source_bin, system_run, system_command, status, report_or_info = parts
        if not source_bin.startswith("/"):
            continue
        model = extract_model(source_bin)
        version = extract_version(source_bin)
        rows.append(
            Row(
                source_bin=source_bin,
                system_run=system_run,
                system_command=system_command,
                status=status,
                report_or_info=report_or_info,
                model=model,
                version=version,
            )
        )
    return rows


def extract_model(source_bin: str) -> str:
    pp = PurePosixPath(source_bin)
    parts = list(pp.parts)
    try:
        stock_idx = parts.index("stock")
    except ValueError:
        return pp.parent.name or "unknown"

    if stock_idx + 2 < len(parts):
        candidate = parts[stock_idx + 1]
        if not candidate.endswith(".bin"):
            return candidate

    filename = pp.name
    m = re.search(r"_(lumi\.[^_]+)_AIOT_V", filename)
    if m:
        return m.group(1)
    m = re.search(r"(lumi\.[^_]+)", filename)
    if m:
        return m.group(1)
    return "root"


def extract_version(source_bin: str) -> Optional[str]:
    name = PurePosixPath(source_bin).name
    patterns = (
        r"_AIOT_V([0-9]+(?:\.[0-9]+){1,3})",
        r"_AIOT_V([0-9]+_[0-9]+_[0-9]+)",
        r"_AIOT_V([0-9]+)",
        r"lumi_dfu_([0-9]+(?:\.[0-9]+)*)",
        r"_model_([0-9]+(?:\.[0-9]+){1,5})",
        r"_([0-9]+(?:\.[0-9]+){1,5})_[0-9]{3,}(?:\.|_)",
        r"_V([0-9]+(?:\.[0-9]+)*)",
    )
    for pat in patterns:
        m = re.search(pat, name)
        if m:
            return m.group(1).replace("_", ".")
    return None


def version_sort_key(version: Optional[str]) -> Tuple:
    if version is None:
        return ((2, ""),)
    parts: List[Tuple[int, object]] = []
    for token in re.split(r"[.\-_]", version):
        if token.isdigit():
            parts.append((0, int(token)))
        else:
            parts.append((1, token))
    return tuple(parts)


def row_sort_key(row: Row) -> Tuple:
    return (version_sort_key(row.version), row.source_bin)


def unique_preserve(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def stable_no_xref_transition(rows: List[Row], field: str) -> Optional[Tuple[Optional[str], Optional[str], int]]:
    statuses = [getattr(r, field) for r in rows]
    xref_idx = [i for i, st in enumerate(statuses) if st == XREF]
    if not xref_idx:
        return None
    last_xref = max(xref_idx)
    if last_xref >= len(rows) - 1:
        return None
    tail = rows[last_xref + 1 :]
    if not tail:
        return None
    if all(getattr(r, field) == NO_XREF for r in tail):
        return rows[last_xref].version, tail[0].version, len(tail)
    return None


def analyze_model(rows: List[Row], field: str) -> Dict[str, object]:
    rows_with_version = [r for r in rows if r.version is not None]
    rows_sorted = sorted(rows_with_version, key=row_sort_key)
    first_xref_row = next((r for r in rows_sorted if getattr(r, field) == XREF), None)
    first_xref = first_xref_row.version if first_xref_row else None

    affected = [r for r in rows_sorted if getattr(r, field) != XREF]
    affected_versions = unique_preserve(
        f"{r.version or 'unknown'} ({getattr(r, field)})" for r in affected
    )
    unknown_affected = [r for r in rows if r.version is None and getattr(r, field) != XREF]
    transition = stable_no_xref_transition(rows_sorted, field)
    return {
        "total_versions": len(rows_sorted),
        "first_xref": first_xref,
        "affected_count": len(affected_versions),
        "affected_versions": affected_versions,
        "unknown_affected_count": len(unknown_affected),
        "transition": transition,
    }


def dataset_name_from_summary_path(summary_path: Path) -> str:
    parts = list(summary_path.parts)
    if "extractions" in parts:
        i = parts.index("extractions")
        if i + 1 < len(parts):
            return parts[i + 1]
    return summary_path.parent.name


def format_transition_text(transition: Optional[Tuple[Optional[str], Optional[str], int]]) -> str:
    if not transition:
        return "none"
    _after_ver, from_ver, _tail_count = transition
    return f">={from_ver}"


def summarize_dataset(summary_path: Path, rows: List[Row]) -> List[Dict[str, object]]:
    by_model: Dict[str, List[Row]] = {}
    for r in rows:
        by_model.setdefault(r.model, []).append(r)

    dataset = dataset_name_from_summary_path(summary_path)
    out: List[Dict[str, object]] = []
    for model in sorted(by_model.keys()):
        model_rows = by_model[model]
        run_stats = analyze_model(model_rows, "system_run")
        transition = run_stats["transition"]
        out.append(
            {
                "dataset": dataset,
                "model": model,
                "total_firmware": len(model_rows),
                "first_found_with_xref": run_stats["first_xref"] or "none",
                "non_found_with_xref_version_count": run_stats["affected_count"],
                "stable_found_no_xref": format_transition_text(transition),
                "non_found_with_xref_versions": "; ".join(run_stats["affected_versions"]),
                "stable_after_version": transition[0] if transition else "",
                "stable_from_version": transition[1] if transition else "",
                "stable_tail_versions": transition[2] if transition else 0,
            }
        )
    return out


def render_markdown_table(dataset: str, rows: List[Dict[str, object]]) -> str:
    out: List[str] = []
    out.append(f"## {dataset}")
    out.append("| Model | Total Firmware | First found_with_xref | Non found_with_xref Versions | Stable found_no_xref |")
    out.append("| --- | ---: | --- | ---: | --- |")
    for r in rows:
        out.append(
            f"| {r['model']} | {r['total_firmware']} | {r['first_found_with_xref']} | "
            f"{r['non_found_with_xref_version_count']} | {r['stable_found_no_xref']} |"
        )
    return "\n".join(out)


def write_detailed_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    headers = [
        "dataset",
        "model",
        "total_firmware",
        "first_found_with_xref",
        "non_found_with_xref_version_count",
        "stable_found_no_xref",
        "stable_after_version",
        "stable_from_version",
        "stable_tail_versions",
        "non_found_with_xref_versions",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate simple per-model summary tables and detailed CSV from firmware summary Markdown files."
    )
    parser.add_argument(
        "--summary",
        type=Path,
        action="append",
        required=True,
        help="Path to ha_master_all_firmware_summary.md (repeat for multiple files).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output Markdown path. If omitted, print to stdout.",
    )
    parser.add_argument(
        "--csv-output",
        type=Path,
        default=None,
        help="Detailed CSV output path. Default: <output-stem>.csv when --output is set.",
    )
    args = parser.parse_args()

    dataset_sections: List[str] = []
    csv_rows: List[Dict[str, object]] = []
    for sp in args.summary:
        sp = sp.expanduser().resolve()
        rows = parse_summary_md(sp)
        dataset_rows = summarize_dataset(sp, rows)
        if not dataset_rows:
            continue
        dataset = dataset_rows[0]["dataset"]
        dataset_sections.append(render_markdown_table(dataset, dataset_rows))
        csv_rows.extend(dataset_rows)

    report = "# Xref Transition Summary\n\n" + "\n\n".join(dataset_sections).rstrip() + "\n"
    if args.output:
        out_path = args.output.expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")
        print(out_path)
        csv_path = args.csv_output
        if csv_path is None:
            csv_path = out_path.with_suffix(".csv")
        csv_path = csv_path.expanduser().resolve()
        write_detailed_csv(csv_path, csv_rows)
        print(csv_path)
    else:
        print(report, end="")


if __name__ == "__main__":
    main()
