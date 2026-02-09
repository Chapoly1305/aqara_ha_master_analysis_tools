#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

DEFAULT_BIN_RE = r"^(rootfs?_.*|root_.*)\.bin$"


def safe_name(path_part: str) -> str:
    s = path_part.replace("/", "__").replace("\\", "__")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s.strip("_") or "root"


def run_tag_to_relpath(run_tag: str) -> Path:
    # Keep hierarchical tags like "original/M2", but block path traversal.
    p = Path(run_tag)
    parts = [x for x in p.parts if x not in ("", ".")]
    if any(x == ".." for x in parts):
        raise ValueError(f"invalid run-tag: {run_tag}")
    if not parts:
        raise ValueError("invalid run-tag: empty")
    return Path(*parts)


def find_bins(firmware_dir: Path, bin_regex: str):
    cre = re.compile(bin_regex, re.IGNORECASE)
    bins_by_bucket = defaultdict(list)
    for p in firmware_dir.rglob("*.bin"):
        rel = p.relative_to(firmware_dir)
        # stock/<model>/<firmware.bin> => bucket by file (each file is a version)
        # original/<model>/<version>/<part.bin> => bucket by version folder
        bucket = p if len(rel.parts) <= 2 else p.parent
        bins_by_bucket[bucket].append(p)

    selected = []
    matched_dirs = 0
    fallback_dirs = 0
    for bucket in sorted(bins_by_bucket.keys()):
        bucket_bins = sorted(bins_by_bucket[bucket])
        matched = [p for p in bucket_bins if cre.match(p.name)]
        if matched:
            matched_dirs += 1
            selected.extend(matched)
            continue
        fallback_dirs += 1
        selected.append(select_fallback_bin(bucket_bins))

    print(
        f"[run_all_firmware] candidate discovery: {len(bins_by_bucket)} buckets, "
        f"{matched_dirs} regex-hit buckets, {fallback_dirs} fallback buckets, {len(selected)} selected bins"
    )
    return sorted(selected)


def fallback_score(bin_path: Path):
    name = bin_path.name.lower()
    if name.startswith("rootfs"):
        cls = 0
    elif name.startswith("root_"):
        cls = 1
    elif name.startswith("ota") or "_ota_" in name:
        cls = 2
    elif "firmware" in name:
        cls = 3
    elif name.startswith("lumi.camera"):
        cls = 4
    else:
        cls = 5
    try:
        size = bin_path.stat().st_size
    except OSError:
        size = 0
    # Lower class first; larger size first; stable tie break by name.
    return (cls, -size, name)


def select_fallback_bin(parent_bins):
    return sorted(parent_bins, key=fallback_score)[0]


def ensure_extracted(bin_path: Path, firmware_dir: Path, work_root: Path, recursive: bool = True):
    rel_parent = bin_path.parent.relative_to(firmware_dir)
    source_bucket = work_root / rel_parent
    source_bucket.mkdir(parents=True, exist_ok=True)

    out_dir = source_bucket / f"{bin_path.name}.extracted"
    if out_dir.exists() and any(out_dir.rglob("squashfs-root")):
        return out_dir

    # Binwalk creates a symlink in the output directory and may fail on retries
    # after a partial extraction if stale artifacts remain.
    stale_link = source_bucket / bin_path.name
    if stale_link.exists() or stale_link.is_symlink():
        stale_link.unlink()
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)

    cmd = ["binwalk", "-Me" if recursive else "-e", str(bin_path), "-C", str(source_bucket)]
    subprocess.run(cmd, check=False)
    if out_dir.exists():
        return out_dir
    return None


def find_ha_master(extracted_dir: Path):
    for p in extracted_dir.rglob("ha_master"):
        if p.is_file():
            return p
    return None


def run_ida(idat: Path, ida_script: Path, ha_master: Path, report_path: Path, log_path: Path):
    cmd = [
        str(idat),
        f"-L{log_path}",
        "-A",
        f"-S{ida_script} {report_path}",
        str(ha_master),
    ]
    subprocess.run(cmd, check=False)


def parse_report_state(report_path: Path, key: str):
    text = report_path.read_text(encoding="utf-8", errors="ignore")
    m = re.search(rf"## `{re.escape(key)}`\n(.*?)(\n## `|\Z)", text, re.S)
    if not m:
        return "section_missing"
    section = m.group(1)

    # Detect positive first to avoid false negative classification
    if "Xref EA:" in section:
        return "found_with_xref"
    if "Xrefs: none" in section:
        return "found_no_xref"
    if "Not found." in section:
        return "not_found"
    return "unknown"


def write_summary(summary_rows, out_csv: Path, out_md: Path):
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    # Keep .txt filename for compatibility, but content is CSV as requested.
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source_bin", "system_run", "system_command", "status", "report_or_info"])
        for row in summary_rows:
            if row["status"] != "ok":
                w.writerow([row["source_bin"], row["status"], row["status"], row["status"], row["info"]])
                continue
            report = Path(row["info"])
            run_state = parse_report_state(report, "system_run")
            cmd_state = parse_report_state(report, "system_command")
            w.writerow([row["source_bin"], run_state, cmd_state, "ok", str(report)])

    with out_md.open("w", encoding="utf-8") as f:
        f.write("# ha_master Auto Analysis Summary\n\n")
        f.write("| source_bin | system_run | system_command | status | report_or_info |\n")
        f.write("| --- | --- | --- | --- | --- |\n")
        for row in summary_rows:
            if row["status"] != "ok":
                f.write(
                    f"| {row['source_bin']} | {row['status']} | {row['status']} | {row['status']} | {row['info']} |\n"
                )
                continue
            report = Path(row["info"])
            run_state = parse_report_state(report, "system_run")
            cmd_state = parse_report_state(report, "system_command")
            f.write(
                f"| {row['source_bin']} | {run_state} | {cmd_state} | ok | {report} |\n"
            )


def setup_log_file(log_file):
    if not log_file:
        return
    log_path = log_file.expanduser().resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(str(log_path), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o644)
    os.dup2(log_fd, 1)
    os.dup2(log_fd, 2)
    if log_fd > 2:
        os.close(log_fd)
    sys.stdout = os.fdopen(1, "w", buffering=1, encoding="utf-8", errors="replace", closefd=False)
    sys.stderr = os.fdopen(2, "w", buffering=1, encoding="utf-8", errors="replace", closefd=False)
    print(f"[run_all_firmware] logging to {log_path}", flush=True)


def check_dependencies(idat: Path):
    errors = []
    if not shutil.which("binwalk"):
        errors.append("`binwalk` is not in PATH")
    if not idat.exists():
        errors.append(f"`idat` does not exist: {idat}")
    elif not os.access(idat, os.X_OK):
        errors.append(f"`idat` is not executable: {idat}")
    if errors:
        for err in errors:
            print(f"[run_all_firmware] dependency error: {err}", file=sys.stderr, flush=True)
        raise SystemExit(2)

    if not shutil.which("jefferson"):
        print(
            "[run_all_firmware] warning: `jefferson` is missing from PATH; JFFS2 extraction will fail. "
            "Install with: python3 -m pip install jefferson",
            file=sys.stderr,
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser(
        description="Extract firmware bins and analyze ha_master with IDA headless"
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--firmware-dir",
        type=Path,
        default=None,
        help="Default: <project-root>/stock",
    )
    parser.add_argument(
        "--original-dir",
        dest="firmware_dir",
        type=Path,
        default=None,
        help="Deprecated alias for --firmware-dir",
    )
    parser.add_argument("--extractions-dir", type=Path, default=None, help="Default: <project-root>/extractions")
    parser.add_argument(
        "--idat",
        type=Path,
        default=Path("/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"),
        help="IDA headless binary path",
    )
    parser.add_argument(
        "--ida-script",
        type=Path,
        default=Path(__file__).resolve().parent / "ida_system_strings.py",
    )
    parser.add_argument("--bin-regex", type=str, default=DEFAULT_BIN_RE)
    parser.set_defaults(binwalk_recursive=True)
    parser.add_argument(
        "--binwalk-recursive",
        dest="binwalk_recursive",
        action="store_true",
        help="Use recursive extraction via binwalk -Me (default: enabled).",
    )
    parser.add_argument(
        "--no-binwalk-recursive",
        dest="binwalk_recursive",
        action="store_false",
        help="Disable recursive extraction and use one-level binwalk -e.",
    )
    parser.add_argument("--extract-workers", type=int, default=min(8, os.cpu_count() or 1))
    parser.add_argument("--ida-workers", type=int, default=min(4, os.cpu_count() or 1))
    parser.add_argument("--single-bin", type=Path, default=None, help="Only process one firmware bin")
    parser.add_argument(
        "--run-tag",
        type=str,
        default=None,
        help="Output namespace under extractions/runs/<run-tag>. Example: original_M2, original_all",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Optional log file path. Parent directories are auto-created.",
    )
    args = parser.parse_args()
    setup_log_file(args.log_file)
    check_dependencies(args.idat)

    project_root = args.project_root.resolve()
    firmware_dir = (args.firmware_dir or (project_root / "stock")).resolve()
    extractions_dir = (args.extractions_dir or (project_root / "extractions")).resolve()
    if args.run_tag:
        run_tag_rel = run_tag_to_relpath(args.run_tag)
    else:
        try:
            rel_firmware = firmware_dir.relative_to(project_root)
            run_tag_rel = rel_firmware
        except ValueError:
            run_tag_rel = Path(safe_name(str(firmware_dir)))
    run_root = extractions_dir / "runs" / run_tag_rel
    reports_dir = run_root / "reports"
    logs_dir = run_root / "logs"
    summaries_dir = run_root / "summaries"
    reports_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    summaries_dir.mkdir(parents=True, exist_ok=True)

    if args.single_bin:
        bins = [args.single_bin.resolve()]
    else:
        bins = find_bins(firmware_dir, args.bin_regex)

    summary = []

    def extract_job(bin_path: Path):
        rel = bin_path.relative_to(project_root) if bin_path.is_relative_to(project_root) else bin_path
        out = ensure_extracted(bin_path, firmware_dir, run_root, recursive=args.binwalk_recursive)
        return rel, bin_path, out

    extracted = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.extract_workers) as ex:
        futures = [ex.submit(extract_job, b) for b in bins]
        for fut in concurrent.futures.as_completed(futures):
            rel, bin_path, out = fut.result()
            source_bin = str(rel)
            if not out:
                summary.append({"source_bin": source_bin, "status": "extract_failed", "info": str(bin_path)})
                continue
            extracted.append((source_bin, bin_path, out))

    jobs = []
    for source_bin, bin_path, out in extracted:
        ha = find_ha_master(out)
        if not ha:
            summary.append({"source_bin": source_bin, "status": "ha_master_not_found", "info": str(out)})
            continue

        try:
            rel_for_id = bin_path.relative_to(firmware_dir)
        except ValueError:
            rel_for_id = bin_path.name
        bin_id = safe_name(str(rel_for_id).replace(".bin", ""))
        report = reports_dir / f"ha_master_{bin_id}_report.md"
        log = logs_dir / f"ida_{bin_id}.log"
        jobs.append((source_bin, ha, report, log))

    def ida_job(item):
        source_bin, ha, report, log = item
        run_ida(args.idat, args.ida_script, ha, report, log)
        if report.exists():
            return {"source_bin": source_bin, "status": "ok", "info": str(report)}
        return {"source_bin": source_bin, "status": "ida_failed", "info": str(log)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.ida_workers) as ex:
        futures = [ex.submit(ida_job, j) for j in jobs]
        for fut in concurrent.futures.as_completed(futures):
            summary.append(fut.result())

    summary = sorted(summary, key=lambda x: x["source_bin"])
    out_csv = summaries_dir / "ha_master_all_firmware_summary.csv"
    out_md = summaries_dir / "ha_master_all_firmware_summary.md"
    write_summary(summary, out_csv, out_md)

    print(out_csv)
    print(out_md)


if __name__ == "__main__":
    main()
