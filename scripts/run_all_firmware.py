#!/usr/bin/env python3
import argparse
import concurrent.futures
import csv
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Optional

def safe_name(path_part: str) -> str:
    s = path_part.replace("/", "__").replace("\\", "__")
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s.strip("_") or "root"


def run_tag_to_relpath(run_tag: str) -> Path:
    # Keep hierarchical tags like "stock/M2", but block path traversal.
    p = Path(run_tag)
    parts = [x for x in p.parts if x not in ("", ".")]
    if any(x == ".." for x in parts):
        raise ValueError(f"invalid run-tag: {run_tag}")
    if not parts:
        raise ValueError("invalid run-tag: empty")
    return Path(*parts)


def infer_dataset_name(firmware_dir: Path):
    if firmware_dir.name.lower() == "stock" and firmware_dir.parent.name:
        return safe_name(firmware_dir.parent.name)
    if firmware_dir.parent.name.lower() == "stock" and firmware_dir.parent.parent.name:
        return safe_name(firmware_dir.parent.parent.name)
    return safe_name(firmware_dir.name)


def infer_run_tag(firmware_dir: Path):
    if firmware_dir.name.lower() == "stock":
        return Path("stock_all")
    if firmware_dir.parent.name.lower() == "stock":
        return Path(f"stock_{safe_name(firmware_dir.name)}")
    return Path(safe_name(firmware_dir.name))


def find_bins(firmware_dir: Path):
    all_bins = sorted([p for p in firmware_dir.rglob("*.bin") if p.is_file()])
    print(
        f"[run_all_firmware] candidate discovery: {len(all_bins)} total bins, "
        f"{len(all_bins)} selected bins"
    )
    return all_bins


def bin_id_for_path(bin_path: Path, firmware_dir: Path):
    try:
        rel_for_id = bin_path.relative_to(firmware_dir)
    except ValueError:
        rel_for_id = bin_path.name
    return safe_name(str(rel_for_id).replace(".bin", ""))


def find_ha_master(extracted_dir: Path):
    for p in extracted_dir.rglob("ha_master"):
        if p.is_file():
            return p
    return None


def resolve_path(p: Optional[Path], base: Path):
    if p is None:
        return None
    p = p.expanduser()
    if p.is_absolute():
        return p.resolve()
    return (base / p).resolve()


def prepare_ha_master(
    bin_path: Path,
    firmware_dir: Path,
    ha_master_dir: Path,
    temp_root: Optional[Path] = None,
    recursive: bool = True,
):
    bin_id = bin_id_for_path(bin_path, firmware_dir)
    keep_dir = ha_master_dir / bin_id
    keep_path = keep_dir / "ha_master"

    if keep_path.exists() and keep_path.is_file() and keep_path.stat().st_size > 0:
        return keep_path, "cached"

    if keep_path.exists() and not keep_path.is_file():
        if keep_path.is_dir():
            shutil.rmtree(keep_path, ignore_errors=True)
        else:
            keep_path.unlink(missing_ok=True)

    try:
        tmp_ctx = tempfile.TemporaryDirectory(
            prefix="ha_master_extract_",
            dir=str(temp_root) if temp_root else None,
        )
    except Exception:
        return None, "tempdir_failed"

    with tmp_ctx as tmp:
        tmp_dir = Path(tmp)
        cmd = ["binwalk", "-Me" if recursive else "-e", str(bin_path), "-C", str(tmp_dir)]
        subprocess.run(cmd, check=False)

        out_dir = tmp_dir / f"{bin_path.name}.extracted"
        if not out_dir.exists():
            return None, "extract_failed"

        ha = find_ha_master(out_dir)
        if not ha:
            return None, "ha_master_not_found"

        try:
            keep_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ha, keep_path)
        except OSError:
            return None, "persist_failed"
        return keep_path, "extracted"


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


def check_dependencies(idat: Path, require_binwalk: bool = True):
    errors = []
    if require_binwalk and not shutil.which("binwalk"):
        errors.append("`binwalk` is not in PATH")
    if not idat.exists():
        errors.append(f"`idat` does not exist: {idat}")
    elif not os.access(idat, os.X_OK):
        errors.append(f"`idat` is not executable: {idat}")
    if errors:
        for err in errors:
            print(f"[run_all_firmware] dependency error: {err}", file=sys.stderr, flush=True)
        raise SystemExit(2)

    if require_binwalk and not shutil.which("jefferson"):
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
    parser.add_argument(
        "--project-root",
        type=Path,
        default=None,
        help="Base directory for defaults. Default: current working directory.",
    )
    parser.add_argument(
        "--firmware-dir",
        type=Path,
        default=None,
        help="Default: <project-root>/stock",
    )
    parser.add_argument(
        "--extractions-dir",
        type=Path,
        default=None,
        help="Default: <project-root>/extractions/<dataset-name>",
    )
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
        help="Output namespace under extractions/runs/<run-tag>. Example: stock_M2, stock_all",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="Optional log file path. Parent directories are auto-created.",
    )
    parser.add_argument(
        "--ha-master-dir",
        type=Path,
        default=None,
        help="Directory for persisted ha_master binaries. Default: <run-root>/ha_master_cache",
    )
    parser.add_argument(
        "--temp-root",
        type=Path,
        default=None,
        help="Local temp root for binwalk extraction. Default: <project-root>/.tmp",
    )
    args = parser.parse_args()
    setup_log_file(args.log_file)

    project_root = (args.project_root or Path.cwd()).resolve()
    firmware_dir = resolve_path(args.firmware_dir, project_root) or (project_root / "stock")
    dataset_name = infer_dataset_name(firmware_dir)
    extractions_dir = resolve_path(args.extractions_dir, project_root) or (project_root / "extractions" / dataset_name)
    temp_root = resolve_path(args.temp_root, project_root) or (project_root / ".tmp")
    temp_root.mkdir(parents=True, exist_ok=True)
    if args.run_tag:
        run_tag_rel = run_tag_to_relpath(args.run_tag)
    else:
        run_tag_rel = infer_run_tag(firmware_dir)
    run_root = extractions_dir / "runs" / run_tag_rel
    reports_dir = run_root / "reports"
    logs_dir = run_root / "logs"
    summaries_dir = run_root / "summaries"
    if args.ha_master_dir:
        ha_master_dir = resolve_path(args.ha_master_dir, project_root)
    else:
        ha_master_dir = run_root / "ha_master_cache"
    reports_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    summaries_dir.mkdir(parents=True, exist_ok=True)
    ha_master_dir.mkdir(parents=True, exist_ok=True)

    if args.single_bin:
        bins = [args.single_bin.resolve()]
    else:
        bins = find_bins(firmware_dir)

    need_binwalk = False
    for b in bins:
        bin_id = bin_id_for_path(b, firmware_dir)
        keep_path = ha_master_dir / bin_id / "ha_master"
        if not (keep_path.exists() and keep_path.is_file() and keep_path.stat().st_size > 0):
            need_binwalk = True
            break
    check_dependencies(args.idat, require_binwalk=need_binwalk)

    summary = []

    def extract_job(bin_path: Path):
        rel = bin_path.relative_to(project_root) if bin_path.is_relative_to(project_root) else bin_path
        ha, prep_status = prepare_ha_master(
            bin_path,
            firmware_dir,
            ha_master_dir,
            temp_root=temp_root,
            recursive=args.binwalk_recursive,
        )
        return rel, bin_path, ha, prep_status

    extracted = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.extract_workers) as ex:
        futures = [ex.submit(extract_job, b) for b in bins]
        for fut in concurrent.futures.as_completed(futures):
            try:
                rel, bin_path, ha, prep_status = fut.result()
            except Exception as e:
                summary.append({"source_bin": "<internal>", "status": "extract_exception", "info": str(e)})
                continue
            source_bin = str(rel)
            if not ha:
                status = prep_status if prep_status in {
                    "extract_failed",
                    "ha_master_not_found",
                    "persist_failed",
                    "tempdir_failed",
                } else "extract_failed"
                summary.append({"source_bin": source_bin, "status": status, "info": str(bin_path)})
                continue
            extracted.append((source_bin, bin_path, ha))

    jobs = []
    for source_bin, bin_path, ha in extracted:
        bin_id = bin_id_for_path(bin_path, firmware_dir)
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
