#!/usr/bin/env python3
import argparse
import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BIN_RE = re.compile(r"^(rootfs?_.*|root_.*)\.bin$", re.IGNORECASE)


def load_versions(path: Path):
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def find_version_dirs(base: Path, version: str):
    return sorted([p for p in base.iterdir() if p.is_dir() and p.name.startswith(version + "_")])


def find_bins(version_dir: Path):
    bins = []
    for p in version_dir.rglob("*.bin"):
        if BIN_RE.match(p.name):
            bins.append(p)
    return sorted(bins)


def ensure_extracted(bin_path: Path, extractions_dir: Path):
    out_dir = extractions_dir / f"{bin_path.name}.extracted"
    if out_dir.exists() and any(out_dir.rglob("squashfs-root")):
        return out_dir

    # Clear stale binwalk artifacts from previous partial attempts.
    stale_link = extractions_dir / bin_path.name
    if stale_link.exists() or stale_link.is_symlink():
        stale_link.unlink()
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)

    cmd = ["binwalk", "-e", str(bin_path), "-C", str(extractions_dir)]
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

    # Important: detect with_xref before no_xref
    if "Xref EA:" in section:
        return "found_with_xref"
    if "Xrefs: none" in section:
        return "found_no_xref"
    if "Not found." in section:
        return "not_found"
    return "unknown"


def write_summary(extractions_dir: Path, rows):
    tsv = extractions_dir / "ha_master_all_versions_summary.txt"
    with tsv.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write("\t".join(row) + "\n")

    md = extractions_dir / "ha_master_all_versions_summary.md"
    with md.open("w", encoding="utf-8") as f:
        f.write("# ha_master system_run / system_command summary\n\n")
        f.write("| Version | system_run | system_command | report |\n")
        f.write("| --- | --- | --- | --- |\n")
        for version_dir, status, info in rows:
            if status != "ok":
                f.write(f"| {version_dir} | {status} | {status} | {info} |\n")
                continue
            report_path = Path(info)
            run_state = parse_report_state(report_path, "system_run")
            cmd_state = parse_report_state(report_path, "system_command")
            f.write(f"| {version_dir} | {run_state} | {cmd_state} | {report_path} |\n")


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
            print(f"[run_batch] dependency error: {err}", file=sys.stderr, flush=True)
        raise SystemExit(2)

    if not shutil.which("jefferson"):
        print(
            "[run_batch] warning: `jefferson` is missing from PATH; JFFS2 extraction will fail. "
            "Install with: python3 -m pip install jefferson",
            file=sys.stderr,
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser(description="Extract and analyze ha_master across versions")
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--versions-file", type=Path, default=Path(__file__).resolve().parent.parent / "VERSIONS.txt")
    parser.add_argument("--original-dir", type=Path, default=None, help="Default: <project-root>/original/M2")
    parser.add_argument("--extractions-dir", type=Path, default=None, help="Default: <project-root>/extractions")
    parser.add_argument("--idat", type=Path, default=Path("/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"))
    parser.add_argument("--ida-script", type=Path, default=Path(__file__).resolve().parent / "ida_system_strings.py")
    parser.add_argument("--extract-workers", type=int, default=min(6, os.cpu_count() or 1))
    parser.add_argument("--ida-workers", type=int, default=min(3, os.cpu_count() or 1))
    parser.add_argument("--version", type=str, default=None, help="Only process one major version prefix, e.g. 4.3.7")
    args = parser.parse_args()
    check_dependencies(args.idat)

    original_dir = args.original_dir or (args.project_root / "original" / "M2")
    extractions_dir = args.extractions_dir or (args.project_root / "extractions")
    extractions_dir.mkdir(parents=True, exist_ok=True)

    versions = load_versions(args.versions_file)
    if args.version:
        versions = [v for v in versions if v == args.version]

    version_dirs = []
    for v in versions:
        version_dirs.extend(find_version_dirs(original_dir, v))

    bins = []
    rows = []

    for vd in version_dirs:
        b = find_bins(vd)
        if not b:
            rows.append((vd.name, "bin_not_found", str(vd)))
            continue
        for one in b:
            bins.append((vd.name, one))

    def do_extract(item):
        version_dir_name, bin_path = item
        ext_dir = ensure_extracted(bin_path, extractions_dir)
        return (version_dir_name, bin_path, ext_dir)

    extracted = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.extract_workers) as ex:
        futures = [ex.submit(do_extract, it) for it in bins]
        for fut in concurrent.futures.as_completed(futures):
            version_dir_name, bin_path, ext_dir = fut.result()
            if not ext_dir:
                rows.append((version_dir_name, "extract_failed", str(bin_path)))
                continue
            extracted.append((version_dir_name, bin_path, ext_dir))

    jobs = []
    for version_dir_name, _, ext_dir in extracted:
        ha = find_ha_master(ext_dir)
        if not ha:
            rows.append((version_dir_name, "ha_master_not_found", str(ext_dir)))
            continue
        report_path = extractions_dir / f"ha_master_{version_dir_name}_report.md"
        log_path = extractions_dir / f"ida_{version_dir_name}.log"
        jobs.append((version_dir_name, ha, report_path, log_path))

    def do_ida(job):
        version_dir_name, ha, report_path, log_path = job
        run_ida(args.idat, args.ida_script, ha, report_path, log_path)
        if report_path.exists():
            return (version_dir_name, "ok", str(report_path))
        return (version_dir_name, "ida_failed", str(log_path))

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.ida_workers) as ex:
        futures = [ex.submit(do_ida, j) for j in jobs]
        for fut in concurrent.futures.as_completed(futures):
            rows.append(fut.result())

    rows = sorted(rows, key=lambda x: x[0])
    write_summary(extractions_dir, rows)
    print(extractions_dir / "ha_master_all_versions_summary.txt")
    print(extractions_dir / "ha_master_all_versions_summary.md")


if __name__ == "__main__":
    main()
