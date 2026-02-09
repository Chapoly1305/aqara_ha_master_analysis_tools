# ha_master Analysis Toolkit (No Firmware Included)

This repository contains automation scripts and documentation only.
It does not include firmware binaries, extracted rootfs content, IDA databases, logs, or previous results.

## Source Repository

- SSH: `git@github.com:Chapoly1305/AqaraM1SM2fw.git`
- HTTPS: `https://github.com/Chapoly1305/AqaraM1SM2fw.git`

## Included Files

- `scripts/run_all_firmware.py` (main pipeline)
- `scripts/run_batch.py` (legacy version-driven pipeline)
- `scripts/ida_system_strings.py` (IDA headless script)
- `README.md`

## Goal

Extract candidate firmware bins, locate `ha_master`, and run IDA headless analysis for:
- `system_run`
- `system_command`

## Requirements

- Python 3.9+
- `binwalk` in `PATH`
- `jefferson` in `PATH` (needed for JFFS2 extraction, e.g. some G2 images)
- IDA Pro headless binary (`idat`)
- Firmware tree available locally

## Main Pipeline: run_all_firmware.py

### Default Layout

- Default firmware input: `<project-root>/stock/...`
- Default output root: `<project-root>/extractions/...`
- Per-run outputs: `<project-root>/extractions/runs/<run-tag>/...`

Note: `--original-dir` is still accepted, but it is a deprecated alias of `--firmware-dir`.

### Quick Start

```bash
python3 scripts/run_all_firmware.py \
  --project-root /path/to/AqaraM1SM2fw \
  --idat /path/to/idat
```

On macOS:

```bash
python3 scripts/run_all_firmware.py \
  --project-root /path/to/AqaraM1SM2fw \
  --idat "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"
```

Run a specific firmware tree with isolated namespace:

```bash
python3 scripts/run_all_firmware.py \
  --project-root /path/to/AqaraM1SM2fw \
  --firmware-dir /path/to/AqaraM1SM2fw/stock/M2 \
  --idat "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat" \
  --run-tag stock_M2
```

### Typical HPC Usage

```bash
python3 scripts/run_all_firmware.py \
  --project-root /data/AqaraM1SM2fw \
  --firmware-dir /data/AqaraM1SM2fw/stock \
  --idat /opt/ida/idat \
  --extract-workers 16 \
  --ida-workers 8 \
  --log-file /data/logs/ha_master_run_all.log
```

### Useful Options

- `--firmware-dir /path/to/stock_or_original`
- `--original-dir /path/to/stock_or_original` (deprecated alias)
- `--extractions-dir /path/to/extractions`
- `--bin-regex '^(rootfs?_.*|root_.*)\\.bin$'`
- `--single-bin /path/to/one.bin`
- `--run-tag stock_M2` (recommended for run isolation)
- `--log-file /path/to/run.log`
- `--binwalk-recursive` (default enabled; uses `binwalk -Me`)
- `--no-binwalk-recursive` (uses `binwalk -e`)

### Outputs

Generated in `<project-root>/extractions/runs/<run-tag>/`:

- `reports/ha_master_<source_id>_report.md`
- `logs/ida_<source_id>.log`
- `summaries/ha_master_all_firmware_summary.csv`
- `summaries/ha_master_all_firmware_summary.md`

CSV columns:
`source_bin,system_run,system_command,status,report_or_info`

## Legacy Pipeline: run_batch.py

This script is version-list driven and oriented to `original/M2` style layouts.

Default behavior:
- reads versions from `<project-root>/VERSIONS.txt`
- scans `<project-root>/original/M2`
- writes outputs directly under `<project-root>/extractions`

Example:

```bash
python3 scripts/run_batch.py \
  --project-root /path/to/AqaraM1SM2fw \
  --original-dir /path/to/AqaraM1SM2fw/original/M2 \
  --idat "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"
```

Optional single-version filter:

```bash
python3 scripts/run_batch.py \
  --project-root /path/to/AqaraM1SM2fw \
  --version 4.3.7
```

Primary outputs:
- `<extractions-dir>/ha_master_all_versions_summary.txt`
- `<extractions-dir>/ha_master_all_versions_summary.md`

## Classification Logic

Summary classification checks `Xref EA:` before `Xrefs: none` to avoid false `found_no_xref` when real xrefs exist.
