# ha_master Analysis Toolkit (No Firmware Included)

This repository contains automation scripts and documentation only.
It does not include firmware binaries, extracted rootfs content, IDA databases, logs, or previous results.

## Source Repository

- SSH: `git@github.com:Chapoly1305/AqaraM1SM2fw.git`
- HTTPS: `https://github.com/Chapoly1305/AqaraM1SM2fw.git`

## Included Files

- `scripts/run_all_firmware.py` (main pipeline)
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

- Default base dir (`project-root`): current working directory
- Default firmware input: `<project-root>/stock/...`
- Default output root: `<project-root>/extractions/<dataset-name>/...`
- Per-run outputs: `<project-root>/extractions/runs/<run-tag>/...`
- Persisted extracted binaries: `<run-root>/ha_master_cache/...` (or `--ha-master-dir`)
- Local temporary extraction root: `<project-root>/.tmp/...` (or `--temp-root`)

### Extraction Strategy

- Each firmware bin is extracted in a `tempfile` temporary directory.
- Only the discovered `ha_master` file is copied to the persistent cache directory.
- Temporary extraction directories are removed automatically after each bin.
- If cached `ha_master` already exists for a bin, binwalk is skipped.

### Quick Start

```bash
python3 scripts/run_all_firmware.py \
  --idat /path/to/idat
```

On macOS:

```bash
python3 scripts/run_all_firmware.py \
  --idat "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"
```

Run a specific firmware tree with isolated namespace:

```bash
python3 scripts/run_all_firmware.py \
  --firmware-dir /path/to/AqaraM1SM2fw/stock/M2 \
  --idat "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat" \
  --run-tag stock_M2
```

### Typical HPC Usage

```bash
python3 scripts/run_all_firmware.py \
  --firmware-dir /data/AqaraM1SM2fw/stock \
  --idat /opt/ida/idat \
  --extract-workers 16 \
  --ida-workers 8 \
  --log-file /data/logs/ha_master_run_all.log
```

### Useful Options

- `--firmware-dir /path/to/stock`
- `--extractions-dir /path/to/extractions`
- `--project-root /path/to/base` (optional, default: current directory)
- `--single-bin /path/to/one.bin`
- `--run-tag stock_M2` (optional; auto defaults to `stock_all` or `stock_<model>`)
- `--log-file /path/to/run.log`
- `--ha-master-dir /path/to/persisted_ha_master`
- `--temp-root /path/to/local_tmp_root`
- `--binwalk-recursive` (default enabled; uses `binwalk -Me`)
- `--no-binwalk-recursive` (uses `binwalk -e`)

### Outputs

Generated in `<project-root>/extractions/runs/<run-tag>/`:

- `ha_master_cache/<source_id>/ha_master` (persisted binaries for IDA input)
- `reports/ha_master_<source_id>_report.md`
- `logs/ida_<source_id>.log`
- `summaries/ha_master_all_firmware_summary.csv`
- `summaries/ha_master_all_firmware_summary.md`

CSV columns:
`source_bin,system_run,system_command,status,report_or_info`

## Classification Logic

Summary classification checks `Xref EA:` before `Xrefs: none` to avoid false `found_no_xref` when real xrefs exist.
