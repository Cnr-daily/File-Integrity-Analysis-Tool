# Log Integrity Checker

A standalone Python CLI for detecting changes to log files with SHA-256.

## Features

- Accepts one log file or a directory.
- Optional recursive directory scanning.
- Computes SHA-256 hashes for files.
- First use automatically creates a baseline.
- Subsequent runs report:
  - modified files
  - deleted files
  - newly discovered files
- Manual baseline re-initialization with `--reinitialize`.
- Baseline is stored in a per-user application/state directory with restrictive POSIX permissions (`0700` directory and `0600` file).
- `--all-files` can be used when logs do not have conventional extensions.

## Usage

```text
python log_integrity.py C:\Logs\application.log
python log_integrity.py C:\Logs
python log_integrity.py C:\Logs --recursive
python log_integrity.py C:\Logs --recursive --all-files
python log_integrity.py C:\Logs --reinitialize
python log_integrity.py --show-baseline
```

### Exit codes

- `0`: no integrity discrepancy requiring action was found.
- `1`: a file was modified or deleted.
- `2`: input/configuration error.

## Important security note

The baseline itself must be protected. If an attacker can modify both a log file and its baseline, they can potentially hide tampering. For high-assurance environments, keep the baseline on a separate protected system, use OS access controls, or add a cryptographically protected/HMAC-signed baseline stored independently from the monitored logs.
