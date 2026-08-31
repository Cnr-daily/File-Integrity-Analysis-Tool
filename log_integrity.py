#!/usr/bin/env python3
"""
Log File Integrity Checker

Features:
- Accepts a single file or directory.
- Computes SHA-256 for each log file.
- First run creates a baseline in the user's configuration directory.
- Later runs compare current hashes against the baseline.
- Reports modified, deleted, and newly discovered files.
- Supports manual baseline re-initialization.

Usage:
    python log_integrity.py /path/to/log
    python log_integrity.py /path/to/logs
    python log_integrity.py /path/to/logs --recursive
    python log_integrity.py /path/to/logs --reinitialize
    python log_integrity.py --show-baseline
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

APP_NAME = "log-integrity-checker"
BASELINE_FILENAME = "baseline.json"

# Common log-like file extensions. Use --all-files to hash every regular file.
LOG_EXTENSIONS = {
    ".log", ".txt", ".out", ".err", ".trace", ".audit",
    ".jsonl", ".csv"
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_secure_baseline_dir() -> Path:
    """Return a per-user configuration directory and create it."""
    system = platform.system()

    if system == "Windows":
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if root:
            base = Path(root)
        else:
            base = Path.home() / "AppData" / "Local"
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))

    directory = base / APP_NAME
    directory.mkdir(parents=True, exist_ok=True)
    restrict_permissions(directory, is_directory=True)
    return directory


def restrict_permissions(path: Path, is_directory: bool = False) -> None:
    """
    Restrict permissions to the current user on POSIX.
    Windows ACLs are inherited from the user's profile location.
    """
    if os.name == "posix":
        try:
            os.chmod(path, 0o700 if is_directory else 0o600)
        except OSError:
            pass


def baseline_path() -> Path:
    return get_secure_baseline_dir() / BASELINE_FILENAME


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def is_log_file(path: Path, all_files: bool) -> bool:
    if not path.is_file():
        return False
    if all_files:
        return True
    return path.suffix.lower() in LOG_EXTENSIONS


def collect_files(input_path: Path, recursive: bool, all_files: bool) -> list[Path]:
    input_path = input_path.expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input does not exist: {input_path}")

    if input_path.is_file():
        return [input_path] if is_log_file(input_path, all_files) else []

    if recursive:
        candidates = input_path.rglob("*")
    else:
        candidates = input_path.glob("*")

    files = [p.resolve() for p in candidates if is_log_file(p, all_files)]
    return sorted(files, key=lambda p: str(p).lower())


def make_relative_key(path: Path, input_root: Path) -> str:
    """
    Store relative paths for directory baselines and absolute paths for
    single-file baselines, avoiding accidental collisions.
    """
    if input_root.is_dir():
        return path.relative_to(input_root).as_posix()
    return str(path)


def build_snapshot(files: Iterable[Path], input_root: Path) -> dict[str, dict[str, str]]:
    snapshot: dict[str, dict[str, str]] = {}

    for file_path in files:
        key = make_relative_key(file_path, input_root)
        try:
            snapshot[key] = {
                "sha256": sha256_file(file_path),
                "size": str(file_path.stat().st_size),
            }
        except OSError as exc:
            print(f"[ERROR] Could not hash {file_path}: {exc}", file=sys.stderr)

    return snapshot


def load_baseline() -> dict:
    path = baseline_path()
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict):
            raise ValueError("Baseline is not a JSON object.")
        return data
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"Could not read baseline {path}: {exc}") from exc


def save_baseline(input_path: Path, snapshot: dict) -> Path:
    path = baseline_path()
    payload = {
        "format_version": 1,
        "algorithm": "SHA-256",
        "created_utc": utc_now(),
        "input_root": str(input_path),
        "entries": snapshot,
    }

    temp = path.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())

    restrict_permissions(temp)
    os.replace(temp, path)
    restrict_permissions(path)
    return path


def compare_snapshots(expected: dict, current: dict) -> dict[str, list[str]]:
    expected_entries = expected.get("entries", {})
    current_entries = current

    expected_keys = set(expected_entries)
    current_keys = set(current_entries)

    modified = sorted(
        key for key in expected_keys & current_keys
        if expected_entries[key].get("sha256") != current_entries[key].get("sha256")
    )
    deleted = sorted(expected_keys - current_keys)
    added = sorted(current_keys - expected_keys)

    return {
        "modified": modified,
        "deleted": deleted,
        "added": added,
    }


def print_report(input_path: Path, current: dict, comparison: dict) -> int:
    print(f"\nIntegrity report: {input_path}")
    print(f"Algorithm: SHA-256")
    print(f"Files checked: {len(current)}")

    if comparison["modified"]:
        print("\n[TAMPERING SUSPECTED] Modified files:")
        for item in comparison["modified"]:
            print(f"  - {item}")

    if comparison["deleted"]:
        print("\n[WARNING] Files present in baseline but now missing:")
        for item in comparison["deleted"]:
            print(f"  - {item}")

    if comparison["added"]:
        print("\n[NOTICE] New files not present in baseline:")
        for item in comparison["added"]:
            print(f"  - {item}")

    if not any(comparison.values()):
        print("\n[OK] No differences detected.")

    return 1 if comparison["modified"] or comparison["deleted"] else 0


def reinitialize(input_path: Path, files: list[Path]) -> int:
    snapshot = build_snapshot(files, input_path)
    destination = save_baseline(input_path, snapshot)
    print(f"[OK] Baseline initialized for {len(snapshot)} file(s).")
    print(f"[OK] Stored at: {destination}")
    return 0


def show_baseline() -> int:
    path = baseline_path()
    if not path.exists():
        print(f"No baseline exists yet: {path}")
        return 0

    try:
        data = load_baseline()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect changes to log files using SHA-256 hashes."
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="A log file or directory containing log files."
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="When input is a directory, scan subdirectories recursively."
    )
    parser.add_argument(
        "--all-files",
        action="store_true",
        help="When input is a directory, include every regular file, not only log-like extensions."
    )
    parser.add_argument(
        "--reinitialize",
        action="store_true",
        help="Replace the stored baseline with the current hashes."
    )
    parser.add_argument(
        "--show-baseline",
        action="store_true",
        help="Print the stored baseline JSON."
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.show_baseline:
        return show_baseline()

    if not args.input:
        print("Error: provide a file/directory or use --show-baseline.", file=sys.stderr)
        return 2

    input_path = Path(args.input).expanduser().resolve()

    try:
        files = collect_files(input_path, args.recursive, args.all_files)
    except (FileNotFoundError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    if input_path.is_dir() and not files:
        print("[ERROR] No matching files found.")
        print("Use --all-files to include every regular file.")
        return 2

    # First use: automatically initialize.
    existing = baseline_path().exists()

    if args.reinitialize:
        return reinitialize(input_path, files)

    current = build_snapshot(files, input_path)

    if not existing:
        return reinitialize(input_path, files)

    try:
        baseline = load_baseline()
    except RuntimeError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2

    baseline_root = baseline.get("input_root")
    if baseline_root and str(input_path) != baseline_root:
        print("[WARNING] The supplied input path differs from the path used to create the baseline.")
        print(f"  Baseline: {baseline_root}")
        print(f"  Current:  {input_path}")
        print("  The comparison will still be performed using the stored file keys.\n")

    comparison = compare_snapshots(baseline, current)
    return print_report(input_path, current, comparison)


if __name__ == "__main__":
    raise SystemExit(main())
