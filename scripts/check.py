#!/usr/bin/env python3
"""Run every check in one command: lint, tests, and a determinism smoke test.

    python scripts/check.py

Exit code 0 only when everything passed. Every step runs even if an earlier
one fails, then a summary lists them all.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(name: str, cmd: list[str]) -> bool:
    print(f"=== {name}: {' '.join(cmd)}", flush=True)
    result = subprocess.run(cmd, cwd=ROOT)
    return result.returncode == 0


def determinism() -> bool:
    cmd = [sys.executable, "-m", "jamfdoctor.cli", "demo", "--format", "json"]
    env_src = {"PYTHONPATH": str(ROOT / "src")}
    env = {**_base_env(), **env_src}
    first = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    second = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env=env)
    ok = first.returncode == 0 and first.stdout == second.stdout and first.stdout.strip() != ""
    print(f"=== determinism: demo rendered twice, {'identical' if ok else 'DIFFERENT'}")
    return ok


def _base_env() -> dict[str, str]:
    import os

    return {k: v for k, v in os.environ.items() if k not in {"PYTHONPATH"}}


def main() -> int:
    results = [
        (
            "ruff lint",
            run("ruff lint", [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts"]),
        ),
        ("pytest", run("pytest", [sys.executable, "-m", "pytest", "-q"])),
        ("determinism", determinism()),
    ]
    print("=" * 60)
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"{len(failed)} step(s) failed.")
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
