#!/usr/bin/env python3

import argparse
import os
import subprocess
from pathlib import Path

MODELS = [
    "C5",
    "CBUAE_PHASE1",
    "CBUAE_PHASE2",
    "Corda",
    "CordaSolanaToolkit",
    "R3",
    "R3Protocol",
]


def compare_md(base: Path) -> int:
    print("MODEL,md_diff_lines_excl_last_update")
    for model in MODELS:
        py = base / "output_python" / model / f"{model}.md"
        ts = base / "output_ts" / model / f"{model}.md"
        if not py.exists() or not ts.exists():
            print(f"{model},MISSING")
            continue

        result = subprocess.run(["diff", "-u", str(py), str(ts)], capture_output=True, text=True)
        diff_lines = 0
        for line in result.stdout.splitlines():
            if line.startswith(("---", "+++", "@@")):
                continue
            if line.startswith(("+", "-")) and "Last update:" not in line:
                diff_lines += 1

        print(f"{model},{diff_lines}")
    return 0


def compare_puml(base: Path) -> int:
    print("MODEL,python_puml_count,ts_puml_count")
    for model in MODELS:
        py_dir = base / "output_python" / model
        ts_dir = base / "output_ts" / model

        py_count = len(list(py_dir.rglob("*.puml"))) if py_dir.exists() else 0
        ts_count = len(list(ts_dir.rglob("*.puml"))) if ts_dir.exists() else 0

        print(f"{model},{py_count},{ts_count}")
    return 0


def compare_html(base: Path) -> int:
    print("MODEL,html_diff_lines_excl_last_update")
    for model in MODELS:
        py = base / "output_python" / model / f"{model}.html"
        ts = base / "output_ts" / model / f"{model}.html"
        if not py.exists() or not ts.exists():
            print(f"{model},MISSING")
            continue

        result = subprocess.run(["diff", "-u", str(py), str(ts)], capture_output=True, text=True)
        diff_lines = 0
        for line in result.stdout.splitlines():
            if line.startswith(("---", "+++", "@@")):
                continue
            if line.startswith(("+", "-")) and "Last update:" not in line:
                diff_lines += 1

        print(f"{model},{diff_lines}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["md", "puml", "html"], required=True)
    parser.add_argument("--base", default="build/totest")
    args = parser.parse_args()

    base = Path(args.base).resolve()
    if args.mode == "md":
        return compare_md(base)
    if args.mode == "html":
        return compare_html(base)
    return compare_puml(base)


if __name__ == "__main__":
    raise SystemExit(main())
