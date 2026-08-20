"""Run every gate in one command, in the same order CI does.

`detkit ci` is what a human runs from a clean checkout; the CI workflow runs the
same commands split across parallel jobs. Keeping the sequence here means a
green local run and a green build mean the same thing.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from detkit.hayabusa import HayabusaError, install
from detkit.paths import REPO

# (label, argv). Everything runs through the current interpreter's environment,
# so this works under `uv run` without assuming anything is on PATH.
STEPS: tuple[tuple[str, Sequence[str]], ...] = (
    ("ruff", ("ruff", "check", ".")),
    ("mypy", ("mypy",)),
    ("yamllint", ("yamllint", "detections/")),
    ("sigma check", ("sigma", "check", "--fail-on-issues", "detections/")),
    ("rule discipline", ("detkit", "validate")),
    ("pytest", (sys.executable, "-m", "pytest", "-q")),
    ("detection quality", ("detkit", "eval")),
    ("convert + binding", ("detkit", "convert")),
    ("vendored corpus", ("detkit", "vendored")),
    ("navigator layer", ("detkit", "navigator")),
    ("coverage matrix", ("detkit", "coverage")),
    ("dashboard", ("detkit", "dashboard")),
    ("readme numbers", ("detkit", "readme")),
)

DRIFT_PATHS = (
    "coverage/navigator_layer.json",
    "vendored/report.json",
    "evals/results.json",
    "site/index.html",
    "site/about.html",
    "README.md",
)


def _run(label: str, argv: Sequence[str], env: dict[str, str]) -> bool:
    # Resolve against the running interpreter's script directory. Invoked via the
    # `detkit` console script, the venv's bin/Scripts is not necessarily on PATH,
    # and on Windows the tools need their .exe suffix found for them.
    resolved = shutil.which(argv[0], path=env["PATH"])
    if resolved is None:
        print(f"\n[FAIL] {label}: {argv[0]!r} not found — run `uv sync --all-extras`\n")
        return False

    started = time.monotonic()
    proc = subprocess.run([resolved, *argv[1:]], cwd=REPO, env=env, check=False)
    elapsed = time.monotonic() - started
    status = "ok  " if proc.returncode == 0 else "FAIL"
    print(f"\n[{status}] {label} ({elapsed:.1f}s)\n", flush=True)
    return proc.returncode == 0


def run() -> int:
    env = dict(os.environ)
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")

    # The detection tests must not be able to skip. Installing the pinned binary
    # here means `detkit ci` from a clean checkout runs the real suite.
    try:
        binary = install()
    except HayabusaError as exc:
        print(f"could not install Hayabusa: {exc}", file=sys.stderr)
        return 1
    env["HAYABUSA_BIN"] = str(binary)
    env["DETKIT_REQUIRE_HAYABUSA"] = "1"
    print(f"hayabusa: {binary}")

    failures = []
    for label, argv in STEPS:
        print(f"::: {label}", flush=True)
        if not _run(label, argv, env):
            failures.append(label)
            break  # later steps assume earlier ones held

    if not failures:
        print("::: generated artifacts match the corpus", flush=True)
        diff = subprocess.run(
            ["git", "diff", "--exit-code", "--", *DRIFT_PATHS],
            cwd=REPO, env=env, check=False,
        )
        if diff.returncode != 0:
            print("\n[FAIL] generated artifacts are stale — commit the regenerated files\n")
            failures.append("artifact drift")

    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    print("all gates green")
    return 0
