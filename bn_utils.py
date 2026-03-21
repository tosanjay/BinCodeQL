"""BN utilities — reusable helpers for Binary Ninja headless operations.

Provides BN Python path resolution, subprocess runner, and batch fact extraction.
Ported from fuzz_harness/agent.py _get_bn_python() pattern.
"""

import json
import os
import subprocess
from pathlib import Path


def get_bn_python() -> tuple[str, dict]:
    """Resolve the Python interpreter that has the binaryninja module.

    Checks (in order):
    1. BN_PYTHON env var — full path to a Python with binaryninja installed
    2. BN_PYTHON_PATH env var — path to binaryninja Python package dir (added to PYTHONPATH)
    3. Common Binary Ninja installation paths
    4. Falls back to system python3

    Returns:
        (python_path, env_dict) — the interpreter path and environment to use.
    """
    env = os.environ.copy()

    # Option 1: User-specified Python interpreter with BN
    bn_python = os.environ.get("BN_PYTHON")
    if bn_python and Path(bn_python).exists():
        return bn_python, env

    # Option 2: BN package path (add to PYTHONPATH)
    bn_python_path = os.environ.get("BN_PYTHON_PATH")
    if bn_python_path:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{bn_python_path}:{existing}" if existing else bn_python_path
        return "python3", env

    # Option 3: Common install paths
    common_bn_paths = [
        Path.home() / "binaryninja" / "python",
        Path.home() / ".binaryninja" / "python",
        Path("/opt/binaryninja/python"),
    ]
    for bn_path in common_bn_paths:
        if bn_path.exists():
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = f"{bn_path}:{existing}" if existing else str(bn_path)
            return "python3", env

    # Fallback: hope binaryninja is importable from system python3
    return "python3", env


def run_bn_script(script_path: str | Path, args: list[str],
                  timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a headless BN script via subprocess with proper Python/env resolution.

    Args:
        script_path: Path to the BN Python script.
        args: Command-line arguments for the script.
        timeout: Max seconds before killing the subprocess.

    Returns:
        subprocess.CompletedProcess with stdout, stderr, returncode.
    """
    bn_python, bn_env = get_bn_python()
    return subprocess.run(
        [bn_python, str(script_path)] + args,
        capture_output=True, text=True, timeout=timeout, env=bn_env,
    )


def extract_facts_batch(binary_path: str, function_names: list[str] | None,
                        facts_dir: str, extract_all: bool = False) -> dict:
    """Run bn_extract_facts.py headlessly and return parsed JSON summary.

    Args:
        binary_path: Path to the binary to analyze.
        function_names: List of function names to extract (ignored if extract_all).
        facts_dir: Directory to write .facts files.
        extract_all: If True, extract all functions.

    Returns:
        Dict with extraction summary (functions_processed, relations, total_facts)
        or {"error": ...} on failure.
    """
    script = Path(__file__).parent / "scripts" / "bn_extract_facts.py"
    if not script.exists():
        return {"error": f"Script not found: {script}"}

    cmd_args = [binary_path, "-o", str(facts_dir), "--json", "-v"]
    if extract_all:
        cmd_args.append("--all")
    elif function_names:
        cmd_args.extend(["-f", ",".join(function_names)])
    else:
        return {"error": "Specify function_names or extract_all=True"}

    try:
        proc = run_bn_script(script, cmd_args)
    except subprocess.TimeoutExpired:
        return {"error": "BN extraction timed out (300s)"}

    if proc.returncode == 0:
        try:
            result = json.loads(proc.stdout)
            # Attach any stderr messages as verbose log
            if proc.stderr:
                result["log"] = proc.stderr.strip().split('\n')[-5:]
            return result
        except json.JSONDecodeError:
            return {"error": "Failed to parse JSON output",
                    "stdout": proc.stdout[:500], "stderr": proc.stderr[:500]}

    return {"error": f"Script exited with code {proc.returncode}",
            "stderr": proc.stderr[:500]}


def find_loop_functions(binary_path: str, min_blocks: int = 2) -> dict:
    """Run bn_find_loop_funcs.py to find functions containing loops.

    This is a lightweight pre-filter for BOIL analysis. Scanning all functions
    for back-edges is much faster than full fact extraction, so use this first
    to identify loop-containing functions, then extract facts only for those.

    Args:
        binary_path: Path to the binary or .bndb database.
        min_blocks: Minimum basic blocks to consider (skip trivial functions).

    Returns:
        Dict with loop function info or {"error": ...} on failure.
    """
    script = Path(__file__).parent / "scripts" / "bn_find_loop_funcs.py"
    if not script.exists():
        return {"error": f"Script not found: {script}"}

    cmd_args = [binary_path, "--json", "--min-blocks", str(min_blocks), "-v"]

    try:
        proc = run_bn_script(script, cmd_args, timeout=600)
    except subprocess.TimeoutExpired:
        return {"error": "Loop function scan timed out (600s)"}

    if proc.returncode == 0:
        try:
            result = json.loads(proc.stdout)
            if proc.stderr:
                result["log"] = proc.stderr.strip().split('\n')[-5:]
            return result
        except json.JSONDecodeError:
            return {"error": "Failed to parse JSON output",
                    "stdout": proc.stdout[:500], "stderr": proc.stderr[:500]}

    return {"error": f"Script exited with code {proc.returncode}",
            "stderr": proc.stderr[:500]}
