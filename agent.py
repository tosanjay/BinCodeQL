# File: agent.py
# BinCodeQL — Datalog-powered binary analysis co-pilot
# Interactive agent with Binary Ninja MCP + Souffle Datalog tools

import os
import asyncio
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from google.adk.agents import LlmAgent
from google.adk.tools.mcp_tool.mcp_toolset import MCPToolset, StdioConnectionParams, StdioServerParameters
from google.adk.tools import FunctionTool
from google.adk.models.lite_llm import LiteLlm

load_dotenv(override=True)

# =============================================================================
# Configuration
# =============================================================================
MODEL_NAME = os.getenv("MODEL_NAME", "anthropic/claude-sonnet-4-6")
MCP_PYTHON_PATH = os.getenv("MCP_PYTHON_PATH", "python3")
MCP_BRIDGE_PATH = os.getenv("MCP_BRIDGE_PATH", "")
BNDB_PATH = os.getenv("BNDB_PATH", "")

PROJECT_DIR = Path(__file__).parent
RULES_DIR = PROJECT_DIR / "rules"
FACTS_DIR = PROJECT_DIR / "facts"
OUTPUT_DIR = PROJECT_DIR / "output"


def _resolve_api_key():
    """Pick the right API key based on MODEL_NAME prefix."""
    explicit = os.getenv("API_KEY")
    if explicit:
        return explicit
    if MODEL_NAME.startswith("anthropic/"):
        return os.getenv("ANTHROPIC_API_KEY")
    if MODEL_NAME.startswith("openai/"):
        return os.getenv("OPENAI_API_KEY")
    return os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")


def create_model():
    return LiteLlm(model=MODEL_NAME, api_key=_resolve_api_key())


def create_mcp_toolset():
    if not MCP_BRIDGE_PATH:
        raise ValueError(
            "MCP_BRIDGE_PATH not set. Add it to .env (see .env.example)."
        )
    return MCPToolset(
        connection_params=StdioConnectionParams(
            server_params=StdioServerParameters(
                command=MCP_PYTHON_PATH,
                args=[MCP_BRIDGE_PATH],
            )
        )
    )


# =============================================================================
# Tool: Clean workspace (remove stale facts and output files)
# =============================================================================
def tool_clean_workspace(
    clean_facts: bool = True,
    clean_output: bool = True,
) -> dict:
    """Remove stale .facts and .csv files to start a fresh analysis.

    Call this before beginning a new analysis session to ensure no stale
    data from previous runs contaminates results.

    Args:
        clean_facts: If True, remove all .facts files from facts/ dir.
        clean_output: If True, remove all .csv files from output/ dir.

    Returns:
        Dict with counts of removed files.
    """
    removed = {"facts": 0, "output": 0}
    if clean_facts:
        for f in FACTS_DIR.glob("*.facts"):
            f.unlink()
            removed["facts"] += 1
    if clean_output:
        for f in OUTPUT_DIR.glob("*.csv"):
            f.unlink()
            removed["output"] += 1
    return removed


# =============================================================================
# Tool: Extract MLIL-SSA facts from a function
# =============================================================================
def tool_extract_facts(
    function_name: str,
    mlil_ssa_text: str,
    append: bool = True,
    facts_dir: str = "",
) -> dict:
    """Extract Datalog facts from MLIL-SSA text for a function.

    Call this AFTER using the BN MCP tool `get_il(function_name, "mlil", ssa=True)`
    to obtain the MLIL-SSA text. This tool parses that text into Souffle-compatible
    fact files (Def, Use, Call, ActualArg, PhiSource, FormalParam, etc.).

    By default, successive calls ACCUMULATE facts (append=True). Call
    `tool_clean_workspace` first to start fresh, then call this for each
    function to build up the fact database incrementally.

    Args:
        function_name: Name of the function being parsed.
        mlil_ssa_text: Raw MLIL-SSA text from Binary Ninja.
        append: If True (default), merge new facts with existing .facts files
                (deduplicated). If False, overwrite files.
        facts_dir: Directory to write .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with parse stats: fact counts per relation, any unparsed lines,
        and `unresolved_callees` — list of hex-address callees that need
        resolution via `function_at` + `tool_resolve_calls`.
    """
    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from mlil_parser import parse_mlil_ssa, FactKind
    from fact_writer import write_facts

    target_dir = Path(facts_dir) if facts_dir else FACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    facts = parse_mlil_ssa(function_name, mlil_ssa_text)

    # Check for unparsed lines by re-running and capturing stderr
    import io
    old_stdout = sys.stdout
    sys.stdout = capture = io.StringIO()
    _ = parse_mlil_ssa(function_name, mlil_ssa_text)
    sys.stdout = old_stdout
    unparsed = [l for l in capture.getvalue().split('\n') if 'UNPARSED' in l]

    stats = write_facts(facts, target_dir, append=append)

    # Scan for unresolved hex-address callees
    unresolved = sorted(set(
        f.fields["callee"]
        for f in facts
        if f.kind == FactKind.CALL and f.fields["callee"].startswith("0x")
    ))

    return {
        "function": function_name,
        "total_facts": len(facts),
        "relations": {k: v for k, v in sorted(stats.items())},
        "unparsed_lines": len(unparsed),
        "unparsed_samples": unparsed[:5] if unparsed else [],
        "facts_dir": str(target_dir),
        "unresolved_callees": unresolved,
    }


# =============================================================================
# Tool: Resolve hex call targets to function names
# =============================================================================
def tool_resolve_calls(
    address_map: dict,
    facts_dir: str = "",
) -> dict:
    """Resolve hex-address callees in Call.facts to function names.

    After extracting facts, Call.facts may contain hex addresses (e.g., "0x436600")
    instead of function names. Use the BN MCP `function_at` tool to discover what
    function lives at each address, then call this tool with the mapping.

    Args:
        address_map: Dict mapping hex addresses to function names,
                     e.g. {"0x436600": "memcpy", "0x41a2f0": "png_crc_read"}.
        facts_dir: Directory containing .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with resolution stats.
    """
    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from resolve_calls import resolve_call_targets

    target_dir = str(Path(facts_dir) if facts_dir else FACTS_DIR)

    import io
    old_stdout = sys.stdout
    sys.stdout = capture = io.StringIO()
    resolve_call_targets(target_dir, address_map)
    sys.stdout = old_stdout

    return {"result": capture.getvalue().strip(), "facts_dir": target_dir}


# =============================================================================
# Tool: Run Souffle Datalog query
# =============================================================================
def tool_run_souffle(
    rule_file: str = "",
    custom_rules: str = "",
    facts_dir: str = "",
    output_dir: str = "",
    timeout_seconds: int = 30,
) -> dict:
    """Run a Souffle Datalog query against extracted facts.

    You can either:
    1. Run an existing rule file from the rules/ directory (e.g. "interproc.dl")
    2. Provide custom Datalog rules as a string (written to a temp file and run)

    The query reads .facts files from facts_dir and writes results to output_dir.

    Args:
        rule_file: Name of a rule file in rules/ dir (e.g., "interproc.dl", "taint.dl").
                   Ignored if custom_rules is provided.
        custom_rules: Custom Souffle Datalog program as a string. If provided,
                      this is written to a temp file and executed instead of rule_file.
        facts_dir: Directory containing .facts input files.
        output_dir: Directory for output CSV files.
        timeout_seconds: Max execution time (default 30s).

    Returns:
        Dict with stdout, stderr, return code, and list of output files with contents.
    """
    fdir = str(Path(facts_dir) if facts_dir else FACTS_DIR)
    odir = str(Path(output_dir) if output_dir else OUTPUT_DIR)
    Path(odir).mkdir(parents=True, exist_ok=True)

    # Clear stale output CSVs before running to avoid mixing old/new results
    for stale in Path(odir).glob("*.csv"):
        stale.unlink()

    # Determine the .dl file to run
    if custom_rules:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.dl', delete=False,
                                          dir=str(PROJECT_DIR))
        tmp.write(custom_rules)
        tmp.close()
        dl_path = tmp.name
    elif rule_file:
        dl_path = str(RULES_DIR / rule_file)
        if not Path(dl_path).exists():
            return {"error": f"Rule file not found: {dl_path}"}
    else:
        return {"error": "Provide either rule_file or custom_rules"}

    try:
        result = subprocess.run(
            ["souffle", "-F", fdir, "-D", odir, dl_path],
            capture_output=True, text=True, timeout=timeout_seconds,
        )

        # Collect output files
        outputs = {}
        for f in sorted(Path(odir).glob("*.csv")):
            content = f.read_text().strip()
            if content:
                lines = content.split('\n')
                outputs[f.name] = {
                    "rows": len(lines),
                    "preview": lines[:20],  # first 20 rows
                }

        return {
            "return_code": result.returncode,
            "stdout": result.stdout.strip() if result.stdout else "",
            "stderr": result.stderr.strip() if result.stderr else "",
            "output_files": outputs,
            "rule_file": dl_path,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Souffle timed out after {timeout_seconds}s"}
    finally:
        if custom_rules:
            Path(dl_path).unlink(missing_ok=True)


# =============================================================================
# Tool: List available rule files and fact files
# =============================================================================
def tool_list_datalog_files() -> dict:
    """List available Datalog rule files and fact files.

    Returns the rule files in rules/ and fact files in facts/ with their sizes
    and column schemas, so you know what's available to query.
    """
    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from fact_writer import SCHEMA_DOCS
    from mlil_parser import FactKind

    # Build filename→columns lookup from SCHEMA_DOCS
    from fact_writer import RELATION_SCHEMA
    file_columns = {}
    for kind, cols in SCHEMA_DOCS.items():
        schema = RELATION_SCHEMA.get(kind)
        if schema:
            file_columns[schema[0]] = cols

    rules = []
    for f in sorted(RULES_DIR.glob("*.dl")):
        rules.append({"name": f.name, "size_bytes": f.stat().st_size})

    facts = []
    for f in sorted(FACTS_DIR.glob("*.facts")):
        lines = f.read_text().strip().count('\n') + 1 if f.stat().st_size > 0 else 0
        entry = {"name": f.name, "rows": lines}
        if f.name in file_columns:
            entry["columns"] = file_columns[f.name]
        facts.append(entry)

    return {"rules": rules, "facts": facts}


# =============================================================================
# Tool: Read a rule or output file
# =============================================================================
def tool_read_file(file_path: str) -> dict:
    """Read contents of a rule file, fact file, or output file.

    Args:
        file_path: Path relative to project dir (e.g., "rules/interproc.dl",
                   "output/TaintedSink.csv", "facts/Call.facts").
                   Also accepts absolute paths.
    """
    p = Path(file_path)
    if not p.is_absolute():
        p = PROJECT_DIR / p

    if not p.exists():
        return {"error": f"File not found: {p}"}

    content = p.read_text()
    return {
        "path": str(p),
        "size_bytes": p.stat().st_size,
        "content": content,
    }


# =============================================================================
# Tool: Generate TaintTransfer.facts from signatures
# =============================================================================
def tool_generate_signatures(
    extra_signatures: list[dict] = None,
) -> dict:
    """Generate TaintTransfer.facts from the signatures rule file.

    Runs rules/signatures.dl to produce TaintTransfer.csv, then copies it
    to facts/TaintTransfer.facts so interproc.dl can use it.

    Optionally add extra signatures (e.g., for newly discovered library functions).

    Args:
        extra_signatures: Optional list of dicts with keys:
            func (str), out_arg (str), in_arg (str).
            Example: [{"func": "png_crc_read", "out_arg": "arg1", "in_arg": "external"}]

    Returns:
        Dict with the number of TaintTransfer facts generated.
    """
    # If extra signatures provided, append to a temp copy of signatures.dl
    sig_file = RULES_DIR / "signatures.dl"
    dl_content = sig_file.read_text()

    if extra_signatures:
        # Insert before the .output line
        extra_lines = []
        for sig in extra_signatures:
            extra_lines.append(
                f'TaintTransfer("{sig["func"]}", "{sig["out_arg"]}", "{sig["in_arg"]}").'
            )
        dl_content = dl_content.replace(
            '.output TaintTransfer',
            '\n'.join(extra_lines) + '\n.output TaintTransfer'
        )

    # Write temp file and run
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.dl', delete=False)
    tmp.write(dl_content)
    tmp.close()

    try:
        result = subprocess.run(
            ["souffle", "-F", str(FACTS_DIR), "-D", str(OUTPUT_DIR), tmp.name],
            capture_output=True, text=True, timeout=15,
        )

        if result.returncode != 0:
            return {"error": result.stderr}

        # Copy output to facts dir
        result_info = {}
        src = OUTPUT_DIR / "TaintTransfer.csv"
        dst = FACTS_DIR / "TaintTransfer.facts"
        if src.exists():
            dst.write_text(src.read_text())
            content = src.read_text().strip()
            rows = content.count('\n') + 1 if content else 0
            result_info["taint_transfer_facts"] = rows
            result_info["taint_transfer_path"] = str(dst)
        else:
            return {"error": "TaintTransfer.csv not generated"}

        # Also copy BufferWriteSource if produced
        bws_src = OUTPUT_DIR / "BufferWriteSource.csv"
        bws_dst = FACTS_DIR / "BufferWriteSource.facts"
        if bws_src.exists():
            bws_dst.write_text(bws_src.read_text())
            content = bws_src.read_text().strip()
            bws_rows = content.count('\n') + 1 if content else 0
            result_info["buffer_write_source_facts"] = bws_rows
            result_info["buffer_write_source_path"] = str(bws_dst)

        # Also copy TaintKill if produced
        tk_src = OUTPUT_DIR / "TaintKill.csv"
        tk_dst = FACTS_DIR / "TaintKill.facts"
        if tk_src.exists():
            tk_dst.write_text(tk_src.read_text())
            content = tk_src.read_text().strip()
            tk_rows = content.count('\n') + 1 if content else 0
            result_info["taint_kill_facts"] = tk_rows
            result_info["taint_kill_path"] = str(tk_dst)

        return result_info
    finally:
        Path(tmp.name).unlink(missing_ok=True)


# =============================================================================
# Tool: Generate source/sink annotation fact files
# =============================================================================
# Built-in catalogs for dangerous sinks and taint source functions
_BUILTIN_SINKS = [
    ("memcpy", 0, "buffer_overflow_dst"),
    ("memcpy", 2, "buffer_overflow_size"),
    ("memmove", 0, "buffer_overflow_dst"),
    ("memmove", 2, "buffer_overflow_size"),
    ("strcpy", 0, "buffer_overflow_dst"),
    ("strncpy", 0, "buffer_overflow_dst"),
    ("strcat", 0, "buffer_overflow_dst"),
    ("sprintf", 0, "format_buffer_overflow"),
    ("snprintf", 0, "format_buffer_overflow"),
    ("system", 0, "command_injection"),
    ("execve", 0, "command_injection"),
    ("free", 0, "double_free"),
]

_BUILTIN_SOURCES = [
    ("read", "external"),
    ("recv", "external"),
    ("recvfrom", "external"),
    ("fread", "external"),
    ("fgets", "external"),
    ("gets", "external"),
    ("getenv", "external"),
    ("getline", "external"),
    ("scanf", "external"),
    ("recvmsg", "external"),
]


# =============================================================================
# Tool: Batch extract facts via headless Binary Ninja
# =============================================================================
def tool_extract_facts_batch(
    binary_path: str,
    function_names: list[str] = None,
    extract_all: bool = False,
) -> dict:
    """Extract Datalog facts from a binary or .bndb database using Binary Ninja.

    Accepts either a raw binary (ELF/PE/Mach-O) or a pre-analyzed .bndb
    database. Using .bndb is significantly faster — BN skips analysis and
    loads pre-computed MLIL-SSA directly.

    One call replaces the multi-step MCP extraction workflow (get_il → parse →
    write facts). Runs a headless BN subprocess that walks MLIL-SSA objects
    directly, producing .facts files including StackVar.

    Use this for batch extraction of multiple functions. For incremental,
    interactive exploration, continue using `tool_extract_facts` with MCP.

    Requires: BN_PYTHON or BN_PYTHON_PATH env var set, or BN on system path.

    Args:
        binary_path: Path to the binary or .bndb file to analyze.
        function_names: List of function names to extract.
        extract_all: If True, extract ALL functions (ignores function_names).

    Returns:
        Dict with extraction summary or error.
    """
    if not binary_path and BNDB_PATH:
        binary_path = BNDB_PATH

    import sys
    sys.path.insert(0, str(PROJECT_DIR))
    from bn_utils import extract_facts_batch

    return extract_facts_batch(binary_path, function_names, str(FACTS_DIR), extract_all)


def tool_generate_annotations(
    extra_sources: list[dict] = None,
    extra_sinks: list[dict] = None,
    facts_dir: str = "",
) -> dict:
    """Generate DangerousSink.facts and TaintSourceFunc.facts from built-in catalogs.

    These fact files are loaded by interproc.dl via `.input` directives instead
    of being hardcoded in the rule file. You can extend the catalogs with
    extra entries for binary-specific functions.

    Args:
        extra_sources: Optional list of dicts with keys:
            func (str), category (str, e.g. "external").
            Example: [{"func": "png_read_data", "category": "external"}]
        extra_sinks: Optional list of dicts with keys:
            func (str), arg_idx (int), risk (str).
            Example: [{"func": "png_crc_read", "arg_idx": 1, "risk": "buffer_overflow"}]
        facts_dir: Directory for .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with counts of sink and source facts written.
    """
    target_dir = Path(facts_dir) if facts_dir else FACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    # Sinks
    sink_rows = set()
    for func, idx, risk in _BUILTIN_SINKS:
        sink_rows.add((func, str(idx), risk))
    if extra_sinks:
        for s in extra_sinks:
            sink_rows.add((s["func"], str(s["arg_idx"]), s["risk"]))
    sorted_sinks = sorted(sink_rows)
    sink_path = target_dir / "DangerousSink.facts"
    with open(sink_path, 'w') as fp:
        for row in sorted_sinks:
            fp.write('\t'.join(row) + '\n')

    # Sources
    source_rows = set()
    for func, cat in _BUILTIN_SOURCES:
        source_rows.add((func, cat))
    if extra_sources:
        for s in extra_sources:
            source_rows.add((s["func"], s["category"]))
    sorted_sources = sorted(source_rows)
    source_path = target_dir / "TaintSourceFunc.facts"
    with open(source_path, 'w') as fp:
        for row in sorted_sources:
            fp.write('\t'.join(row) + '\n')

    return {
        "sinks": len(sorted_sinks),
        "sources": len(sorted_sources),
        "sink_path": str(sink_path),
        "source_path": str(source_path),
    }


# =============================================================================
# Tool: Set entry-point taint (attack surface specification)
# =============================================================================
def tool_set_entry_taint(
    entries: list[dict],
    facts_dir: str = "",
) -> dict:
    """Specify which exported API parameters are attacker-controlled.

    For library analysis where there are no calls to read()/recv() — the
    library's exported API IS the attack surface. Mark params as tainted
    and interproc.dl will seed TaintedVar from them.

    Args:
        entries: List of dicts with keys:
            func (str): Function name (e.g., "parse_image")
            param_idx (int): 0-based parameter index (e.g., 1 for arg2)
            Example: [{"func": "parse_image", "param_idx": 1},
                      {"func": "parse_image", "param_idx": 0}]
        facts_dir: Directory for .facts files. Defaults to project facts/ dir.

    Returns:
        Dict with count of entries written and file path.
    """
    target_dir = Path(facts_dir) if facts_dir else FACTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    rows = set()
    for e in entries:
        rows.add((e["func"], str(e["param_idx"])))
    sorted_rows = sorted(rows)

    path = target_dir / "EntryTaint.facts"
    with open(path, 'w') as fp:
        for row in sorted_rows:
            fp.write('\t'.join(row) + '\n')

    return {
        "entries": len(sorted_rows),
        "path": str(path),
        "description": f"Marked {len(sorted_rows)} params as attacker-controlled entry points",
    }


# =============================================================================
# Tool: Two-pass taint pipeline (alias → interproc)
# =============================================================================
def tool_run_taint_pipeline(
    facts_dir: str = "",
    output_dir: str = "",
    timeout_seconds: int = 60,
) -> dict:
    """Run the full taint analysis pipeline: alias analysis → interprocedural taint.

    Pass 1: Runs alias.dl to compute PointsTo facts.
    Pass 2: Copies PointsTo to facts dir, runs interproc.dl with alias-enhanced taint.

    This replaces manually running alias.dl then interproc.dl. It handles the
    intermediate PointsTo.csv → PointsTo.facts copy automatically.

    Args:
        facts_dir: Directory containing .facts input files. Defaults to project facts/ dir.
        output_dir: Directory for output CSV files. Defaults to project output/ dir.
        timeout_seconds: Max execution time per pass (default 60s).

    Returns:
        Dict with results from both passes and combined output files.
    """
    fdir = Path(facts_dir) if facts_dir else FACTS_DIR
    odir = Path(output_dir) if output_dir else OUTPUT_DIR
    odir.mkdir(parents=True, exist_ok=True)

    results = {"pass1_alias": {}, "pass2_interproc": {}, "outputs": {}}

    # ── Pass 1: alias.dl → PointsTo ──
    alias_dl = str(RULES_DIR / "alias.dl")
    if not Path(alias_dl).exists():
        return {"error": f"Rule file not found: {alias_dl}"}

    # Clear stale output
    for stale in odir.glob("*.csv"):
        stale.unlink()

    try:
        r1 = subprocess.run(
            ["souffle", "-F", str(fdir), "-D", str(odir), alias_dl],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Pass 1 (alias.dl) timed out after {timeout_seconds}s"}

    if r1.returncode != 0:
        results["pass1_alias"]["error"] = r1.stderr.strip()
        # Continue anyway — interproc.dl has fallback rules for empty PointsTo
    else:
        results["pass1_alias"]["return_code"] = r1.returncode

    # Collect pass 1 outputs
    for f in sorted(odir.glob("*.csv")):
        content = f.read_text().strip()
        if content:
            lines = content.split('\n')
            results["pass1_alias"][f.name] = len(lines)

    # ── Copy PointsTo.csv → facts/PointsTo.facts ──
    pts_src = odir / "PointsTo.csv"
    pts_dst = fdir / "PointsTo.facts"
    if pts_src.exists():
        pts_content = pts_src.read_text().strip()
        if pts_content:
            pts_dst.write_text(pts_content + '\n')
            results["points_to_facts"] = pts_content.count('\n') + 1
        else:
            pts_dst.touch()
            results["points_to_facts"] = 0
    else:
        pts_dst.touch()
        results["points_to_facts"] = 0

    # ── Pass 2: interproc.dl ──
    interproc_dl = str(RULES_DIR / "interproc.dl")
    if not Path(interproc_dl).exists():
        return {"error": f"Rule file not found: {interproc_dl}"}

    # Clear stale output for pass 2
    for stale in odir.glob("*.csv"):
        stale.unlink()

    try:
        r2 = subprocess.run(
            ["souffle", "-F", str(fdir), "-D", str(odir), interproc_dl],
            capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Pass 2 (interproc.dl) timed out after {timeout_seconds}s"}

    results["pass2_interproc"]["return_code"] = r2.returncode
    if r2.returncode != 0:
        results["pass2_interproc"]["stderr"] = r2.stderr.strip()

    # Collect pass 2 outputs
    for f in sorted(odir.glob("*.csv")):
        content = f.read_text().strip()
        if content:
            lines = content.split('\n')
            results["outputs"][f.name] = {
                "rows": len(lines),
                "preview": lines[:20],
            }

    return results


# =============================================================================
# Agent instruction prompt
# =============================================================================
AGENT_INSTRUCTION = """You are **BinCodeQL**, an interactive binary analysis co-pilot.
You help vulnerability researchers analyze compiled binaries using Datalog queries
over facts extracted from Binary Ninja's MLIL-SSA intermediate representation.

## Your capabilities

1. **Binary Ninja MCP tools** — decompile functions, get MLIL-SSA IL, list functions,
   search symbols, get cross-references, list imports/exports, etc.

2. **Fact extraction** — Parse MLIL-SSA into Datalog facts (Def, Use, Call, PhiSource,
   ActualArg, ReturnVal, AddressOf, FieldRead, FieldWrite, MemRead, FormalParam,
   Guard, etc.). **Prefer batch extraction** (`tool_extract_facts_batch`) — it runs a
   headless BN subprocess, auto-resolves callees, and emits StackVar + Guard facts.

3. **Souffle Datalog engine** — Run pre-built or custom Datalog queries:
   - `interproc.dl` — Full interprocedural taint analysis with 1-CFA context sensitivity,
     sanitizer modeling (TaintKill), guard detection (GuardedSink), and interprocedural
     field taint propagation. TaintedVar has 5 columns: (func, var, ver, origin, ctx).
   - `taint.dl` — Intraprocedural taint tracking
   - `summary.dl` — Function summary computation (param → return dependencies)
   - `core.dl` — Basic def-use, reachability, field access queries
   - `alias.dl` — Andersen-style points-to analysis + alias-enhanced taint
   - `boil.dl` — BOIL (Buffer Overflow Inducing Loop) candidate detection
   - `patterns.dl` — Structural vulnerability heuristics (unsafe strcpy, gets, sprintf)
   - `patterns_mem.dl` — Intraprocedural memory safety: UAF, double-free,
     unchecked malloc, format string vulnerabilities
   - `patterns_mem_interproc.dl` — Interprocedural memory safety: parameter-based
     (FreesParam → InterDoubleFree/InterUseAfterFree) + global-mediated
     (GlobalFreeSite → GlobalDoubleFree/GlobalUseAfterFree). Includes intraprocedural
     rules too — run this instead of patterns_mem.dl for comprehensive detection.
   - `inttype.dl` — Integer/type confusion: signed→unsigned, truncation,
     widening-after-overflow, sign-extend-negative-to-size at size-sensitive sinks
   - `inttype_taint.dl` — Taint-integrated integer vulns (requires TaintedVar from interproc.dl)
   - `schema.dl` — Reusable `.decl` + `.input` declarations (include in custom queries)
   - Custom `.dl` programs you compose on the fly

4. **Taint signatures** — Library function models (memcpy, strcpy, read, recv, etc.)
   that declare how taint transfers through external functions. Also includes TaintKill
   (sanitizers like memset, bzero) that kill taint on buffers.

5. **Annotations** — Source/sink fact files generated from built-in catalogs, extensible
   with binary-specific functions.

## Fact schema reference

| Relation | Columns | File |
|----------|---------|------|
| Def | func, var, ver, addr | Def.facts |
| Use | func, var, ver, addr | Use.facts |
| Call | caller, callee, addr | Call.facts |
| ActualArg | call_addr, arg_idx, param, var, ver | ActualArg.facts |
| ReturnVal | func, var, ver | ReturnVal.facts |
| PhiSource | func, var, def_ver, src_var, src_ver | PhiSource.facts |
| FormalParam | func, var, idx | FormalParam.facts |
| MemRead | func, addr, base, offset, size | MemRead.facts |
| MemWrite | func, addr, target, mem_in, mem_out | MemWrite.facts |
| FieldRead | func, addr, base, field | FieldRead.facts |
| FieldWrite | func, addr, base, field, mem_in, mem_out | FieldWrite.facts |
| AddressOf | func, var, ver, target | AddressOf.facts |
| CFGEdge | func, from_addr, to_addr | CFGEdge.facts |
| Jump | func, addr, expr | Jump.facts |
| StackVar | func, var, offset, size | StackVar.facts |
| Guard | func, addr, var, ver, op, bound | Guard.facts |
| ArithOp | func, addr, dst, dst_ver, op, src, src_ver, operand | ArithOp.facts |
| Cast | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width | Cast.facts |
| VarWidth | func, var, ver, width | VarWidth.facts |
| DangerousSink | func, arg_idx, risk | DangerousSink.facts |
| TaintSourceFunc | name, category | TaintSourceFunc.facts |
| BufferWriteSource | func, arg_idx | BufferWriteSource.facts |
| TaintKill | func, arg_idx | TaintKill.facts |
| PointsTo | func, var, ver, obj | PointsTo.facts (derived from alias.dl) |

### Derived output relations (from interproc.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| TaintedVar | func, var, ver, origin, ctx | Context-sensitive tainted variables (ctx = call-site address) |
| TaintedSink | caller, callee, call_addr, arg_idx, tainted_var, risk, origin | Tainted data reaching dangerous sinks (excludes sanitized vars) |
| TaintedBuffer | func, buffer, origin, ctx | Buffers tainted via pointer aliasing |
| TaintedField | func, base, field, origin, ctx | Field-level taint (interprocedural) |
| TaintedHeapObject | obj, origin | Heap objects tainted via buffer-write sources |
| SanitizedVar | func, var, ver, kill_func, kill_addr | Variables sanitized by TaintKill functions |
| GuardedSink | caller, callee, call_addr, guard_var, guard_op, guard_bound | Sinks with bounds-check guards (for triage) |

### Derived output relations (from inttype.dl / inttype_taint.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| SignedToUnsignedConfusion | func, cast_addr, dst, dst_ver, callee, call_addr, arg_idx | Sign-extend output flows to size-sensitive sink |
| IntegerTruncation | func, cast_addr, dst, dst_ver, src_width, dst_width, callee, call_addr, arg_idx | Wide→narrow truncation before size arg |
| WideningAfterOverflow | func, arith_addr, op, arith_width, cast_addr, callee, call_addr | Narrow arith then zero-extend to wide |
| SignExtNegativeToSize | func, arith_addr, cast_addr, callee, call_addr | Arith result sign-extended, used as size |
| TaintedIntVuln | func, vuln_type, cast_addr, callee, sink_addr, origin | Taint-integrated integer bug (from inttype_taint.dl) |
| GuardedIntIssue | func, cast_addr, guard_addr, guard_op, guard_bound | Int issue with bounds check (lower confidence) |

### Derived output relations (from patterns_mem.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| UseAfterFree | func, free_addr, use_addr, var | Pointer used after free() |
| DoubleFree | func, free1_addr, free2_addr, var | Same pointer freed twice |
| UncheckedMalloc | func, call_addr, var | malloc/calloc/realloc return used without NULL check |
| FormatStringVuln | func, call_addr, callee, fmt_var | Function param used as format string |

### Derived output relations (from patterns_mem_interproc.dl)

| Relation | Columns | Description |
|----------|---------|-------------|
| FreesParam | func, param_idx | Function summary: frees its Nth parameter |
| InterDoubleFree | caller, callee1, call1, callee2, call2, var | Same arg passed to two callees that both free it |
| InterUseAfterFree | caller, callee, free_call, use_addr, var | Arg passed to freeing callee, then used after call returns |
| GlobalFreeSite | func, free_addr, global_addr | Global pointer loaded and freed |
| GlobalDoubleFree | func1, free1, func2, free2, global_addr | Same global freed in two places |
| GlobalUseAfterFree | free_func, free_addr, use_func, use_addr, global_addr, use_var | Global freed, then used (same or different function) |
| UsesAfterFreeParam | func, param_idx, free_addr, use_addr | Function frees param then uses it (callee-side UAF summary) |
| ReturnsFreedPtr | func, param_idx | Function frees param then returns it (dangling pointer) |
| ReturnedDanglingPtr | caller, callee, call_addr, dangling_var, use_addr | Caller uses return value that was freed inside callee |

## Workflow for analyzing a binary

### Recommended: Batch extraction (headless BN)
1. **Clean workspace** — Call `tool_clean_workspace` to remove stale facts/output.
2. **Batch extract** — Call `tool_extract_facts_batch` with the binary path and function
   names (or `extract_all=True`). This runs a headless BN subprocess that walks MLIL-SSA
   objects directly, emitting all facts including StackVar and Guard. No MCP round-trips
   needed. Callees are auto-resolved. Requires BN_PYTHON or BN_PYTHON_PATH env var.
   **Prefer .bndb** when available — it loads in milliseconds vs seconds/minutes
   for raw binaries, and includes user-refined analysis (renamed functions,
   custom types, annotations). The script auto-detects .bndb siblings.
3. **Generate annotations** — Call `tool_generate_annotations` to create DangerousSink.facts
   and TaintSourceFunc.facts. Add binary-specific sources/sinks via extra args.
4. **Generate signatures** — Call `tool_generate_signatures` to create TaintTransfer.facts,
   BufferWriteSource.facts, and TaintKill.facts.
5. **Run taint pipeline** — Call `tool_run_taint_pipeline` for the full two-pass analysis:
   - Pass 1: alias.dl → computes PointsTo facts
   - Pass 2: interproc.dl → 1-CFA context-sensitive interprocedural taint with
     alias-enhanced pointer tracking, sanitizer kill, and guard detection.
   This handles buffer-write sources (fread, read, recv) that taint heap objects,
   not just pointer variables. Also run `patterns.dl` separately for structural patterns.
6. **Interpret results** — Read output CSVs and explain findings to the user.
   Key output relations: TaintedVar, TaintedSink, TaintedHeapObject, TaintedBuffer.
   Check SanitizedVar for false-positive suppression, GuardedSink for triage.

### Alternative: Interactive MCP extraction
Use when you need to explore incrementally or BN headless is unavailable.
1. **Select binary** — Use `select_binary` if needed.
2. **Clean workspace** — Call `tool_clean_workspace`.
3. **Explore** — Use `list_methods`, `search_functions_by_name`, `list_imports`.
4. **Extract IL** — Use `get_il(func, "mlil", ssa=True)` for functions of interest.
5. **Parse facts** — Call `tool_extract_facts` with the MLIL-SSA text (facts accumulate).
   If `unresolved_callees` is non-empty, resolve via `function_at` + `tool_resolve_calls`.
6. **Generate annotations + signatures** — Same as batch workflow.
7. **Run analysis** — Same as batch workflow.

## Writing custom Datalog queries

When the user asks a question not covered by existing rules, **compose a custom Datalog
program on the fly**. You can `#include "schema.dl"` to get all type and relation
declarations, or declare only what you need. The program must:
- Declare types: `.type Addr <: unsigned`, `.type Sym <: symbol`, `.type Ver <: unsigned`, `.type Idx <: unsigned`
- Declare and `.input` the relations it needs (Def, Use, Call, etc.)
- Define derived relations with rules
- `.output` the result relations

### Common vulnerability query patterns

For patterns not covered by existing rule files, compose custom queries on the fly:

- **Use-after-free / Double-free / Unchecked malloc / Format string:** Run
  `patterns_mem_interproc.dl` for comprehensive detection — covers both intraprocedural
  patterns AND interprocedural ones (parameter-based FreesParam summaries + global-mediated
  tracking). Detects cross-function UAF/double-free via shared globals. Or run the lighter
  `patterns_mem.dl` for intraprocedural-only analysis.
- **Integer/type confusion:** Run `inttype.dl` to find signed→unsigned confusion,
  integer truncation, widening-after-overflow, and sign-extend-negative-to-size bugs.
  Requires Cast.facts and VarWidth.facts (emitted by batch extraction).
- **Tainted integer bugs:** After running interproc.dl, run `inttype_taint.dl` to find
  integer confusion bugs reachable from attacker-controlled input. Output: TaintedIntVuln.
- **BOIL detection:** Run `boil.dl` to find buffer-overflow-inducing loops.
  BOILCandidate(func, src_ptr, dst_ptr, read_addr, write_addr, confidence)
  shows loops that copy data with incrementing pointers. "high" confidence means
  ArithOp confirmed both pointers increment and termination depends on source data.
  Examine candidates with decompile_function for full analysis.
- **Library attack surface (entry-point taint):** For libraries without calls to
  read()/recv(), use `tool_set_entry_taint` to mark exported API params as
  attacker-controlled. Example: `[{"func": "parse_image", "param_idx": 1}]`.
  Then run interproc.dl — TaintedVar will propagate from those params.
  Origin strings use format `entry:func_name:argN` for traceability.
- **Tainted BOIL (end-to-end):** After setting entry taints and running both
  interproc.dl and boil.dl, run `boil_taint.dl` to find BOILs reachable from
  attacker input. TaintedBOIL shows which BOIL candidates have tainted src/dst
  pointers. TaintedBOILEntry traces back to the specific entry-point param.

Use `tool_run_souffle(custom_rules=...)` with inline Datalog for these.

Example — "Which functions call memcpy?":
```
.type Sym <: symbol
.type Addr <: unsigned
.decl Call(caller: Sym, callee: Sym, addr: Addr)
.input Call
.decl CallerOfMemcpy(func: Sym)
CallerOfMemcpy(f) :- Call(f, "memcpy", _).
.output CallerOfMemcpy
```

## Response style

- Be concise. Lead with findings, not process.
- When showing taint paths, trace from source to sink with variable names and addresses.
- Flag the vulnerability type and severity.
- If the user asks about a specific function, extract and analyze it before answering.
- When reporting TaintedSink, note the ctx column to distinguish call-site contexts.
- If a sink appears in GuardedSink, note the guard condition for triage.
"""


# =============================================================================
# Build and register the root agent
# =============================================================================
root_agent = LlmAgent(
    name="BinCodeQL",
    model=create_model(),
    instruction=AGENT_INSTRUCTION,
    tools=[
        FunctionTool(tool_clean_workspace),
        FunctionTool(tool_extract_facts),
        FunctionTool(tool_extract_facts_batch),
        FunctionTool(tool_resolve_calls),
        FunctionTool(tool_run_souffle),
        FunctionTool(tool_list_datalog_files),
        FunctionTool(tool_read_file),
        FunctionTool(tool_generate_signatures),
        FunctionTool(tool_generate_annotations),
        FunctionTool(tool_set_entry_taint),
        FunctionTool(tool_run_taint_pipeline),
        create_mcp_toolset(),
    ],
)
