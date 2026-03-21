#!/usr/bin/env python3
"""
BinCodeQL Loop Function Finder — lightweight pre-filter for BOIL analysis.

Uses Binary Ninja's HLIL which has explicit loop constructs (WHILE, DO_WHILE,
FOR). Also detects goto-based backward jumps as a fallback for irreducible
control flow that BN can't structure into loops. Flags which loops contain
memory writes (DEREF assignments) for BOIL relevance.

This is much faster than full fact extraction and enables targeted BOIL
analysis on large binaries — only functions with loops AND memory writes
are BOIL candidates.

Usage:
    python3 bn_find_loop_funcs.py /path/to/binary
    python3 bn_find_loop_funcs.py /path/to/binary --json
    python3 bn_find_loop_funcs.py /path/to/binary --min-blocks 3
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import binaryninja
    from binaryninja import HighLevelILOperation as HLIL
except ImportError:
    print("[!] Error: Binary Ninja Python API not available", file=sys.stderr)
    sys.exit(1)

# HLIL operations that represent structured loops
_LOOP_OPS = {HLIL.HLIL_WHILE, HLIL.HLIL_DO_WHILE, HLIL.HLIL_FOR}

# HLIL operations that represent memory writes (pointer dereference assigns)
_DEREF_OPS = {HLIL.HLIL_DEREF, HLIL.HLIL_DEREF_FIELD}


def resolve_binary_path(binary_path: str) -> tuple:
    """Prefer .bndb sibling if it exists."""
    if binary_path.lower().endswith('.bndb'):
        return binary_path, True
    bndb_sibling = binary_path + '.bndb'
    if Path(bndb_sibling).exists():
        return bndb_sibling, True
    return binary_path, False


def _walk_hlil(expr, in_loop=False):
    """Recursively walk HLIL AST. Returns (loop_count, has_mem_write_in_loop)."""
    loops = 0
    mem_write = False

    op = expr.operation
    is_loop = op in _LOOP_OPS
    if is_loop:
        loops += 1
    now_in_loop = in_loop or is_loop

    # HLIL_ASSIGN where dest is a DEREF/DEREF_FIELD → memory store
    if now_in_loop and op == HLIL.HLIL_ASSIGN:
        dest = expr.dest
        if hasattr(dest, 'operation') and dest.operation in _DEREF_OPS:
            mem_write = True

    for operand in expr.operands:
        if hasattr(operand, 'operation'):
            l, m = _walk_hlil(operand, now_in_loop)
            loops += l
            mem_write = mem_write or m
        elif isinstance(operand, list):
            for item in operand:
                if hasattr(item, 'operation'):
                    l, m = _walk_hlil(item, now_in_loop)
                    loops += l
                    mem_write = mem_write or m
    return loops, mem_write


def _check_goto_loops(hlil):
    """Detect goto-based backward jumps (irreducible loops not structured by BN).

    Returns (goto_loop_count, has_mem_write_near_goto_loop).
    A backward goto is one where the target label address < the goto address,
    indicating a loop that BN couldn't lift to while/for/do-while.
    """
    goto_loops = 0
    has_store = False

    for instr in hlil.instructions:
        op_name = instr.operation
        if op_name == HLIL.HLIL_GOTO:
            # Parse target label address from "goto label_XXXX"
            label_str = str(instr)
            if 'label_' in label_str:
                try:
                    target_addr = int(label_str.split('label_')[1], 16)
                    if target_addr < instr.address:
                        goto_loops += 1
                except (ValueError, IndexError):
                    pass

        # Check for memory writes anywhere in the function (conservative —
        # we don't know exactly which instructions are in the goto loop body,
        # but if there's a backward goto AND a deref assign, flag it)
        if not has_store and op_name == HLIL.HLIL_ASSIGN:
            dest = instr.dest
            if hasattr(dest, 'operation') and dest.operation in _DEREF_OPS:
                has_store = True

    return goto_loops, has_store


def find_loop_functions(bv, min_blocks=2, verbose=False):
    """Scan all functions and return those containing loops.

    Uses HLIL which has explicit loop constructs (WHILE, DO_WHILE, FOR).
    Falls back to detecting goto-based backward jumps for irreducible
    control flow that BN can't structure into loops.
    Also detects memory writes (DEREF assignments) inside loop bodies to
    flag BOIL-relevant functions.

    Args:
        bv: BinaryView
        min_blocks: Minimum MLIL basic blocks to consider (skip trivial functions)
        verbose: Print progress to stderr

    Returns:
        List of dicts with function info: name, addr, blocks, loops,
        has_mem_write, loop_type ("structured", "goto", or "both").
    """
    results = []
    total = len(bv.functions)
    skipped = 0

    for i, func in enumerate(bv.functions):
        if verbose and (i + 1) % 500 == 0:
            print(f"[*] Scanned {i + 1}/{total} functions, "
                  f"found {len(results)} with loops...", file=sys.stderr)

        # Skip very small functions (stubs, thunks) — use MLIL block count
        # as a complexity proxy (cheaper than full HLIL walk)
        try:
            mlil = func.mlil
            if mlil is None:
                skipped += 1
                continue
            block_count = len(mlil.basic_blocks)
            if block_count < min_blocks:
                skipped += 1
                continue
        except Exception:
            skipped += 1
            continue

        # Walk HLIL AST for structured loops and memory writes
        try:
            hlil = func.hlil
            if hlil is None:
                skipped += 1
                continue

            structured_loops = 0
            has_mem_write = False
            for instr in hlil.instructions:
                l, m = _walk_hlil(instr)
                structured_loops += l
                has_mem_write = has_mem_write or m

            # Fallback: check for goto-based backward jumps
            goto_loops = 0
            if structured_loops == 0:
                goto_loops, goto_store = _check_goto_loops(hlil)
                has_mem_write = has_mem_write or goto_store
        except Exception:
            continue

        total_loops = structured_loops + goto_loops
        if total_loops > 0:
            if structured_loops > 0 and goto_loops > 0:
                loop_type = "both"
            elif structured_loops > 0:
                loop_type = "structured"
            else:
                loop_type = "goto"

            results.append({
                "name": func.name,
                "addr": hex(func.start),
                "blocks": block_count,
                "loops": total_loops,
                "has_mem_write": has_mem_write,
                "loop_type": loop_type,
            })

    if verbose:
        print(f"[*] Done: {total} functions scanned, {skipped} skipped, "
              f"{len(results)} contain loops", file=sys.stderr)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="BinCodeQL: Find functions with loops (pre-filter for BOIL analysis)"
    )
    parser.add_argument("binary",
                        help="Path to binary or .bndb database")
    parser.add_argument("--min-blocks", type=int, default=2,
                        help="Minimum basic blocks to consider (default: 2)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON (default: one name per line)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress to stderr")
    args = parser.parse_args()

    binary_path = args.binary
    if not Path(binary_path).exists():
        print(f"[!] Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    load_path, is_bndb = resolve_binary_path(binary_path)

    if args.verbose:
        print(f"[*] Loading {'database' if is_bndb else 'binary'}: {load_path}",
              file=sys.stderr)

    bv = binaryninja.load(load_path, update_analysis=not is_bndb)
    if bv is None:
        if is_bndb and load_path != binary_path:
            bv = binaryninja.load(binary_path)
        if bv is None:
            print(f"[!] Failed to load: {binary_path}", file=sys.stderr)
            sys.exit(1)

    results = find_loop_functions(bv, min_blocks=args.min_blocks,
                                  verbose=args.verbose)

    if args.json:
        mem_write_count = sum(1 for r in results if r["has_mem_write"])
        structured = sum(1 for r in results if r["loop_type"] == "structured")
        goto = sum(1 for r in results if r["loop_type"] == "goto")
        both = sum(1 for r in results if r["loop_type"] == "both")
        output = {
            "total_functions": len(bv.functions),
            "loop_functions": len(results),
            "loop_with_mem_write": mem_write_count,
            "by_type": {
                "structured": structured,
                "goto": goto,
                "both": both,
            },
            "functions": results,
        }
        print(json.dumps(output, indent=2))
    else:
        for r in results:
            print(r["name"])


if __name__ == "__main__":
    main()
