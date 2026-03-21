#!/usr/bin/env python3
"""
BinCodeQL Headless Fact Extraction — Walk MLIL-SSA objects via Binary Ninja API.

Runs as a subprocess (no MCP). Emits Souffle-compatible .facts files directly
from BN's MLIL-SSA instruction objects, bypassing text regex parsing.

Usage:
    python3 bn_extract_facts.py /path/to/binary -f main,process_data -o facts/
    python3 bn_extract_facts.py /path/to/binary --all -o facts/
    python3 bn_extract_facts.py /path/to/binary -f main -o facts/ -v --json
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

try:
    import binaryninja
    from binaryninja import (
        MediumLevelILOperation as MLIL,
        MediumLevelILInstruction,
    )
except ImportError:
    print("[!] Error: Binary Ninja Python API not available", file=sys.stderr)
    print("    Set BN_PYTHON or BN_PYTHON_PATH env var", file=sys.stderr)
    sys.exit(1)


def resolve_binary_path(binary_path: str, verbose: bool = False) -> tuple:
    """Resolve binary path, preferring .bndb sibling if it exists.

    Returns (resolved_path, is_bndb).

    Priority:
    1. If path ends with .bndb → use it directly
    2. If <path>.bndb exists → use .bndb (pre-analyzed, faster)
    3. Otherwise → use raw binary (BN will analyze from scratch)
    """
    if binary_path.lower().endswith('.bndb'):
        return binary_path, True

    bndb_sibling = binary_path + '.bndb'
    if Path(bndb_sibling).exists():
        if verbose:
            print(f"[*] Found .bndb database: {bndb_sibling}", file=sys.stderr)
        return bndb_sibling, True

    return binary_path, False


# ── Fact accumulator ──────────────────────────────────────────────────────────

class FactCollector:
    """Accumulates facts as tuples, keyed by relation name."""

    def __init__(self):
        self.facts = defaultdict(set)

    def add(self, relation: str, *columns):
        """Add a fact row. All columns are converted to strings."""
        self.facts[relation].add(tuple(str(c) for c in columns))

    # Canonical list of ALL .facts files that Souffle rules may expect.
    ALL_FACT_FILES = [
        "ActualArg.facts", "AddressOf.facts", "ArithOp.facts",
        "BufferWriteSource.facts",
        "CFGEdge.facts", "Call.facts", "Cast.facts",
        "DangerousSink.facts", "Def.facts",
        "EntryTaint.facts",
        "FieldRead.facts", "FieldWrite.facts", "FormalParam.facts",
        "Guard.facts", "Jump.facts", "MemRead.facts", "MemWrite.facts",
        "PhiSource.facts", "PointsTo.facts", "ReturnVal.facts",
        "StackVar.facts", "TaintKill.facts", "TaintSourceFunc.facts",
        "TaintTransfer.facts", "Use.facts", "VarWidth.facts",
    ]

    def write_all(self, output_dir: Path):
        """Write all accumulated facts to .facts files (TSV)."""
        output_dir.mkdir(parents=True, exist_ok=True)
        stats = {}
        for relation, rows in sorted(self.facts.items()):
            path = output_dir / f"{relation}.facts"
            sorted_rows = sorted(rows)
            with open(path, 'w') as f:
                for row in sorted_rows:
                    f.write('\t'.join(row) + '\n')
            stats[f"{relation}.facts"] = len(sorted_rows)

        # Ensure all schema relations have a .facts file (empty if no data)
        for filename in self.ALL_FACT_FILES:
            filepath = output_dir / filename
            if not filepath.exists():
                filepath.touch()

        return stats

    def summary(self):
        return {name: len(rows) for name, rows in sorted(self.facts.items())}


# ── SSA variable helpers ──────────────────────────────────────────────────────

def ssa_var_name(var):
    """Get the name string of an SSA variable."""
    if hasattr(var, 'var'):
        return var.var.name
    if hasattr(var, 'name'):
        return var.name
    return str(var)


def ssa_var_version(var):
    """Get the version of an SSA variable."""
    if hasattr(var, 'version'):
        return var.version
    return 0


def ssa_str(var):
    """Return 'name' for an SSA var."""
    return ssa_var_name(var)


# ── Expression walkers ────────────────────────────────────────────────────────

def collect_uses(fc, func_name, expr, addr):
    """Recursively collect Use facts from an MLIL-SSA expression."""
    if expr is None:
        return
    op = expr.operation

    if op == MLIL.MLIL_VAR_SSA:
        name = ssa_var_name(expr.src)
        ver = ssa_var_version(expr.src)
        fc.add("Use", func_name, name, ver, addr)
        return

    if op == MLIL.MLIL_VAR_SSA_FIELD:
        name = ssa_var_name(expr.src)
        ver = ssa_var_version(expr.src)
        fc.add("Use", func_name, name, ver, addr)
        return

    if op == MLIL.MLIL_ADDRESS_OF:
        # &var — the var itself is not "used" in the data-flow sense
        return

    if op == MLIL.MLIL_ADDRESS_OF_FIELD:
        return

    # Recurse into sub-expressions via operands
    for operand in expr.operands:
        if isinstance(operand, MediumLevelILInstruction):
            collect_uses(fc, func_name, operand, addr)
        elif isinstance(operand, list):
            for item in operand:
                if isinstance(item, MediumLevelILInstruction):
                    collect_uses(fc, func_name, item, addr)


# ── Comparison operator mapping for Guard extraction ─────────────────────────

COMPARISON_OPS = {
    MLIL.MLIL_CMP_SLT, MLIL.MLIL_CMP_ULT,
    MLIL.MLIL_CMP_SLE, MLIL.MLIL_CMP_ULE,
    MLIL.MLIL_CMP_SGT, MLIL.MLIL_CMP_UGT,
    MLIL.MLIL_CMP_SGE, MLIL.MLIL_CMP_UGE,
    MLIL.MLIL_CMP_E, MLIL.MLIL_CMP_NE,
}

COMPARISON_OP_MAP = {
    MLIL.MLIL_CMP_SLT: "slt", MLIL.MLIL_CMP_ULT: "ult",
    MLIL.MLIL_CMP_SLE: "sle", MLIL.MLIL_CMP_ULE: "ule",
    MLIL.MLIL_CMP_SGT: "sgt", MLIL.MLIL_CMP_UGT: "ugt",
    MLIL.MLIL_CMP_SGE: "sge", MLIL.MLIL_CMP_UGE: "uge",
    MLIL.MLIL_CMP_E: "eq", MLIL.MLIL_CMP_NE: "ne",
}

# Flipped operators for const OP var → var FLIPPED_OP const
COMPARISON_FLIP_MAP = {
    MLIL.MLIL_CMP_SLT: "sgt", MLIL.MLIL_CMP_ULT: "ugt",
    MLIL.MLIL_CMP_SLE: "sge", MLIL.MLIL_CMP_ULE: "uge",
    MLIL.MLIL_CMP_SGT: "slt", MLIL.MLIL_CMP_UGT: "ult",
    MLIL.MLIL_CMP_SGE: "sle", MLIL.MLIL_CMP_UGE: "ule",
    MLIL.MLIL_CMP_E: "eq", MLIL.MLIL_CMP_NE: "ne",
}


def resolve_callee(bv, insn):
    """Resolve the callee of a CALL instruction to a function name."""
    dest = insn.dest
    if dest.operation == MLIL.MLIL_CONST_PTR or dest.operation == MLIL.MLIL_CONST:
        target_addr = dest.constant
        funcs = bv.get_functions_containing(target_addr)
        if funcs:
            return funcs[0].name
        # Check imported symbol
        sym = bv.get_symbol_at(target_addr)
        if sym:
            return sym.name
        return hex(target_addr)
    if dest.operation == MLIL.MLIL_IMPORT:
        return dest.constant  # import address
    # Indirect call — can't resolve statically
    return "<indirect>"


# ── Main extraction logic ─────────────────────────────────────────────────────

def find_function(bv, name):
    """Find a function by name in the binary view."""
    funcs = bv.get_functions_by_name(name)
    if funcs:
        return funcs[0]
    return None


CAST_OPS = {
    MLIL.MLIL_SX: "sx",
    MLIL.MLIL_ZX: "zx",
    MLIL.MLIL_LOW_PART: "trunc",
}


def extract_function_facts(bv, func, fc, verbose=False):
    """Extract all facts from a single function's MLIL-SSA."""
    func_name = func.name

    if func.mlil is None:
        if verbose:
            print(f"  [SKIP] {func_name}: no MLIL available", file=sys.stderr)
        return

    try:
        mlil = func.mlil.ssa_form
    except Exception as e:
        if verbose:
            print(f"  [SKIP] {func_name}: SSA form error: {e}", file=sys.stderr)
        return

    if mlil is None:
        if verbose:
            print(f"  [SKIP] {func_name}: no SSA form", file=sys.stderr)
        return

    # Track version-0 vars for FormalParam detection
    defined_v0 = set()
    used_v0 = {}  # var_name -> min_addr

    for insn in mlil.instructions:
        addr = insn.address
        op = insn.operation

        # ── SET_VAR_SSA: var#ver = expr ──
        if op == MLIL.MLIL_SET_VAR_SSA:
            dst = insn.dest
            name = ssa_var_name(dst)
            ver = ssa_var_version(dst)
            fc.add("Def", func_name, name, ver, addr)
            if ver == 0:
                defined_v0.add(name)

            src = insn.src

            # Check for address-of
            if src.operation == MLIL.MLIL_ADDRESS_OF:
                target = src.src
                target_name = ssa_var_name(target) if hasattr(target, 'name') or hasattr(target, 'var') else str(target)
                fc.add("AddressOf", func_name, name, ver, target_name)
            elif src.operation == MLIL.MLIL_ADDRESS_OF_FIELD:
                target = src.src
                target_name = ssa_var_name(target) if hasattr(target, 'name') or hasattr(target, 'var') else str(target)
                fc.add("AddressOf", func_name, name, ver, target_name)

            # Check for arithmetic operation: var = var2 op const/var3
            ARITH_OPS = {
                MLIL.MLIL_ADD, MLIL.MLIL_SUB, MLIL.MLIL_MUL,
                MLIL.MLIL_LSL, MLIL.MLIL_LSR,
            }
            ARITH_OP_MAP = {
                MLIL.MLIL_ADD: "add", MLIL.MLIL_SUB: "sub",
                MLIL.MLIL_MUL: "mul", MLIL.MLIL_LSL: "lsl",
                MLIL.MLIL_LSR: "lsr",
            }
            if src.operation in ARITH_OPS:
                op_str = ARITH_OP_MAP[src.operation]
                left = src.left
                right = src.right
                if left.operation == MLIL.MLIL_VAR_SSA:
                    src_name = ssa_var_name(left.src)
                    src_ver = ssa_var_version(left.src)
                    if right.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                        operand = str(right.constant)
                    elif right.operation == MLIL.MLIL_VAR_SSA:
                        operand = ssa_var_name(right.src)
                    else:
                        operand = str(right)
                    fc.add("ArithOp", func_name, addr, name, ver,
                           op_str, src_name, src_ver, operand)
                elif right.operation == MLIL.MLIL_VAR_SSA:
                    # Commuted: const op var
                    src_name = ssa_var_name(right.src)
                    src_ver = ssa_var_version(right.src)
                    if left.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                        operand = str(left.constant)
                    else:
                        operand = str(left)
                    fc.add("ArithOp", func_name, addr, name, ver,
                           op_str, src_name, src_ver, operand)

            # Check for cast operation (sign-extend, zero-extend, truncation)
            if src.operation in CAST_OPS:
                cast_kind = CAST_OPS[src.operation]
                inner = src.src
                src_width = inner.size
                dst_width = src.size
                if inner.operation == MLIL.MLIL_VAR_SSA:
                    fc.add("Cast", func_name, addr, name, ver,
                           ssa_var_name(inner.src), ssa_var_version(inner.src),
                           cast_kind, src_width, dst_width)

            # Emit VarWidth for every defined variable
            try:
                fc.add("VarWidth", func_name, name, ver, dst.var.type.width)
            except (AttributeError, TypeError):
                # Fallback to expression size if type width unavailable
                try:
                    fc.add("VarWidth", func_name, name, ver, src.size)
                except (AttributeError, TypeError):
                    pass

            # Check for memory read: var = [expr].size
            if src.operation == MLIL.MLIL_LOAD_SSA:
                load_src = src.src
                fc.add("MemRead", func_name, addr, str(load_src), "0", str(src.size))
                fc.add("Use", func_name, "mem", ssa_var_version(src.src_memory), addr)

            # Collect uses from RHS
            collect_uses(fc, func_name, src, addr)
            continue

        # ── SET_VAR_SSA_FIELD: partial variable write ──
        if op == MLIL.MLIL_SET_VAR_SSA_FIELD:
            dst = insn.dest
            name = ssa_var_name(dst)
            ver = ssa_var_version(dst)
            fc.add("Def", func_name, name, ver, addr)
            if ver == 0:
                defined_v0.add(name)
            # Previous version is a use
            prev = insn.prev
            fc.add("Use", func_name, ssa_var_name(prev), ssa_var_version(prev), addr)
            collect_uses(fc, func_name, insn.src, addr)
            continue

        # ── VAR_PHI: var#N = phi(var#A, var#B, ...) ──
        if op == MLIL.MLIL_VAR_PHI:
            dst = insn.dest
            name = ssa_var_name(dst)
            ver = ssa_var_version(dst)
            fc.add("Def", func_name, name, ver, addr)
            if ver == 0:
                defined_v0.add(name)
            try:
                fc.add("VarWidth", func_name, name, ver, dst.var.type.width)
            except (AttributeError, TypeError):
                pass

            for src in insn.src:
                src_name = ssa_var_name(src)
                src_ver = ssa_var_version(src)
                fc.add("PhiSource", func_name, name, ver, src_name, src_ver)
                fc.add("Use", func_name, src_name, src_ver, addr)
                if src_ver == 0:
                    if src_name not in used_v0 or addr < used_v0[src_name]:
                        used_v0[src_name] = addr
            continue

        # ── CALL_SSA: ret, mem = callee(args) @ mem ──
        if op == MLIL.MLIL_CALL_SSA:
            callee = resolve_callee(bv, insn)
            fc.add("Call", func_name, callee, addr)

            # Output (return vars + mem)
            for out_var in insn.output:
                out_name = ssa_var_name(out_var)
                out_ver = ssa_var_version(out_var)
                fc.add("Def", func_name, out_name, out_ver, addr)
                if out_ver == 0:
                    defined_v0.add(out_name)
                try:
                    fc.add("VarWidth", func_name, out_name, out_ver,
                           out_var.var.type.width)
                except (AttributeError, TypeError):
                    pass

            # Memory SSA
            mem_out = insn.output_dest_memory
            mem_in = insn.src_memory
            fc.add("Def", func_name, "mem", mem_out, addr)
            fc.add("Use", func_name, "mem", mem_in, addr)

            # Arguments
            for i, arg in enumerate(insn.params):
                if arg.operation == MLIL.MLIL_VAR_SSA:
                    arg_name = ssa_var_name(arg.src)
                    arg_ver = ssa_var_version(arg.src)
                    fc.add("ActualArg", addr, i, "_", arg_name, arg_ver)
                    fc.add("Use", func_name, arg_name, arg_ver, addr)
                    if arg_ver == 0:
                        if arg_name not in used_v0 or addr < used_v0[arg_name]:
                            used_v0[arg_name] = addr
                else:
                    # Expression argument — collect uses, emit with placeholder
                    collect_uses(fc, func_name, arg, addr)
            continue

        # ── STORE_SSA: [addr_expr] = value @ mem#in -> mem#out ──
        if op == MLIL.MLIL_STORE_SSA:
            dest_expr = insn.dest
            src_expr = insn.src
            mem_in = insn.src_memory
            mem_out = insn.dest_memory

            fc.add("MemWrite", func_name, addr, str(dest_expr), mem_in, mem_out)
            fc.add("Def", func_name, "mem", mem_out, addr)
            fc.add("Use", func_name, "mem", mem_in, addr)
            collect_uses(fc, func_name, dest_expr, addr)
            collect_uses(fc, func_name, src_expr, addr)
            continue

        # ── STORE_STRUCT_SSA: base->field = value ──
        if op == MLIL.MLIL_STORE_STRUCT_SSA:
            base_expr = insn.dest
            offset = insn.offset
            src_expr = insn.src
            mem_in = insn.src_memory
            mem_out = insn.dest_memory

            fc.add("FieldWrite", func_name, addr, str(base_expr),
                    str(offset), mem_in, mem_out)
            fc.add("Def", func_name, "mem", mem_out, addr)
            fc.add("Use", func_name, "mem", mem_in, addr)
            collect_uses(fc, func_name, base_expr, addr)
            collect_uses(fc, func_name, src_expr, addr)
            continue

        # ── IF: conditional branch ──
        if op == MLIL.MLIL_IF:
            cond = insn.condition
            collect_uses(fc, func_name, cond, addr)

            # CFG edges — true and false targets
            true_bb = insn.true
            false_bb = insn.false
            # These are basic block indices; convert to addresses
            if true_bb < len(mlil.basic_blocks):
                fc.add("CFGEdge", func_name, addr, mlil.basic_blocks[true_bb].start)
            if false_bb < len(mlil.basic_blocks):
                fc.add("CFGEdge", func_name, addr, mlil.basic_blocks[false_bb].start)

            # Guard extraction: if condition is a comparison, emit Guard fact
            # Guard schema: func, addr, var, ver, op, bound, bound_type
            #   bound_type: "const" if bound is a literal, "var" if bound is a variable
            if cond.operation in COMPARISON_OPS:
                left = cond.left
                right = cond.right
                op_str = COMPARISON_OP_MAP[cond.operation]
                if left.operation == MLIL.MLIL_VAR_SSA:
                    var_name = ssa_var_name(left.src)
                    var_ver = ssa_var_version(left.src)
                    if right.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                        bound = str(right.constant)
                        bound_type = "const"
                    elif right.operation == MLIL.MLIL_VAR_SSA:
                        bound = ssa_var_name(right.src)
                        bound_type = "var"
                    else:
                        bound = str(right)
                        bound_type = "expr"
                    fc.add("Guard", func_name, addr, var_name, var_ver, op_str, bound, bound_type)
                elif right.operation == MLIL.MLIL_VAR_SSA and left.operation in (MLIL.MLIL_CONST, MLIL.MLIL_CONST_PTR):
                    # Reverse case: const OP var → emit as var FLIPPED_OP const
                    var_name = ssa_var_name(right.src)
                    var_ver = ssa_var_version(right.src)
                    bound = str(left.constant)
                    flipped = COMPARISON_FLIP_MAP.get(cond.operation, op_str)
                    fc.add("Guard", func_name, addr, var_name, var_ver, flipped, bound, "const")
            continue

        # ── GOTO ──
        if op == MLIL.MLIL_GOTO:
            target_bb = insn.dest
            if target_bb < len(mlil.basic_blocks):
                fc.add("CFGEdge", func_name, addr,
                        mlil.basic_blocks[target_bb].start)
            continue

        # ── RET: return expr ──
        if op == MLIL.MLIL_RET:
            for src in insn.src:
                if isinstance(src, MediumLevelILInstruction):
                    if src.operation == MLIL.MLIL_VAR_SSA:
                        rv_name = ssa_var_name(src.src)
                        rv_ver = ssa_var_version(src.src)
                        fc.add("ReturnVal", func_name, rv_name, rv_ver)
                        fc.add("Use", func_name, rv_name, rv_ver, addr)
                    else:
                        collect_uses(fc, func_name, src, addr)
            continue

        # ── JUMP: indirect jump ──
        if op == MLIL.MLIL_JUMP or op == MLIL.MLIL_JUMP_TO:
            fc.add("Jump", func_name, addr, str(insn.dest))
            collect_uses(fc, func_name, insn.dest, addr)
            continue

        # ── TAILCALL_SSA ──
        if op == MLIL.MLIL_TAILCALL_SSA:
            callee = resolve_callee(bv, insn)
            fc.add("Call", func_name, callee, addr)
            for i, arg in enumerate(insn.params):
                if arg.operation == MLIL.MLIL_VAR_SSA:
                    arg_name = ssa_var_name(arg.src)
                    arg_ver = ssa_var_version(arg.src)
                    fc.add("ActualArg", addr, i, "_", arg_name, arg_ver)
                    fc.add("Use", func_name, arg_name, arg_ver, addr)
                else:
                    collect_uses(fc, func_name, arg, addr)
            continue

        # Other operations: collect any uses generically
        for operand in insn.operands:
            if isinstance(operand, MediumLevelILInstruction):
                collect_uses(fc, func_name, operand, addr)

    # ── Track version-0 uses from all collected Use facts ──
    for row in fc.facts.get("Use", set()):
        # row = (func, var, ver, addr)
        if row[0] == func_name and row[2] == "0":
            vname = row[1]
            vaddr = int(row[3])
            if vname not in used_v0 or vaddr < used_v0[vname]:
                used_v0[vname] = vaddr

    # ── Stack variable info ──
    for var in func.stack_layout:
        fc.add("StackVar", func_name, var.name, var.storage, var.type.width)

    # ── Formal parameters ──
    for i, param in enumerate(func.parameter_vars):
        fc.add("FormalParam", func_name, param.name, i)
        try:
            fc.add("VarWidth", func_name, param.name, 0, param.type.width)
        except (AttributeError, TypeError):
            pass

    # ── Fallback FormalParam: version-0 used but not defined ──
    # (Catches cases where BN doesn't explicitly list parameters)
    params_already = {row[1] for row in fc.facts.get("FormalParam", set())
                      if row[0] == func_name}
    fallback_params = []
    for vname, min_addr in used_v0.items():
        if vname not in defined_v0 and vname != "mem" and vname not in params_already:
            fallback_params.append((min_addr, vname))
    fallback_params.sort()
    next_idx = len(params_already)
    for _, vname in fallback_params:
        fc.add("FormalParam", func_name, vname, next_idx)
        next_idx += 1


def extract_facts(bv, function_names, output_dir, verbose=False, extract_all=False):
    """Extract facts for specified functions (or all) and write to output_dir."""
    fc = FactCollector()

    if extract_all:
        targets = list(bv.functions)
        if verbose:
            print(f"[*] Extracting facts for ALL {len(targets)} functions", file=sys.stderr)
    else:
        targets = []
        for name in function_names:
            func = find_function(bv, name)
            if func:
                targets.append(func)
            elif verbose:
                print(f"  [WARN] Function not found: {name}", file=sys.stderr)

    for i, func in enumerate(targets):
        if verbose and (i % 50 == 0 or i == len(targets) - 1):
            print(f"  [{i+1}/{len(targets)}] {func.name}", file=sys.stderr)
        extract_function_facts(bv, func, fc, verbose=verbose)

    out = Path(output_dir)
    stats = fc.write_all(out)

    return {
        "functions_processed": len(targets),
        "relations": stats,
        "total_facts": sum(stats.values()),
        "facts_dir": str(out),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="BinCodeQL: Extract Datalog facts from a binary via Binary Ninja headless API"
    )
    parser.add_argument("binary", help="Path to binary or .bndb database (auto-detects .bndb sibling)")
    parser.add_argument("-f", "--functions",
                        help="Comma-separated function names to extract")
    parser.add_argument("--all", action="store_true",
                        help="Extract facts for ALL functions")
    parser.add_argument("-o", "--output", default="facts",
                        help="Output directory for .facts files (default: facts)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print progress to stderr")
    parser.add_argument("--json", action="store_true",
                        help="Print JSON summary to stdout")
    args = parser.parse_args()

    if not args.functions and not args.all:
        parser.error("Specify -f FUNC1,FUNC2 or --all")

    binary_path = args.binary
    if not Path(binary_path).exists():
        print(f"[!] Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    load_path, is_bndb = resolve_binary_path(binary_path, args.verbose)

    if args.verbose:
        print(f"[*] Loading {'database' if is_bndb else 'binary'}: {load_path}", file=sys.stderr)

    bv = binaryninja.load(load_path, update_analysis=not is_bndb)
    if bv is None:
        # Fallback: if .bndb failed, try raw binary
        if is_bndb and load_path != binary_path:
            if args.verbose:
                print(f"[*] .bndb load failed, falling back to raw binary", file=sys.stderr)
            bv = binaryninja.load(binary_path)
        if bv is None:
            print(f"[!] Failed to load: {binary_path}", file=sys.stderr)
            sys.exit(1)

    if args.verbose:
        mode = "database" if is_bndb else "binary"
        print(f"[*] Loaded {mode}: {len(bv.functions)} functions", file=sys.stderr)

    function_names = []
    if args.functions:
        function_names = [n.strip() for n in args.functions.split(",")]

    result = extract_facts(
        bv, function_names, args.output,
        verbose=args.verbose, extract_all=args.all,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"Extracted {result['total_facts']} facts from "
              f"{result['functions_processed']} functions", file=sys.stderr)
        for name, count in sorted(result['relations'].items()):
            print(f"  {name:25s} {count} rows", file=sys.stderr)


if __name__ == "__main__":
    main()
