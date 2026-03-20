"""
MLIL-SSA Parser — Parses Binary Ninja MLIL-SSA text output into typed fact tuples.

Input:  Text from BN MCP `get_il(func, "mlil", true)`
Output: List of Fact dataclass instances ready for TSV serialization.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class FactKind(Enum):
    DEF = "Def"
    USE = "Use"
    CALL = "Call"
    ACTUAL_ARG = "ActualArg"
    RETURN_VAL = "ReturnVal"
    PHI_SOURCE = "PhiSource"
    MEM_READ = "MemRead"
    MEM_WRITE = "MemWrite"
    ADDRESS_OF = "AddressOf"
    CFG_EDGE = "CFGEdge"
    FIELD_READ = "FieldRead"
    FIELD_WRITE = "FieldWrite"
    JUMP = "Jump"
    FORMAL_PARAM = "FormalParam"
    STACK_VAR = "StackVar"
    GUARD = "Guard"
    ARITH_OP = "ArithOp"
    CAST = "Cast"
    VAR_WIDTH = "VarWidth"


@dataclass
class Fact:
    kind: FactKind
    func: str
    addr: int
    fields: dict = field(default_factory=dict)

    def __repr__(self):
        fstr = ", ".join(f"{k}={v}" for k, v in self.fields.items())
        return f"{self.kind.value}({self.func}, 0x{self.addr:x}, {fstr})"


# ── Regex patterns ──────────────────────────────────────────────────────────

# Line format: hex_addr followed by spaces then statement
LINE_RE = re.compile(r'^([0-9a-f]{8,16})\s{2,}(.+)$')

# SSA variable: name#version (negative lookbehind for & to avoid &symbol)
# Allows colons in names for BN condition vars like cond:0_1#7
SSA_VAR_RE = re.compile(r'(?<![&\w])(\w+(?:[:_]\w+)*)#(\d+)')

# Phi node: var#N = ϕ(sources...)  — allows colons in var names
PHI_RE = re.compile(r'^([\w:]+)#(\d+)\s*=\s*[ϕφ]\((.+)\)$')

# Return: return expr
RETURN_RE = re.compile(r'^return\s+(.+)$')

# Noreturn marker
NORETURN_RE = re.compile(r'^noreturn$')

# Unconditional goto: goto N @ 0xaddr
GOTO_RE = re.compile(r'^goto\s+\d+\s*@\s*(0x[0-9a-f]+)$')

# Conditional branch: if (cond) then N [@ addr] else M @ addr
#   Some targets may not have @ addr
COND_RE = re.compile(
    r'^if\s*\((.+)\)\s*then\s+\d+(?:\s*@\s*(0x[0-9a-f]+))?\s*else\s+\d+(?:\s*@\s*(0x[0-9a-f]+))?$'
)

# Jump (indirect): jump(expr)
JUMP_RE = re.compile(r'^jump\((.+)\)$')

# Address-of: var#N = &symbol  or  var#N = &symbol[offset]  or  &symbol:N
ADDR_OF_RE = re.compile(r'^([\w:]+)#(\d+)\s*=\s*&(\w+(?:[:\[\d\]]+)?)$')

# Memory write (struct field store): base#N->field = val @ mem#J -> mem#K
# Allows dotted field names like zstream.next_in, flags+2.b
FIELD_WRITE_RE = re.compile(
    r'^(.+)->([\w.+]+)\s*=\s*(.+)\s*@\s*mem#(\d+)\s*->\s*mem#(\d+)$'
)

# Memory write (store via ptr deref): [expr].size = val @ mem#J -> mem#K
BRACKET_WRITE_RE = re.compile(
    r'^\[(.+)\]\.\w+\s*=\s*(.+)\s*@\s*mem#(\d+)\s*->\s*mem#(\d+)$'
)

# Memory write (generic): target @ mem#J -> mem#K = value
MEM_WRITE_RE = re.compile(
    r'^(.+)\s*@\s*mem#(\d+)\s*->\s*mem#(\d+)\s*=\s*(.+)$'
)

# Call with return values: ret#N, mem#M = callee(args) @ mem#J
# Also handles: ret#N, mem#M = 0xaddr(args) @ mem#J
CALL_WITH_RET_RE = re.compile(
    r'^(.+),\s*mem#(\d+)\s*=\s*(0x[0-9a-f]+|\w+)\((.*)?\)\s*@\s*mem#(\d+)$'
)

# Void call: mem#M = callee(args) @ mem#J
VOID_CALL_RE = re.compile(
    r'^mem#(\d+)\s*=\s*(0x[0-9a-f]+|\w+)\((.*)\)\s*@\s*mem#(\d+)$'
)

# Struct field read: var#N = base#M->field @ mem#K
# Allows dotted field names like zstream.msg, color_type, flags+2.b
FIELD_READ_RE = re.compile(
    r'^([\w:]+)#(\d+)\s*=\s*(.+)->([\w.+]+)\s*@\s*mem#(\d+)$'
)

# Memory read (bracket): var#N = [base + offset].size @ mem#K
MEM_READ_RE = re.compile(
    r'^([\w:]+)#(\d+)\s*=\s*\[(.+)\]\.(\w+)\s*@\s*mem#(\d+)$'
)

# Array read: var#N = name[idx].size @ mem#K
ARRAY_READ_RE = re.compile(
    r'^([\w:]+)#(\d+)\s*=\s*(\w+)\[([^\]]+)\]\.(\w+)\s*@\s*mem#(\d+)$'
)

# Comparison pattern for Guard extraction from IF conditions:
# var#ver op literal  or  var#ver op var2#ver2
# Operators: <, <=, >, >=, ==, != (signed/unsigned variants in text form)
COMPARE_RE = re.compile(
    r'(\w+(?:[:_]\w+)*)#(\d+)\s*([<>=!]=?|[su][<>]=?)\s*(.+)'
)


def _parse_hex(s: str) -> int:
    """Parse hex string (with or without 0x prefix) to int."""
    return int(s, 16)


def _extract_ssa_vars(expr: str) -> list[tuple[str, int]]:
    """Extract all SSA variable references from an expression."""
    return [(m.group(1), int(m.group(2))) for m in SSA_VAR_RE.finditer(expr)]


def _parse_call_args(args_str: str) -> list[tuple[Optional[str], str, int]]:
    """Parse call arguments. Returns list of (param_name, var, version).

    Handles both named (param: var#N) and positional (var#N) args.
    Also handles literal arguments (0, "string", 0x...).
    """
    if not args_str or not args_str.strip():
        return []

    results = []
    # Split on comma but respect nested parens and quotes
    depth = 0
    in_str = False
    current = []
    for ch in args_str:
        if ch == '"':
            in_str = not in_str
        if not in_str:
            if ch in '(':
                depth += 1
            elif ch in ')':
                depth -= 1
            elif ch == ',' and depth == 0:
                results.append(''.join(current).strip())
                current = []
                continue
        current.append(ch)
    if current:
        results.append(''.join(current).strip())

    parsed = []
    for i, arg in enumerate(results):
        # Named arg: param_name: var#N
        named = re.match(r'^(\w+):\s*(.+)$', arg)
        if named:
            param_name = named.group(1)
            val = named.group(2).strip()
        else:
            param_name = None
            val = arg.strip()

        # Extract SSA var from the value
        ssa = SSA_VAR_RE.search(val)
        if ssa:
            parsed.append((param_name, ssa.group(1), int(ssa.group(2))))
        else:
            # Literal argument (0, "string", 0x...)
            parsed.append((param_name, val, -1))

    return parsed


def parse_mlil_ssa(func_name: str, text: str) -> list[Fact]:
    """Parse MLIL-SSA text output into a list of Fact tuples.

    Args:
        func_name: Name of the function being parsed.
        text: Raw MLIL-SSA text from BN MCP get_il().

    Returns:
        List of Fact instances.
    """
    facts = []

    def emit(kind, addr, **kw):
        facts.append(Fact(kind=kind, func=func_name, addr=addr, fields=kw))

    lines = text.strip().split('\n')
    for raw_line in lines:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        # Skip file header line
        if raw_line.startswith("File:"):
            continue

        lm = LINE_RE.match(raw_line)
        if not lm:
            continue

        addr = _parse_hex(lm.group(1))
        stmt = lm.group(2).strip()

        # ── 1. Skip markers ──
        if NORETURN_RE.match(stmt):
            continue

        # ── 2. Phi node ──
        pm = PHI_RE.match(stmt)
        if pm:
            var, ver = pm.group(1), int(pm.group(2))
            emit(FactKind.DEF, addr, var=var, ver=ver)
            # Parse phi sources
            for sm in SSA_VAR_RE.finditer(pm.group(3)):
                src_var, src_ver = sm.group(1), int(sm.group(2))
                emit(FactKind.PHI_SOURCE, addr,
                     var=var, def_ver=ver, src_var=src_var, src_ver=src_ver)
            continue

        # ── 3. Memory/field write: base->field = val @ mem#J -> mem#K ──
        fwm = FIELD_WRITE_RE.match(stmt)
        if fwm:
            base_expr, field_name = fwm.group(1), fwm.group(2)
            val_expr = fwm.group(3)
            mem_in, mem_out = int(fwm.group(4)), int(fwm.group(5))
            emit(FactKind.FIELD_WRITE, addr,
                 base=base_expr, field=field_name,
                 mem_in=mem_in, mem_out=mem_out)
            emit(FactKind.DEF, addr, var="mem", ver=mem_out)
            emit(FactKind.USE, addr, var="mem", ver=mem_in)
            # Uses in base and value expressions
            for v, vv in _extract_ssa_vars(base_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            for v, vv in _extract_ssa_vars(val_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 3b. Bracketed store: [expr].size = val @ mem#J -> mem#K ──
        bwm = BRACKET_WRITE_RE.match(stmt)
        if bwm:
            target_expr = bwm.group(1)
            val_expr = bwm.group(2)
            mem_in, mem_out = int(bwm.group(3)), int(bwm.group(4))
            emit(FactKind.MEM_WRITE, addr,
                 target=target_expr, mem_in=mem_in, mem_out=mem_out)
            emit(FactKind.DEF, addr, var="mem", ver=mem_out)
            emit(FactKind.USE, addr, var="mem", ver=mem_in)
            for v, vv in _extract_ssa_vars(target_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            for v, vv in _extract_ssa_vars(val_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 4. Generic memory write: expr @ mem#J -> mem#K = val ──
        mwm = MEM_WRITE_RE.match(stmt)
        if mwm:
            target_expr = mwm.group(1)
            mem_in, mem_out = int(mwm.group(2)), int(mwm.group(3))
            val_expr = mwm.group(4)
            emit(FactKind.MEM_WRITE, addr,
                 target=target_expr, mem_in=mem_in, mem_out=mem_out)
            emit(FactKind.DEF, addr, var="mem", ver=mem_out)
            emit(FactKind.USE, addr, var="mem", ver=mem_in)
            for v, vv in _extract_ssa_vars(target_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            for v, vv in _extract_ssa_vars(val_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 5. Goto ──
        gm = GOTO_RE.match(stmt)
        if gm:
            target = _parse_hex(gm.group(1))
            emit(FactKind.CFG_EDGE, addr, to_addr=target)
            continue

        # ── 6. Conditional branch ──
        cm = COND_RE.match(stmt)
        if cm:
            cond_expr = cm.group(1)
            then_addr = _parse_hex(cm.group(2)) if cm.group(2) else None
            else_addr = _parse_hex(cm.group(3)) if cm.group(3) else None
            if then_addr:
                emit(FactKind.CFG_EDGE, addr, to_addr=then_addr)
            if else_addr:
                emit(FactKind.CFG_EDGE, addr, to_addr=else_addr)
            for v, vv in _extract_ssa_vars(cond_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            # Extract Guard fact from comparison in condition
            cmp_m = COMPARE_RE.match(cond_expr)
            if cmp_m:
                g_var, g_ver = cmp_m.group(1), int(cmp_m.group(2))
                g_op = cmp_m.group(3)
                g_bound = cmp_m.group(4).strip()
                emit(FactKind.GUARD, addr,
                     var=g_var, ver=g_ver, op=g_op, bound=g_bound)
            continue

        # ── 7. Jump (indirect) ──
        jm = JUMP_RE.match(stmt)
        if jm:
            emit(FactKind.JUMP, addr, expr=jm.group(1))
            for v, vv in _extract_ssa_vars(jm.group(1)):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 8. Return ──
        rm = RETURN_RE.match(stmt)
        if rm:
            ret_expr = rm.group(1)
            for v, vv in _extract_ssa_vars(ret_expr):
                emit(FactKind.RETURN_VAL, addr, var=v, ver=vv)
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 9. Address-of ──
        am = ADDR_OF_RE.match(stmt)
        if am:
            var, ver, target = am.group(1), int(am.group(2)), am.group(3)
            emit(FactKind.DEF, addr, var=var, ver=ver)
            emit(FactKind.ADDRESS_OF, addr, var=var, ver=ver, target=target)
            continue

        # ── 10. Call with return value(s) ──
        crm = CALL_WITH_RET_RE.match(stmt)
        if crm:
            ret_vars_str = crm.group(1)
            mem_out = int(crm.group(2))
            callee = crm.group(3)
            args_str = crm.group(4) or ""
            mem_in = int(crm.group(5))

            emit(FactKind.CALL, addr, callee=callee)
            emit(FactKind.DEF, addr, var="mem", ver=mem_out)
            emit(FactKind.USE, addr, var="mem", ver=mem_in)

            # Parse return variables (before the ", mem#N")
            for rv, rvv in _extract_ssa_vars(ret_vars_str):
                emit(FactKind.DEF, addr, var=rv, ver=rvv)

            # Parse arguments
            for idx, (param, avar, aver) in enumerate(_parse_call_args(args_str)):
                emit(FactKind.ACTUAL_ARG, addr,
                     arg_idx=idx, param=param or "_", var=avar, ver=aver)
                if aver >= 0:
                    emit(FactKind.USE, addr, var=avar, ver=aver)
            continue

        # ── 11. Void call ──
        vcm = VOID_CALL_RE.match(stmt)
        if vcm:
            mem_out = int(vcm.group(1))
            callee = vcm.group(2)
            args_str = vcm.group(3)
            mem_in = int(vcm.group(4))

            emit(FactKind.CALL, addr, callee=callee)
            emit(FactKind.DEF, addr, var="mem", ver=mem_out)
            emit(FactKind.USE, addr, var="mem", ver=mem_in)

            for idx, (param, avar, aver) in enumerate(_parse_call_args(args_str)):
                emit(FactKind.ACTUAL_ARG, addr,
                     arg_idx=idx, param=param or "_", var=avar, ver=aver)
                if aver >= 0:
                    emit(FactKind.USE, addr, var=avar, ver=aver)
            continue

        # ── 12. Field read: var#N = base->field @ mem#K ──
        frm = FIELD_READ_RE.match(stmt)
        if frm:
            var, ver = frm.group(1), int(frm.group(2))
            base_expr, field_name = frm.group(3), frm.group(4)
            mem_ver = int(frm.group(5))
            emit(FactKind.DEF, addr, var=var, ver=ver)
            emit(FactKind.FIELD_READ, addr,
                 var=var, ver=ver, base=base_expr, field=field_name)
            emit(FactKind.USE, addr, var="mem", ver=mem_ver)
            for v, vv in _extract_ssa_vars(base_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 13. Array read: var#N = name[idx].size @ mem#K ──
        arm = ARRAY_READ_RE.match(stmt)
        if arm:
            var, ver = arm.group(1), int(arm.group(2))
            arr_name, idx_expr, size = arm.group(3), arm.group(4), arm.group(5)
            mem_ver = int(arm.group(6))
            emit(FactKind.DEF, addr, var=var, ver=ver)
            emit(FactKind.MEM_READ, addr,
                 var=var, ver=ver, base=arr_name, offset=idx_expr, size=size)
            emit(FactKind.USE, addr, var="mem", ver=mem_ver)
            for v, vv in _extract_ssa_vars(idx_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 14. Memory read (bracket form): var#N = [expr].size @ mem#K ──
        mrm = MEM_READ_RE.match(stmt)
        if mrm:
            var, ver = mrm.group(1), int(mrm.group(2))
            addr_expr, size = mrm.group(3), mrm.group(4)
            mem_ver = int(mrm.group(5))
            emit(FactKind.DEF, addr, var=var, ver=ver)
            emit(FactKind.MEM_READ, addr,
                 var=var, ver=ver, base=addr_expr, offset="0", size=size)
            emit(FactKind.USE, addr, var="mem", ver=mem_ver)
            for v, vv in _extract_ssa_vars(addr_expr):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 14b. Subfield write: var#N:0.q = expr @ var#M ──
        # Partial register/variable write — treat as assignment
        sfm = re.match(r'^([\w:]+)#(\d+):\d+\.\w+\s*=\s*(.+)\s*@\s*[\w:]+#(\d+)$', stmt)
        if sfm:
            var, ver = sfm.group(1), int(sfm.group(2))
            rhs = sfm.group(3)
            emit(FactKind.DEF, addr, var=var, ver=ver)
            for v, vv in _extract_ssa_vars(rhs):
                emit(FactKind.USE, addr, var=v, ver=vv)
            continue

        # ── 15. Plain assignment (fallback) ──
        # var#N = expr  — allows colons in var names (cond:0_1#7)
        assign = re.match(r'^([\w:]+)#(\d+)\s*=\s*(.+)$', stmt)
        if assign:
            var, ver = assign.group(1), int(assign.group(2))
            rhs = assign.group(3)
            emit(FactKind.DEF, addr, var=var, ver=ver)
            for v, vv in _extract_ssa_vars(rhs):
                emit(FactKind.USE, addr, var=v, ver=vv)
            # Detect ArithOp: var#N = var2#M op literal  (or var op var)
            arith_m = re.match(
                r'^([\w:]+)#(\d+)\s*([+\-*]|<<|>>)\s*(.+)$', rhs
            )
            if arith_m:
                src_var, src_ver = arith_m.group(1), int(arith_m.group(2))
                op_char = arith_m.group(3)
                operand_str = arith_m.group(4).strip()
                op_map = {'+': 'add', '-': 'sub', '*': 'mul',
                          '<<': 'lsl', '>>': 'lsr'}
                op_name = op_map.get(op_char, op_char)
                emit(FactKind.ARITH_OP, addr,
                     dst_var=var, dst_ver=ver, op=op_name,
                     src_var=src_var, src_ver=src_ver, operand=operand_str)
            continue

        # If we get here, line was not parsed — log it
        print(f"  [UNPARSED] {func_name} @ 0x{addr:x}: {stmt}")

    # ── Post-pass: identify formal parameters ──────────────────────────
    # In MLIL-SSA, function parameters are version-0 variables that appear
    # in Use facts but have no corresponding Def. We exclude "mem" (memory
    # state SSA var). Sort by lowest use address to assign positional index.
    defined_v0 = set()
    used_v0 = {}  # var -> min use addr
    for f in facts:
        if f.kind == FactKind.DEF and f.fields.get("ver") == 0:
            defined_v0.add(f.fields["var"])
        if f.kind == FactKind.USE and f.fields.get("ver") == 0:
            var = f.fields["var"]
            if var not in used_v0 or f.addr < used_v0[var]:
                used_v0[var] = f.addr

    params = []
    for var, min_addr in used_v0.items():
        if var not in defined_v0 and var != "mem":
            params.append((min_addr, var))
    params.sort()  # sort by first use address for positional ordering

    for idx, (min_addr, var) in enumerate(params):
        emit(FactKind.FORMAL_PARAM, min_addr, var=var, idx=idx)

    return facts


# ── CLI test ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path

    if len(sys.argv) < 2:
        print("Usage: python mlil_parser.py <sample.mlil_ssa> [func_name]")
        sys.exit(1)

    path = Path(sys.argv[1])
    func_name = sys.argv[2] if len(sys.argv) > 2 else path.stem
    text = path.read_text()

    facts = parse_mlil_ssa(func_name, text)
    print(f"\n{'='*70}")
    print(f"Parsed {len(facts)} facts from {func_name}")
    print(f"{'='*70}")

    # Group by kind for readability
    from collections import Counter
    counts = Counter(f.kind.value for f in facts)
    print("\nFact counts:")
    for kind, count in sorted(counts.items()):
        print(f"  {kind:15s} {count}")

    print(f"\nAll facts:")
    for f in facts:
        print(f"  {f}")
