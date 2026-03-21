"""
Fact Writer — Serializes parsed MLIL-SSA facts to Souffle-compatible TSV files.

Each fact kind maps to a .facts file in the output directory.
"""

import os
from pathlib import Path
from mlil_parser import Fact, FactKind


# Map FactKind → (filename, column_extractor)
# Column extractor returns a tuple of strings for each fact.
RELATION_SCHEMA = {
    FactKind.DEF: ("Def.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["ver"]), str(f.addr)
    )),
    FactKind.USE: ("Use.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["ver"]), str(f.addr)
    )),
    FactKind.CALL: ("Call.facts", lambda f: (
        f.func, f.fields["callee"], str(f.addr)
    )),
    FactKind.ACTUAL_ARG: ("ActualArg.facts", lambda f: (
        str(f.addr), str(f.fields["arg_idx"]),
        f.fields["param"], f.fields["var"], str(f.fields["ver"])
    ) if f.fields["ver"] >= 0 else None),  # skip literal args (ver=-1)
    FactKind.RETURN_VAL: ("ReturnVal.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["ver"])
    )),
    FactKind.PHI_SOURCE: ("PhiSource.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["def_ver"]),
        f.fields["src_var"], str(f.fields["src_ver"])
    )),
    FactKind.MEM_READ: ("MemRead.facts", lambda f: (
        f.func, str(f.addr), f.fields["base"],
        str(f.fields.get("offset", "0")), f.fields.get("size", "?")
    )),
    FactKind.MEM_WRITE: ("MemWrite.facts", lambda f: (
        f.func, str(f.addr), f.fields["target"],
        str(f.fields.get("mem_in", 0)), str(f.fields.get("mem_out", 0))
    )),
    FactKind.FIELD_READ: ("FieldRead.facts", lambda f: (
        f.func, str(f.addr), f.fields["base"], f.fields["field"]
    )),
    FactKind.FIELD_WRITE: ("FieldWrite.facts", lambda f: (
        f.func, str(f.addr), f.fields["base"], f.fields["field"],
        str(f.fields["mem_in"]), str(f.fields["mem_out"])
    )),
    FactKind.ADDRESS_OF: ("AddressOf.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["ver"]), f.fields["target"]
    )),
    FactKind.CFG_EDGE: ("CFGEdge.facts", lambda f: (
        f.func, str(f.addr), str(f.fields["to_addr"])
    )),
    FactKind.JUMP: ("Jump.facts", lambda f: (
        f.func, str(f.addr), f.fields["expr"]
    )),
    FactKind.FORMAL_PARAM: ("FormalParam.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["idx"])
    )),
    FactKind.STACK_VAR: ("StackVar.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["offset"]), str(f.fields["size"])
    )),
    FactKind.GUARD: ("Guard.facts", lambda f: (
        f.func, str(f.addr), f.fields["var"], str(f.fields["ver"]),
        f.fields["op"], f.fields["bound"],
        f.fields.get("bound_type", "unknown")
    )),
    FactKind.ARITH_OP: ("ArithOp.facts", lambda f: (
        f.func, str(f.addr), f.fields["dst_var"], str(f.fields["dst_ver"]),
        f.fields["op"], f.fields["src_var"], str(f.fields["src_ver"]),
        f.fields["operand"]
    )),
    FactKind.CAST: ("Cast.facts", lambda f: (
        f.func, str(f.addr), f.fields["dst"], str(f.fields["dst_ver"]),
        f.fields["src"], str(f.fields["src_ver"]),
        f.fields["kind"], str(f.fields["src_width"]), str(f.fields["dst_width"])
    )),
    FactKind.VAR_WIDTH: ("VarWidth.facts", lambda f: (
        f.func, f.fields["var"], str(f.fields["ver"]), str(f.fields["width"])
    )),
}

# Canonical list of ALL .facts files that Souffle rules may expect.
# After writing populated facts, empty files are created for any missing
# relations to prevent Souffle crashes on missing .input files.
ALL_FACT_FILES = sorted(set(
    filename for filename, _ in RELATION_SCHEMA.values()
) | {
    "ArithOp.facts", "Cast.facts", "DangerousSink.facts", "EntryTaint.facts",
    "TaintSourceFunc.facts", "TaintTransfer.facts", "BufferWriteSource.facts",
    "PointsTo.facts", "StackVar.facts", "TaintKill.facts", "Guard.facts",
    "VarWidth.facts",
})


# Schema documentation: maps FactKind to column names for agent/LLM reference
SCHEMA_DOCS = {
    FactKind.DEF: ["func", "var", "ver", "addr"],
    FactKind.USE: ["func", "var", "ver", "addr"],
    FactKind.CALL: ["caller", "callee", "addr"],
    FactKind.ACTUAL_ARG: ["call_addr", "arg_idx", "param", "var", "ver"],
    FactKind.RETURN_VAL: ["func", "var", "ver"],
    FactKind.PHI_SOURCE: ["func", "var", "def_ver", "src_var", "src_ver"],
    FactKind.MEM_READ: ["func", "addr", "base", "offset", "size"],
    FactKind.MEM_WRITE: ["func", "addr", "target", "mem_in", "mem_out"],
    FactKind.FIELD_READ: ["func", "addr", "base", "field"],
    FactKind.FIELD_WRITE: ["func", "addr", "base", "field", "mem_in", "mem_out"],
    FactKind.ADDRESS_OF: ["func", "var", "ver", "target"],
    FactKind.CFG_EDGE: ["func", "from_addr", "to_addr"],
    FactKind.JUMP: ["func", "addr", "expr"],
    FactKind.FORMAL_PARAM: ["func", "var", "idx"],
    FactKind.STACK_VAR: ["func", "var", "offset", "size"],
    FactKind.GUARD: ["func", "addr", "var", "ver", "op", "bound", "bound_type"],
    FactKind.ARITH_OP: ["func", "addr", "dst", "dst_ver", "op", "src", "src_ver", "operand"],
    FactKind.CAST: ["func", "addr", "dst", "dst_ver", "src", "src_ver", "kind", "src_width", "dst_width"],
    FactKind.VAR_WIDTH: ["func", "var", "ver", "width"],
}


def write_facts(
    facts: list[Fact],
    output_dir: str | Path,
    append: bool = False,
) -> dict[str, int]:
    """Write facts to TSV files in output_dir.

    Args:
        facts: List of Fact instances to write.
        output_dir: Directory for .facts files.
        append: If True, read existing .facts rows first and merge with
                new rows (deduplicated). If False, overwrite files.

    Returns dict of filename → number of rows written.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Group facts by kind
    grouped: dict[FactKind, list[Fact]] = {}
    for f in facts:
        grouped.setdefault(f.kind, []).append(f)

    stats = {}
    for kind, kind_facts in grouped.items():
        schema = RELATION_SCHEMA.get(kind)
        if not schema:
            print(f"  [WARN] No schema for {kind.value}, skipping {len(kind_facts)} facts")
            continue

        filename, extractor = schema
        filepath = output_dir / filename

        # If append mode, seed rows from existing file
        rows = set()
        if append and filepath.exists():
            existing = filepath.read_text().strip()
            if existing:
                for line in existing.split('\n'):
                    rows.add(tuple(line.split('\t')))

        for f in kind_facts:
            try:
                row = extractor(f)
                if row is not None:
                    rows.add(row)
            except (KeyError, TypeError) as e:
                print(f"  [WARN] Failed to extract {kind.value} fact: {e}")

        # Sort for reproducibility
        sorted_rows = sorted(rows)

        with open(filepath, 'w') as fp:
            for row in sorted_rows:
                fp.write('\t'.join(row) + '\n')

        stats[filename] = len(sorted_rows)

    # Ensure all schema relations have a .facts file (empty if no data)
    for filename in ALL_FACT_FILES:
        filepath = output_dir / filename
        if not filepath.exists():
            filepath.touch()

    return stats


if __name__ == "__main__":
    import sys
    from mlil_parser import parse_mlil_ssa

    if len(sys.argv) < 3:
        print("Usage: python fact_writer.py <sample.mlil_ssa> <output_dir> [func_name]")
        sys.exit(1)

    from pathlib import Path
    path = Path(sys.argv[1])
    output_dir = sys.argv[2]
    func_name = sys.argv[3] if len(sys.argv) > 3 else path.stem

    text = path.read_text()
    facts = parse_mlil_ssa(func_name, text)
    stats = write_facts(facts, output_dir)

    print(f"\nWrote facts to {output_dir}/:")
    for filename, count in sorted(stats.items()):
        print(f"  {filename:25s} {count} rows")
