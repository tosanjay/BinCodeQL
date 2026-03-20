"""
Resolve hex-address callees to function names using BN MCP.

Reads Call.facts, resolves unknown callees, writes:
  - FunctionAddr.facts: maps function names to addresses
  - Call.facts: updated with resolved names where possible
"""

import json
import re
import sys
from pathlib import Path


def resolve_call_targets(facts_dir: str, addr_to_name: dict[str, str]) -> None:
    """Rewrite Call.facts replacing hex addresses with resolved names."""
    facts_dir = Path(facts_dir)
    call_file = facts_dir / "Call.facts"

    if not call_file.exists():
        print("No Call.facts found")
        return

    lines = call_file.read_text().strip().split('\n')
    resolved_count = 0
    new_lines = []

    for line in lines:
        parts = line.split('\t')
        if len(parts) >= 2:
            callee = parts[1]
            if callee.startswith("0x") and callee in addr_to_name:
                parts[1] = addr_to_name[callee]
                resolved_count += 1
        new_lines.append('\t'.join(parts))

    call_file.write_text('\n'.join(new_lines) + '\n')
    print(f"Resolved {resolved_count}/{len(lines)} call targets")

    # Write FunctionAddr.facts for Souffle to use
    func_addr_file = facts_dir / "FunctionAddr.facts"
    rows = set()
    for addr_hex, name in addr_to_name.items():
        addr_dec = str(int(addr_hex, 16))
        rows.add(f"{name}\t{addr_dec}")

    sorted_rows = sorted(rows)
    func_addr_file.write_text('\n'.join(sorted_rows) + '\n')
    print(f"Wrote {len(sorted_rows)} entries to FunctionAddr.facts")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python resolve_calls.py <facts_dir> <addr_map.json>")
        print("  addr_map.json: {\"0x401000\": \"main\", \"0x402000\": \"memcpy\", ...}")
        sys.exit(1)

    facts_dir = sys.argv[1]
    with open(sys.argv[2]) as f:
        addr_map = json.load(f)
    resolve_call_targets(facts_dir, addr_map)
