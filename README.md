# BinCodeQL

```
 ____  _        ____          _        ___  _
| __ )(_)_ __  / ___|___   __| | ___  / _ \| |
|  _ \| | '_ \| |   / _ \ / _` |/ _ \| | | | |
| |_) | | | | | |__| (_) | (_| |  __/| |_| | |___
|____/|_|_| |_|\____\___/ \__,_|\___| \__\_\_____|

      LLM  <=>  Datalog/Souffle + Binary Ninja
      ==========================================
           Binary Vulnerability Research
```

Datalog-powered query engine for vulnerability research on compiled binaries.

BinCodeQL extracts structured facts from Binary Ninja's MLIL-SSA intermediate representation and runs [Souffle](https://souffle-lang.github.io/) Datalog queries over them. An LLM agent (via [Google ADK](https://github.com/google/adk-python)) orchestrates the workflow: extracting facts, composing queries, interpreting results, and exploring the binary interactively through MCP.

**Status:** Active development. The core extraction, rule engine, and agent pipeline work end-to-end. Not yet battle-tested on a wide range of binaries. Contributions, bug reports, and feedback are welcome.

---

## Why Datalog for Binary Analysis?

Static analysis on binaries is fundamentally a graph-reachability problem: data flows through assignments, calls, memory operations, and control flow. Datalog is purpose-built for this class of computation.

**Declarative over imperative.** A taint propagation rule in Datalog reads like its specification:

```prolog
TaintedVar(f, dv, dver, origin) :-
    TaintedVar(f, sv, sver, origin),
    Use(f, sv, sver, a),
    Def(f, dv, dver, a).
```

The equivalent in Python would be nested loops over dictionaries with manual worklist fixpoints. Datalog rules compose — adding alias-aware taint is a few extra rules, not a rewrite of the propagation engine.

**Fixed-point computation for free.** Souffle handles recursive relation evaluation automatically. Points-to analysis, transitive call graphs, interprocedural taint — these are inherently recursive and Datalog evaluates them to a fixed point without manual worklist management.

**Separation of facts and rules.** The same extracted facts can be queried by different rule sets: taint analysis, memory safety patterns, integer confusion detection — without re-extracting anything. Adding a new analysis is writing a `.dl` file, not modifying extraction code.

**Proven in practice.** Datalog has a long track record in source-code analysis (Doop, CodeQL/Semmle, Soufflé itself was built for program analysis research). BinCodeQL applies this to compiled binaries, where it has seen less adoption — partly because the fact extraction step is harder when you start from machine code rather than source ASTs.

## Why Binary Ninja's MLIL-SSA?

The intermediate representation matters. Raw disassembly is too low-level for meaningful Datalog queries — you'd drown in register assignments and flag computations. Binary Ninja's Medium-Level IL in SSA form hits a useful sweet spot:

- **Explicit def-use chains.** Every variable has a unique `name#version`. No need to compute reaching definitions — SSA gives them to you. This maps directly to `Def(func, var, ver, addr)` and `Use(func, var, ver, addr)` facts.

- **Side effects made visible.** Memory operations become explicit `STORE_SSA` / `LOAD_SSA` instructions with memory SSA versioning (`mem#3 -> mem#4`). Function calls list their parameters and outputs. Nothing is hidden in implicit register conventions.

- **No complex compound statements.** Unlike HLIL (which reconstructs C-like code with nested expressions), MLIL breaks everything into simple assignments: `var#3 = var#1 + var#2`. Each instruction maps cleanly to one or two fact tuples.

- **Type and width information.** Every expression carries a `.size` (byte width), and casts are explicit operations (`MLIL_SX`, `MLIL_ZX`, `MLIL_LOW_PART`). This enables integer/type confusion detection that would be invisible at the assembly level.

- **Structured control flow.** `IF` conditions, phi nodes, and basic block structure are explicit — no manual CFG recovery from jump tables.

The result: fact extraction from MLIL-SSA is a relatively straightforward walk over instruction objects, producing clean relational data that Souffle can reason about directly.

## How the LLM Fits In

Datalog for binary analysis has been technically feasible for years, but practical adoption has been limited. The main barriers aren't about Datalog itself — they're about everything around it:

- **Fact extraction requires binary analysis expertise.** You need to know which IL to use, how to handle indirect calls, what SSA versioning means for phi nodes, how to model memory operations. This is specialized knowledge.

- **Writing effective queries requires both Datalog and vulnerability domain knowledge.** Knowing that a signed-to-unsigned cast before `malloc` is dangerous, and expressing that as a join over `Cast`, `Flow`, `ActualArg`, and `SizeSensitiveSink` relations — that's a non-trivial translation step.

- **Interpreting results requires context.** A `TaintedSink` row with `(parse_chunk, memcpy, 0x41a300, 2, buf#3, buffer_overflow_size, entry:parse_image:arg1)` is meaningful only if you understand the function's role, the data flow path, and whether the guard conditions are sufficient.

- **The workflow is multi-step.** Extract facts, generate signatures, run alias analysis, feed PointsTo into interprocedural taint, run pattern detectors, cross-reference results — doing this manually is tedious and error-prone.

BinCodeQL uses an LLM agent to bridge these gaps. The agent has access to:

1. **Binary Ninja via MCP** — for interactive exploration (decompile, cross-references, symbol lookup)
2. **Fact extraction tools** — headless BN subprocess for batch extraction, or MCP-based incremental extraction
3. **Souffle engine** — run pre-built rule files or compose custom queries on the fly
4. **The full rule library** — the agent knows the schema, available analyses, and their outputs

The agent doesn't replace Datalog — it makes it accessible. A researcher can say *"check if any attacker-controlled input reaches a size argument of malloc through an integer truncation"* and the agent will extract the relevant functions, set up entry taints, run the taint pipeline, then run `inttype_taint.dl`, and explain what it found.

The LLM can also compose **ad-hoc Datalog queries** for questions not covered by existing rules — it understands the fact schema and Souffle syntax well enough to write correct queries for novel analysis questions.

## What Makes This Different

There are excellent tools for binary vulnerability research — Ghidra + scripts, angr for symbolic execution, CodeQL for source code. BinCodeQL occupies a different niche:

- **Works on binaries directly.** No source code needed. Analyzes whatever Binary Ninja can lift — ELF, PE, Mach-O.

- **Declarative analysis rules.** Adding a new vulnerability pattern is writing a `.dl` file (typically 10-30 lines), not implementing a new analysis pass in Python. The rules are readable and auditable.

- **Scales reasonably.** Souffle compiles Datalog to C++ and runs in parallel. Interprocedural taint analysis over hundreds of functions completes in seconds, not minutes. (Though very large binaries with tens of thousands of functions will need targeted extraction rather than `--all`.)

- **Composable analyses.** Taint results feed into integer confusion detection. Alias analysis enhances taint precision. Memory safety patterns run independently on the same facts. These aren't monolithic — they're modular rule files that combine.

- **LLM-assisted but not LLM-dependent.** The Datalog rules, fact extraction, and Souffle engine work without any LLM. You can run `bn_extract_facts.py` and `souffle` from the command line. The agent adds convenience and interactivity, but the core analysis is deterministic.

**Limitations to be upfront about:**

- Fact extraction quality depends on Binary Ninja's analysis quality. If BN misidentifies a function or gets the IL wrong, the facts will be wrong.
- The MLIL-SSA representation abstracts away some low-level details (exact stack layout, calling conventions) that may matter for certain vulnerability classes.
- Indirect calls (`<indirect>`) are not resolved — this is a known gap in precision for C++ virtual calls and function pointer dispatch.
- The rule library covers common vulnerability patterns but is not exhaustive. This is an evolving project.

---

## Architecture

```
User Query --> LLM Agent (Google ADK)
  |-- Binary Ninja MCP --> interactive exploration + incremental extraction
  |-- Headless BN subprocess (bn_extract_facts.py) --> batch fact extraction
  |-- Generate Souffle .dl file (facts + rules)
  |-- Run `souffle` via subprocess --> get results
  \-- Interpret results --> answer to user
```

## Quick Start

### Prerequisites

- [Binary Ninja](https://binary.ninja/) (commercial or personal license)
- [Souffle](https://souffle-lang.github.io/install) Datalog engine
- Python 3.10+
- [Google ADK](https://github.com/google/adk-python) (`pip install google-adk`)

### Setup

```bash
git clone https://github.com/tosanjay/BinCodeQL.git
cd BinCodeQL
cp .env.example .env
# Edit .env with your API keys and Binary Ninja paths
```

### Standalone Usage (No LLM)

Extract facts from a binary and run Datalog queries directly:

```bash
# Extract facts for specific functions (requires BN Python)
python3 scripts/bn_extract_facts.py /path/to/binary -f main,process_input -o facts/ -v

# Or extract all functions
python3 scripts/bn_extract_facts.py /path/to/binary --all -o facts/ -v --json

# Run taint analysis
souffle -F facts -D output rules/interproc.dl

# Run memory safety patterns
souffle -F facts -D output rules/patterns_mem_interproc.dl

# Run integer confusion detection
souffle -F facts -D output rules/inttype.dl

# Check results
cat output/TaintedSink.csv
cat output/UseAfterFree.csv
cat output/SignedToUnsignedConfusion.csv
```

### Agent Mode (Interactive)

```bash
# Start the agent via ADK
# For interactive UI (web)
uv run adk web

# for cli based run
cd BinCodeQL
uv run agent.py

# The agent can then:
# - Extract facts from functions you're interested in
# - Run pre-built analyses or compose custom Datalog queries
# - Explore the binary interactively via Binary Ninja MCP
# - Explain findings in context
```

**Note on model choice:** The agent has been developed and tested with **Claude Opus 4.6** (via LiteLLM). The quality of ad-hoc Datalog query composition and result interpretation depends heavily on the model's reasoning ability. We have not evaluated performance with other models — your mileage may vary. The model is configurable via `MODEL_NAME` in `.env`.

## Fact Schema

Facts are extracted from MLIL-SSA and stored as tab-separated `.facts` files.

| Relation | Columns | Description |
|----------|---------|-------------|
| Def | func, var, ver, addr | SSA variable definition |
| Use | func, var, ver, addr | SSA variable use |
| Call | caller, callee, addr | Function call |
| ActualArg | call_addr, arg_idx, param, var, ver | Call argument binding |
| ReturnVal | func, var, ver | Function return value |
| PhiSource | func, var, def_ver, src_var, src_ver | Phi node source |
| FormalParam | func, var, idx | Function parameter |
| MemRead | func, addr, base, offset, size | Memory load |
| MemWrite | func, addr, target, mem_in, mem_out | Memory store |
| FieldRead | func, addr, base, field | Struct field read |
| FieldWrite | func, addr, base, field, mem_in, mem_out | Struct field write |
| AddressOf | func, var, ver, target | Address-of operation |
| CFGEdge | func, from_addr, to_addr | Control flow edge |
| StackVar | func, var, offset, size | Stack variable layout |
| Guard | func, addr, var, ver, op, bound, bound_type | Comparison in IF condition |
| ArithOp | func, addr, dst, dst_ver, op, src, src_ver, operand | Arithmetic operation |
| Cast | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width | Type cast (sx/zx/trunc) |
| VarWidth | func, var, ver, width | Variable byte width |

## Rule Modules

For a comprehensive deep-dive into every analysis domain, rule, and design decision, see **[Datalog Architecture and Rule Reference](datalog_architecture_rules.md)**.

| Rule File | What It Detects |
|-----------|----------------|
| `interproc.dl` | 1-CFA context-sensitive interprocedural taint with sanitizer kill and guard detection |
| `taint.dl` | Intraprocedural taint tracking |
| `alias.dl` | Andersen-style points-to analysis |
| `patterns.dl` | Structural heuristics (unsafe strcpy, gets, sprintf) |
| `patterns_mem.dl` | Use-after-free, double-free, unchecked malloc, format string |
| `patterns_mem_interproc.dl` | Interprocedural memory safety (cross-function UAF/double-free via parameter summaries and globals) |
| `inttype.dl` | Signed/unsigned confusion, integer truncation, widening-after-overflow |
| `inttype_taint.dl` | Taint-integrated integer vulnerability detection |
| `boil.dl` | Buffer Overflow Inducing Loop candidates |
| `boil_taint.dl` | BOIL + taint integration |
| `signatures.dl` | Library function taint transfer models |
| `summary.dl` | Function summary computation (param-to-return dependencies) |
| `core.dl` | Basic def-use chains and reachability |
| `schema.dl` | Reusable type and relation declarations |

## Key Files

| File | Purpose |
|------|---------|
| `agent.py` | ADK agent with tools: extract_facts, run_souffle, taint pipeline, etc. |
| `scripts/bn_extract_facts.py` | Headless BN script — walks MLIL-SSA objects, emits .facts directly |
| `mlil_parser.py` | Regex-based MLIL-SSA text parser (for MCP-based extraction) |
| `fact_writer.py` | Serializes parsed facts to Souffle-compatible .facts TSV files |
| `bn_utils.py` | BN Python path resolution and subprocess runner |
| `resolve_calls.py` | Resolves hex-address callees in Call.facts to function names |
| `rules/` | All Souffle Datalog rule files |

## Dependencies

- **[Binary Ninja](https://binary.ninja/)** -- binary analysis platform (via MCP bridge + headless Python API)
- **[Souffle](https://souffle-lang.github.io/)** -- Datalog compiler, invoked via subprocess
- **[Google ADK](https://github.com/google/adk-python)** -- agent framework
- **[LiteLLM](https://github.com/BerriAI/litellm)** -- model abstraction (supports OpenAI, Anthropic, Google, etc.)

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — free for research, academic, and personal use. Commercial use requires a separate license from the author.

---

Developed by **Sanjay Rawat** and **Claude Code (Opus 4.6)**.
