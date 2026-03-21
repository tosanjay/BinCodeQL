# BinCodeQL: Datalog Architecture and Rule Reference

A comprehensive guide to the Souffle Datalog rule system powering BinCodeQL's binary vulnerability analysis. This document covers the fact schema, every analysis domain, rule composition, and the design rationale behind each component.

## Table of Contents

1. [Overview](#1-overview)
2. [Fact Extraction Pipeline](#2-fact-extraction-pipeline)
3. [Fact Schema](#3-fact-schema)
4. [Analysis Domains](#4-analysis-domains)
   - 4.1 [Core: Def-Use Chains and Reachability (`core.dl`)](#41-core-def-use-chains-and-reachability)
   - 4.2 [Intraprocedural Taint (`taint.dl`)](#42-intraprocedural-taint)
   - 4.3 [Alias Analysis (`alias.dl`)](#43-alias-analysis)
   - 4.4 [Library Signatures (`signatures.dl`)](#44-library-signatures)
   - 4.5 [Function Summaries (`summary.dl`)](#45-function-summaries)
   - 4.6 [Interprocedural Taint (`interproc.dl`)](#46-interprocedural-taint)
   - 4.7 [Structural Patterns (`patterns.dl`)](#47-structural-patterns)
   - 4.8 [Memory Safety (`patterns_mem.dl`)](#48-intraprocedural-memory-safety)
   - 4.9 [Interprocedural Memory Safety (`patterns_mem_interproc.dl`)](#49-interprocedural-memory-safety)
   - 4.10 [Integer/Type Confusion (`inttype.dl`)](#410-integertype-confusion)
   - 4.11 [Tainted Integer Vulnerabilities (`inttype_taint.dl`)](#411-tainted-integer-vulnerabilities)
   - 4.12 [BOIL Detection (`boil.dl`)](#412-boil-detection)
   - 4.13 [Tainted BOIL (`boil_taint.dl`)](#413-tainted-boil)
5. [Guard Detection and False-Positive Suppression](#5-guard-detection-and-false-positive-suppression)
6. [Two-Pass Pipeline](#6-two-pass-pipeline)
7. [Rule Composition Map](#7-rule-composition-map)
8. [Shared Schema (`schema.dl`)](#8-shared-schema)
9. [Design Decisions and Tradeoffs](#9-design-decisions-and-tradeoffs)

---

## 1. Overview

BinCodeQL applies Datalog-based program analysis to compiled binaries. Facts are extracted from Binary Ninja's MLIL-SSA (Medium-Level IL in Static Single Assignment form), then Souffle Datalog rules derive vulnerability findings.

**What makes this system distinctive:**

- **Operates on binaries**, not source code. Facts come from disassembled/decompiled IR, not ASTs.
- **SSA-based precision**. Every variable carries an SSA version, giving exact def-use chains without the ambiguity of non-SSA representations.
- **Composable analyses**. Alias analysis feeds interprocedural taint, which feeds integer confusion detection, which feeds BOIL taint integration. Each analysis is a separate `.dl` file that can run standalone or compose with others.
- **1-CFA context sensitivity**. The interprocedural taint analysis distinguishes taint entering a function from different call sites.
- **Guard-aware**. Comparison operators in conditional branches are extracted as Guard facts, enabling the system to flag findings protected by bounds checks.
- **LLM-in-the-loop**. An ADK agent composes queries, selects rule files, and interprets results at runtime. The Datalog rules provide the semantic foundation; the LLM provides the reasoning.

**Rule file inventory:**

| File | Lines | Domain |
|------|-------|--------|
| `schema.dl` | ~80 | Shared type/relation declarations |
| `core.dl` | ~100 | Def-use, reachability, flow |
| `taint.dl` | ~160 | Intraprocedural taint |
| `alias.dl` | ~120 | Andersen-style points-to |
| `signatures.dl` | ~170 | Library function taint models |
| `summary.dl` | ~135 | Function summary computation |
| `interproc.dl` | ~320 | 1-CFA interprocedural taint |
| `patterns.dl` | ~50 | Structural vulnerability heuristics |
| `patterns_mem.dl` | ~95 | Intraprocedural memory safety |
| `patterns_mem_interproc.dl` | ~450 | Interprocedural memory safety |
| `inttype.dl` | ~240 | Integer/type confusion detection |
| `inttype_taint.dl` | ~210 | Taint-integrated integer vulns |
| `boil.dl` | ~265 | Buffer overflow inducing loops |
| `boil_taint.dl` | ~90 | Tainted BOIL integration |

---

## 2. Fact Extraction Pipeline

Facts flow from binary to Datalog results through a multi-stage pipeline:

```
Binary (.elf / .pe / .bndb)
          │
          ├──── Headless BN (bn_extract_facts.py) ── batch, fast
          │         │
          │         ├─ Walks MLIL-SSA instruction objects directly
          │         ├─ Emits all fact types including StackVar, Guard
          │         ├─ Auto-resolves callees via BN symbol table
          │         └─ Outputs: facts/*.facts (TSV)
          │
          └──── MCP + Regex (mlil_parser.py) ── interactive, incremental
                    │
                    ├─ BN MCP get_il(func, "mlil", ssa=True) → text
                    ├─ Regex-based parsing of MLIL-SSA text
                    ├─ No StackVar (requires BN stack layout API)
                    └─ Serialized via fact_writer.py → facts/*.facts
                                │
                                ▼
                    facts/ directory (TSV files)
                    ├── Def.facts, Use.facts, Call.facts, ...
                    ├── DangerousSink.facts (from agent annotations)
                    ├── TaintTransfer.facts (from signatures.dl)
                    ├── EntryTaint.facts (user-specified attack surface)
                    └── PointsTo.facts (from alias.dl Pass 1)
                                │
                                ▼
                    Souffle engine (rules/*.dl)
                                │
                                ▼
                    output/ directory (CSV results)
                    ├── TaintedVar.csv, TaintedSink.csv, ...
                    ├── BOILCandidate.csv, TaintedBOIL.csv, ...
                    ├── SignedToUnsignedConfusion.csv, ...
                    └── UseAfterFree.csv, DoubleFree.csv, ...
```

### Extraction modes

**Batch (recommended):** `bn_extract_facts.py` runs as a headless BN subprocess. One invocation extracts all facts for specified functions. Emits StackVar (stack frame layout) and Guard (from MLIL-SSA conditional objects). Auto-resolves hex-address callees to function names. ~10-100x faster than MCP round-trips for multi-function analysis. Automatically prefers `.bndb` pre-analyzed databases when available.

**Interactive (MCP):** Uses BN MCP `get_il()` to retrieve MLIL-SSA text, then `mlil_parser.py` applies regex patterns. Good for incremental exploration — extract one function, inspect results, extract more. Accumulates facts with deduplication (append mode). Does not emit StackVar.

### Formal parameter detection

Both extractors use the same heuristic: in SSA, version-0 variables that appear in Use facts but have no corresponding Def are formal parameters. They are sorted by minimum use address to assign positional indices (arg0, arg1, ...). The `mem` SSA token (which tracks memory state) is excluded.

---

## 3. Fact Schema

Every fact is a tuple stored as a tab-separated line in a `.facts` file. Souffle reads these as input relations.

### Base types

```
Addr  <: unsigned    — instruction addresses (hex, stored as unsigned integers)
Sym   <: symbol      — variable names, function names, string constants
Ver   <: unsigned    — SSA version numbers
Idx   <: unsigned    — argument/parameter indices
```

### Input relations (extracted from binary)

| Relation | Columns | Description |
|----------|---------|-------------|
| **Def** | func, var, ver, addr | SSA definition: `var#ver` is defined at `addr` in `func` |
| **Use** | func, var, ver, addr | SSA use: `var#ver` is used at `addr` in `func` |
| **Call** | caller, callee, addr | Function call at `addr` from `caller` to `callee` |
| **ActualArg** | call_addr, arg_idx, param, var, ver | Argument `var#ver` passed as arg `arg_idx` at `call_addr` |
| **ReturnVal** | func, var, ver | `var#ver` is a return value of `func` |
| **PhiSource** | func, var, def_ver, src_var, src_ver | Phi node: `var#def_ver = phi(..., src_var#src_ver, ...)` |
| **FormalParam** | func, var, idx | `var` is the `idx`-th formal parameter of `func` |
| **MemRead** | func, addr, base, offset, size | Memory load: reads from `base[offset]` with `size` bytes |
| **MemWrite** | func, addr, target, mem_in, mem_out | Memory store: writes to `target`, memory SSA `mem_in→mem_out` |
| **FieldRead** | func, addr, base, field | Struct field read: `_ = base.field` |
| **FieldWrite** | func, addr, base, field, mem_in, mem_out | Struct field write: `base.field = _` |
| **AddressOf** | func, var, ver, target | Address-of: `var#ver = &target` |
| **CFGEdge** | func, from_addr, to_addr | Control flow edge within `func` |
| **Jump** | func, addr, expr | Indirect jump at `addr` with computed target `expr` |
| **StackVar** | func, var, offset, size | Stack variable `var` at frame offset with `size` bytes |
| **Guard** | func, addr, var, ver, op, bound, bound_type | Conditional comparison: `var#ver op bound` at IF branch. `bound_type` is `"const"`, `"var"`, or `"expr"` |
| **ArithOp** | func, addr, dst, dst_ver, op, src, src_ver, operand | Arithmetic: `dst#dst_ver = src#src_ver op operand` |
| **Cast** | func, addr, dst, dst_ver, src, src_ver, kind, src_width, dst_width | Type cast: `dst = kind(src)` where kind is `"sx"`, `"zx"`, or `"trunc"` |
| **VarWidth** | func, var, ver, width | Type width of `var#ver` in bytes |

### Configuration relations (user/agent-specified)

| Relation | Columns | Description |
|----------|---------|-------------|
| **EntryTaint** | func, param_idx | Mark `func`'s param `param_idx` as attacker-controlled |
| **TaintSourceFunc** | name, category | External functions that produce tainted data |
| **DangerousSink** | func, arg_idx, risk | Dangerous function + which arg is sensitive |
| **TaintTransfer** | func, out_arg, in_arg | Library taint model: when `in_arg` is tainted, `out_arg` becomes tainted |
| **BufferWriteSource** | func, arg_idx | Function writes external data into buffer at `arg_idx` |
| **TaintKill** | func, arg_idx | Sanitizer function that kills taint on `arg_idx` |

### Key derived relations (output)

| Relation | Source Rule | Description |
|----------|------------|-------------|
| **TaintedVar** | interproc.dl | `(func, var, ver, origin, ctx)` — 1-CFA tainted variable |
| **TaintedSink** | interproc.dl | Tainted data reaching a dangerous sink |
| **GuardedSink** | interproc.dl | A TaintedSink protected by a bounds check |
| **SanitizedVar** | interproc.dl | Taint killed by a sanitizer function |
| **PointsTo** | alias.dl | Andersen-style points-to: `var#ver` may point to `obj` |
| **TaintedHeapObject** | interproc.dl | Heap object with tainted contents |
| **TaintedField** | interproc.dl | Struct field carrying tainted data |
| **BOILCandidate** | boil.dl | Buffer overflow inducing loop with confidence tier |
| **TaintedBOIL** | boil_taint.dl | BOIL reachable from attacker input |
| **SignedToUnsignedConfusion** | inttype.dl | Sign-extended value used as unsigned size |
| **IntegerTruncation** | inttype.dl | Wide value truncated before use as size |
| **WideningAfterOverflow** | inttype.dl | Narrow arithmetic widened after potential overflow |
| **TaintedIntVuln** | inttype_taint.dl | Taint-reachable integer vulnerability |
| **CalleeGuardsParam** | inttype.dl | Callee validates its parameter with a guard |
| **UseAfterFree** | patterns_mem*.dl | Pointer used after being freed |
| **DoubleFree** | patterns_mem*.dl | Same pointer freed twice |
| **FreesParam** | patterns_mem_interproc.dl | Function transitively frees its Nth parameter |
| **FormatStringVuln** | patterns_mem_interproc.dl | Function parameter used as format string |

---

## 4. Analysis Domains

### 4.1 Core: Def-Use Chains and Reachability

**File:** `core.dl` (~100 lines)

The foundation layer. Derives basic program properties from SSA facts.

**DefUsePair** — In SSA, matching (var, version) between Def and Use trivially identifies def-use pairs:
```datalog
DefUsePair(f, v, ver, def_addr, use_addr) :-
    Def(f, v, ver, def_addr), Use(f, v, ver, use_addr), def_addr != use_addr.
```

**Reaches** — Transitive call reachability. If A calls B and B calls C, then A reaches C:
```datalog
Reaches(a, b) :- Call(a, b, _).
Reaches(a, c) :- Reaches(a, b), Call(b, c, _).
```

**IntraFlow** — Intraprocedural data flow (transitive). Tracks how values move within a function through assignments and phi merges. This is the building block for all analyses that need to connect a source to a sink within a function:
```datalog
// Direct: dst defined where src is used (assignment)
IntraFlow(f, sv, sver, dv, dver) :- Use(f, sv, sver, addr), Def(f, dv, dver, addr), sv != dv.
// Phi merge
IntraFlow(f, sv, sver, dv, dver) :- PhiSource(f, dv, dver, sv, sver).
// Transitive closure
IntraFlow(f, sv, sver, dv3, dver3) :- IntraFlow(f, sv, sver, dv2, dver2), IntraFlow(f, dv2, dver2, dv3, dver3).
```

**FieldAccess** — Unified view of struct field reads and writes for exploratory queries.

**Why this exists:** Every other analysis needs flow, reachability, or def-use information. Rather than reimporting these concepts everywhere, `core.dl` provides a canonical set. In practice, many rule files redefine `Flow` locally for self-containedness (Souffle deduplicates identical declarations).

---

### 4.2 Intraprocedural Taint

**File:** `taint.dl` (~160 lines)

Single-function taint analysis. Simpler and faster than `interproc.dl`, useful for quick queries.

**Taint sources:** Functions like `read`, `recv`, `fread`, `getenv` whose output is attacker-controlled. Both arguments (buffer is filled with external data) and return values are marked tainted.

**Propagation rules:**
1. **Assignment**: If tainted var is used where another var is defined, the new var is tainted
2. **Phi merge**: Taint flows through SSA phi nodes
3. **Pointer-through-buffer**: If `var = &buf` and `var` is tainted, then `buf` is tainted. Reading from a tainted buffer taints the destination.
4. **Field propagation**: Tainted data written to a struct field taints that field; reading it produces tainted data.

**Sink detection:** When a tainted variable reaches a dangerous sink argument (e.g., `memcpy` size, `strcpy` source, `system` command), a `TaintedSink` is emitted.

**Limitation:** No interprocedural propagation — taint stops at function boundaries. Use `interproc.dl` for cross-function analysis.

---

### 4.3 Alias Analysis

**File:** `alias.dl` (~120 lines)

Andersen-style flow-insensitive, SSA-aware points-to analysis.

**Why this matters:** Without alias analysis, taint tracking misses flows through pointers. If function A stores tainted data via pointer `*p` and function B loads via pointer `*q`, the taint connection is invisible unless we know `p` and `q` alias (point to the same object).

**Core rules (4 Andersen rules adapted for SSA):**

1. **Address-of**: `p = &x` → `PointsTo(f, p, ver, x)`
2. **Assignment**: `q = p` at same addr → `q` inherits `p`'s points-to set
3. **Load**: `p = *q` — if `q` points to `obj` and `obj` was stored to, `p` gets the stored value's points-to set
4. **Heap allocation**: `malloc`/`calloc`/`realloc` return values point to fresh heap objects named `heap_<call_addr>`

**Alias-enhanced taint (`AliasTaintedVar`):** A secondary taint analysis that uses points-to results to detect taint flowing through aliased pointers:
```datalog
// Tainted store through *p, load through *q where p and q alias
AliasTaintedVar(f, load_var, load_ver, origin) :-
    AliasTaintedVar(f, store_val, store_ver, origin),
    Use(f, store_val, store_ver, store_addr),
    MemWrite(f, store_addr, _, _, _),
    PointsTo(f, store_ptr, _, obj),
    Use(f, store_ptr, _, store_addr),
    PointsTo(f, load_ptr, _, obj),     // same object!
    Use(f, load_ptr, _, load_addr),
    MemRead(f, load_addr, _, _, _),
    Def(f, load_var, load_ver, load_addr).
```

**Design:** Under-approximate (false negatives only, never false positives). This is deliberate — the alias analysis is safe to compose with taint without introducing spurious findings.

---

### 4.4 Library Signatures

**File:** `signatures.dl` (~170 lines)

Models the taint behavior of external library functions that are called but never analyzed (no MLIL-SSA available for them).

**Three relation types:**

**TaintTransfer(func, out_arg, in_arg)** — "When `in_arg` is tainted, `out_arg` becomes tainted." Uses string identifiers: `"arg0"`, `"arg1"`, ..., `"return"`, `"external"`.

Coverage includes:
- Memory copy: `memcpy`, `memmove`, `memccpy`, `bcopy`
- String copy: `strcpy`, `strncpy`, `stpcpy`
- String concat: `strcat`, `strncat`
- Formatted output: `sprintf`, `snprintf`, `sscanf`
- String examination: `strlen`, `strcmp`, `strchr`, `strstr`, `strtol`, `atoi`
- Memory allocation: `realloc` (inherits pointer taint)
- I/O sources: `read`, `recv`, `fread`, `fgets`, `getenv` (produce `"external"` taint)
- Network: `recvmsg`, `accept`
- Domain-specific: `png_read_data`, `png_crc_read`, `png_inflate_read` (PNG library)

**BufferWriteSource(func, arg_idx)** — Functions that write external data INTO a buffer argument. Used by `interproc.dl` to taint the heap object the buffer points to:
```
fread(buf, ...) → BufferWriteSource("fread", 0)
read(fd, buf, n) → BufferWriteSource("read", 1)
```

**TaintKill(func, arg_idx)** — Sanitizer functions that clear taint:
```
memset(dst, ...) → TaintKill("memset", 0)   // clears buffer
bzero(s, n) → TaintKill("bzero", 0)
```

**Why separate from taint rules:** Signatures are configuration, not analysis. Different binaries may need different signatures. The agent can extend signatures at runtime (e.g., adding PNG-specific functions when analyzing libpng).

---

### 4.5 Function Summaries

**File:** `summary.dl` (~135 lines)

Computes per-function summaries: which outputs (return values, call arguments) depend on which inputs (parameters).

**IsParam** — Identifies function parameters using the SSA heuristic: version-0 variables that are Used but never Defined.

**Flow** — Intraprocedural data flow (transitive), same as `core.dl`'s `IntraFlow`.

**ReturnDependsOnParam** — Does the return value depend on parameter P? Checks if there's a flow chain from `P#0` to the return variable:
```datalog
ReturnDependsOnParam(f, rv, p) :-
    IsParam(f, p), ReturnVal(f, rv, rver), Flow(f, p, 0, rv, rver).
```

**CallArgDependsOnParam** — Does a call argument at some call site depend on a function parameter? This shows how data is passed through the function to its callees.

**FuncSummary** — Compact representation combining all dependencies:
```datalog
FuncSummary(f, "return", p) :- ReturnDependsOnParam(f, _, p).
FuncSummary(f, cat("arg", idx, "_to_", callee), p) :- CallArgDependsOnParam(f, _, callee, idx, p).
```

**Why this exists:** Summary computation is the Datalog equivalent of LiSTT's `arg_dep`/`return_dep`. It enables interprocedural analysis without analyzing every function inline — the summary captures what you need to know about a function's data flow behavior.

---

### 4.6 Interprocedural Taint

**File:** `interproc.dl` (~320 lines)

The most complex and important rule file. Implements 1-CFA context-sensitive interprocedural taint analysis with sanitizer modeling, guard detection, and field sensitivity.

**TaintedVar(func, var, ver, origin, ctx):**
- `origin`: human-readable string describing where taint came from (e.g., `"external_via_read"`, `"entry:main:arg0"`)
- `ctx`: call address that introduced taint into the current function (1-CFA context). `ctx=0` for top-level sources.

**8 propagation rules:**

**Rule 1 — External taint sources:** Functions with `TaintTransfer(func, output, "external")` produce tainted data. The variable at the output position becomes tainted with context = call address:
```datalog
TaintedVar(caller, v, ver, cat("external_via_", callee), ca) :-
    Call(caller, callee, ca),
    TaintTransfer(callee, "arg1", "external"),
    ActualArg(ca, 1, _, v, ver).
```

**Rule 2 — Intraprocedural propagation:** Standard SSA-based flow propagation within a function. Preserves context from source.

**Rule 3 — Pointer-to-buffer propagation:** If `var = &target` and `var` is tainted, `target` is a tainted buffer. Reading from a tainted buffer taints the destination.

**Rule 4 — Library taint transfer:** Uses `TaintTransfer` signatures to propagate taint through library calls. Maps `"argN"` strings to actual indices via a helper relation. Handles both arg-to-arg transfer (e.g., `memcpy dst ← src`) and arg-to-return transfer (e.g., `strlen` return ← arg0).

**Rule 5 — Interprocedural caller↔callee:** Tainted actual arguments propagate to callee formal parameters (context = call address). Tainted return values propagate back to the caller's def at the call site.

**Rule 6 — Field taint:** Tainted data written to `base.field` taints that field. Reading a tainted field produces tainted data. Propagates across function boundaries: struct pointers passed as arguments carry their field taint to the callee.

**Rule 7 — Buffer-write sources:** Functions in `BufferWriteSource` (like `fread`) write external data into the buffer they receive. The heap object the buffer points to becomes a `TaintedHeapObject`.

**Rule 8 — Tainted heap object propagation:** If a heap object is tainted and a pointer to it is loaded, the loaded value is tainted. Propagates interprocedurally — tainted object pointers passed to callees or returned to callers carry the taint.

**Sanitizer modeling (`SanitizedVar`):** When a tainted variable is passed to a `TaintKill` function (e.g., `memset`), the taint on that variable is killed. `TaintedSink` excludes sanitized variables.

**Guard detection (`GuardedSink`):** If the tainted variable at a sink was compared in a Guard (directly or via flow), the sink is flagged as guarded. Not suppressed — provides triage context.

**Entry-point taint (`EntryTaint`):** For library analysis where there are no `read`/`recv` calls, the user marks exported API parameters as attacker-controlled. Seeds taint with origin `"entry:func:argN"`.

---

### 4.7 Structural Patterns

**File:** `patterns.dl` (~50 lines)

Lightweight heuristic patterns that detect obviously dangerous code without taint analysis.

**UnsafeStringCopy:** `strcpy`/`strcat` into a stack buffer (any size). Joins `Call` → `ActualArg` → `AddressOf` → `StackVar` to confirm the destination is a fixed-size stack buffer:
```datalog
UnsafeStringCopy(f, ca, callee, dv, buf, sz) :-
    Call(f, callee, ca), (callee = "strcpy" ; callee = "strcat"),
    ActualArg(ca, 0, _, dv, dver), AddressOf(f, dv, dver, buf), StackVar(f, buf, _, sz).
```

**UnsafeGets:** Any call to `gets()` — always vulnerable.

**UnsafeSprintf:** `sprintf` into a stack buffer without size limits.

**Why these are separate:** These patterns are fast, require no taint analysis, and catch "low-hanging fruit." Useful as a first pass before running heavier analyses.

---

### 4.8 Intraprocedural Memory Safety

**File:** `patterns_mem.dl` (~95 lines)

Detects UAF, double-free, unchecked malloc, and format string vulnerabilities within a single function.

**UseAfterFree:** Pointer `v` passed to `free()`, then the same `v` is used later (at a higher address). Excludes uses that are themselves `free()` calls (that's double-free):
```datalog
UseAfterFree(f, fa, ua, v) :-
    Call(f, "free", fa), ActualArg(fa, 0, _, v, _),
    Use(f, v, _, ua), ua > fa, !Call(f, "free", ua).
```

**DoubleFree:** Same variable freed twice (same SSA var, two free call sites).

**UncheckedMalloc:** `malloc`/`calloc`/`realloc` return value used without a NULL check. Uses Guard negation — if neither `Guard(f, _, v, ver, "eq", "0", _)` nor `Guard(f, _, v, ver, "ne", "0", _)` exists, the malloc is unchecked.

**FormatStringVuln:** Function parameter (or a variable derived from one) used as a format string argument to `printf`, `fprintf`, `sprintf`, `snprintf`, `syslog`.

---

### 4.9 Interprocedural Memory Safety

**File:** `patterns_mem_interproc.dl` (~450 lines)

The most comprehensive memory safety analysis. Three detection strategies for finding UAF and double-free across function boundaries.

**Strategy 1: Parameter-based summaries**

The key insight: if we know "function F frees its Nth parameter," then any caller passing a pointer to F's Nth argument must not use that pointer afterward.

**FreesParam(func, param_idx)** — Transitively derives which functions free which parameters:
```datalog
// Base case: param flows to free(arg0)
FreesParam(func, pidx) :-
    FormalParam(func, pv, pidx), Flow(func, pv, _, fv, fver),
    Call(func, "free", fa), ActualArg(fa, 0, _, fv, fver).

// Transitive: param flows to arg of callee that FreesParam
FreesParam(func, pidx) :-
    FormalParam(func, pv, pidx), Flow(func, pv, _, av, aver),
    Call(func, callee, ca), ActualArg(ca, cidx, _, av, aver),
    FreesParam(callee, cidx), callee != func.
```

This enables detecting double-free and UAF across arbitrarily deep call chains (A→B→C→free).

**InterDoubleFree** — Four cases:
1. Same var passed to two callees that both free their param
2. Callee frees param, then caller also frees directly
3. Var flows through assignment, then underlying value freed twice
4. Same pointer through data flow variants

**InterUseAfterFree** — Three cases:
1. Caller passes var to freeing callee, then uses var after
2. Caller passes var to freeing callee, then passes to non-freeing callee
3. Var flows through data flow after being passed to freeing callee

**Strategy 2: Global-mediated analysis**

For bugs involving global variables. Two functions may access the same global pointer — one frees it, the other uses it.

**NormalizedGlobal** — Groups MemRead base strings into equivalence classes. Raw hex addresses normalize to themselves; computed addresses like `"rdx#2 + 0x404020"` normalize to their hex constant `"0x404020"`. This handles the common pattern where different functions index into the same global array with different SSA temporaries.

**GlobalFreeSite / GlobalUseSite** — Tracks where global pointers are loaded and freed/used.

**GlobalDoubleFree / GlobalUseAfterFree** — Cross-function (or same-function different-site) double-free and UAF through global storage.

**Strategy 3: Return-value propagation**

**ReturnsFreedPtr** — Callee frees its parameter then returns the same value. The caller receives a dangling pointer.

**ReturnedDanglingPtr** — Caller uses the return value of such a callee.

---

### 4.10 Integer/Type Confusion

**File:** `inttype.dl` (~240 lines)

Detects integer vulnerabilities at size-sensitive sinks: signed→unsigned confusion, truncation, widening-after-overflow, and sign-extend-negative-to-size patterns.

**Size-sensitive sinks:** `malloc`, `calloc`, `realloc`, `memcpy`, `memmove`, `alloca`, `read`, `recv`, `__memcpy_chk`, `__memmove_chk`.

**4 vulnerability patterns:**

**1. SignedToUnsignedConfusion** — A sign-extend (`sx`) widens a narrow signed value; if that flows to a size sink, a negative input becomes a huge unsigned size:
```datalog
SignedToUnsignedConfusion(f, ca, cdst, cdv, callee, call_addr, idx) :-
    Cast(f, ca, cdst, cdv, _, _, "sx", sw, dw), sw < dw,
    Flow(f, cdst, cdv, av, aver),
    Call(f, callee, call_addr), ActualArg(call_addr, idx, _, av, aver),
    SizeSensitiveSink(callee, idx).
```

**2. IntegerTruncation** — Wide value truncated (`trunc`) before use as size. High bits are lost, potentially creating a small allocation for a large copy.

**3. WideningAfterOverflow** — Narrow arithmetic (32-bit `mul`/`add`/`lsl`), then zero-extend to 64-bit. The overflow in narrow width is preserved after widening. This is the `len * 2` → `zx` pattern found in libxml2's xmlParseCDSect.

**4. SignExtNegativeToSize** — Arithmetic result (possibly negative after overflow) sign-extended, then used as unsigned size argument.

**Guard flagging:** `GuardedIntIssue` flags findings where the value was bounds-checked. Six guard detection cases:
- (a) Post-cast: cast output flows to a guarded variable
- (b) Pre-cast direct: cast SOURCE is directly guarded
- (c) Pre-cast via flow: guarded var flows into the cast source
- (d) Pre-arith direct: ArithOp source is directly guarded
- (e) Pre-arith via flow: guarded var flows into the ArithOp source

**Callee parameter guards:** `CalleeGuardsParam` derives that a callee validates its parameter. For example, `xmlStrndup` checking `if (len < 0) return 0` produces `CalleeGuardsParam(xmlStrndup, 1, "slt", "0")`. `CalleeGuardedIntIssue` joins this with integer findings to flag mitigated findings.

---

### 4.11 Tainted Integer Vulnerabilities

**File:** `inttype_taint.dl` (~210 lines)

Joins integer vulnerability patterns with `TaintedVar` from `interproc.dl` to find attacker-reachable integer bugs. Same 4 patterns as `inttype.dl`, but each requires the cast/arithmetic source to be tainted:

```datalog
TaintedIntVuln(f, "signed_to_unsigned", ca, callee, call_addr, origin) :-
    Cast(f, ca, cdst, cdv, csrc, csv, "sx", sw, dw), sw < dw,
    TaintedVar(f, csrc, csv, origin, _),          // ← taint requirement
    Flow(f, cdst, cdv, av, aver),
    Call(f, callee, call_addr), ActualArg(call_addr, idx, _, av, aver),
    SizeSensitiveSink(callee, idx).
```

**`CalleeGuardedTaintedIntVuln`** — Tainted integer findings where the callee guards its size parameter. Highest-value triage relation: if both tainted AND guarded, the analyst can evaluate whether the guard is sufficient for the taint range.

**Prerequisites:** Requires `TaintedVar.facts` from a prior `interproc.dl` run.

---

### 4.12 BOIL Detection

**File:** `boil.dl` (~265 lines)

Detects Buffer Overflow Inducing Loops — loops that copy data byte-by-byte with incrementing pointers, terminating on source data content (e.g., null terminator) rather than destination buffer size.

**Detection pipeline (7 stages):**

**Stage 1 — BackEdge:** `CFGEdge(f, tail, head)` where `head <= tail` (jump backward in address space).

**Stage 2 — LoopIterVar:** SSA phi node that references itself (`PhiSource(f, v, pv, v, uv)` where `pv != uv`). This is the hallmark of a loop-carried variable — a pointer that is updated each iteration.

**Stage 3 — IncrementingVar / DecrementingVar:** Confirms the loop variable is modified by arithmetic (add/sub). Handles both direct cases (`v#uv = v#pv + 1`) and indirect cases where SSA introduces temporaries. Uses `Flow` to bridge temporaries.

**Stage 4 — LoopMemRead / LoopMemWrite:** Memory operations using loop-iterating pointers. Both direct (loop var at mem op address) and indirect (loop var flows to temp used at mem op).

**Stage 5 — DataDepTermination:** The loop termination condition depends on data read from memory (e.g., `if (*src == 0) break`). Detected by tracing flow from MemRead destinations to Guard variables.

**Stage 6 — BoundsGuardedLoop (FP suppression):** A loop iterator compared against a non-zero bound (e.g., `i < size`). This indicates size-based termination, which prevents unbounded overflow. Five sub-rules handle different patterns:
- Direct check on phi version
- Direct check on update version (do-while loops)
- Indirect via flow (excluding memory-derived bounds — those are data-content checks, not size checks)
- Counter-based: decrementing var compared to 0

**Stage 7 — BOILCandidate (3 confidence tiers):**

| Tier | Criteria |
|------|----------|
| **High** | Both pointers confirmed incrementing + data-dependent termination + no bounds guard |
| **Medium** | Both are loop-iter vars + data-dependent termination + no bounds guard, but ArithOp not confirmed for both |
| **Low** | Structural pattern matches but no data-dependent termination confirmed |

**BOILParamInvolvement:** Links BOIL candidates to function parameters (direct or via flow), enabling interprocedural attack surface analysis.

---

### 4.13 Tainted BOIL

**File:** `boil_taint.dl` (~90 lines)

Joins BOIL candidates with taint analysis to answer: "Is the BOIL's source or destination pointer reachable from attacker-controlled input?"

**TaintedBOIL:** Two roles:
- `"src_tainted"`: attacker controls WHAT is copied (the source data)
- `"dst_tainted"`: attacker controls WHERE data goes (the destination buffer)

Both direct taint and indirect (tainted var flows to the pointer) are checked.

**TaintedBOILEntry:** Connects the tainted BOIL back to the attack surface entry point. Matches taint origin strings against `EntryTaint` specifications to produce: "Param N of entry function X reaches the BOIL in function Y."

**Run order:** `interproc.dl` → `boil.dl` → `boil_taint.dl` (or compose into a single Souffle invocation).

---

## 5. Guard Detection and False-Positive Suppression

Guards are comparison operators in conditional branches extracted as facts. They are critical for reducing false positives — a vulnerability pattern protected by a sufficient bounds check may not be exploitable.

### Guard fact schema

```
Guard(func, addr, var, ver, op, bound, bound_type)
```

- `op`: comparison operator — `slt`, `sle`, `ult`, `ule`, `sgt`, `sge`, `ugt`, `uge`, `eq`, `ne`
- `bound`: the value being compared against (constant as string, or variable name)
- `bound_type`: `"const"` (literal value), `"var"` (SSA variable), or `"expr"` (complex expression)

### Guard extraction

Both extractors handle `if (var OP rhs)` conditions. The headless extractor also handles the reverse case: `if (const OP var)` is flipped to `if (var FLIPPED_OP const)` (e.g., `0 < len` → `len sgt 0`).

### Guard usage across analyses

| Analysis | How guards are used |
|----------|-------------------|
| **interproc.dl** | `GuardedSink` — flags tainted sinks where the tainted variable was compared in a Guard |
| **inttype.dl** | `GuardedIntIssue` — flags integer findings with pre-cast, post-cast, or pre-arith guards. `CalleeGuardsParam` — derives callee parameter validation |
| **inttype_taint.dl** | `GuardedTaintedIntVuln` + `CalleeGuardedTaintedIntVuln` — same for taint-integrated findings |
| **patterns_mem*.dl** | `UncheckedMalloc` — uses Guard negation (no eq/ne comparison against 0) |
| **boil.dl** | `BoundsGuardedLoop` — identifies loops with size-based termination (FP suppression). `DataDepTermination` — identifies data-content-based termination |

### Design philosophy

Guards are **not** used for automatic suppression. A guard's presence doesn't guarantee the vulnerability is mitigated — the bound might be insufficient, the guard might be on the wrong branch, or the overflow might require exceeding a limit the guard allows. Instead, guard information is output as separate relations for analyst/LLM triage.

The `bound_type` field enables reasoning about guard strength:
- `"const"` bound: deterministic — the analyst can evaluate whether the constant is sufficient
- `"var"` bound: needs further analysis — what value does the bound variable hold?
- `"expr"` bound: complex expression — hardest to reason about statically

---

## 6. Two-Pass Pipeline

The agent's `tool_run_taint_pipeline()` orchestrates a two-pass Souffle execution:

```
Pass 1: souffle rules/alias.dl  -F facts/ -D output/
         └─ Produces: PointsTo.csv

Copy:   output/PointsTo.csv → facts/PointsTo.facts

Pass 2: souffle rules/interproc.dl -F facts/ -D output/
         └─ Reads: PointsTo.facts (alias results from Pass 1)
         └─ Produces: TaintedVar, TaintedSink, GuardedSink, ...
```

**Why two passes?** Souffle requires all input `.facts` files to exist before execution. Since `interproc.dl` reads `PointsTo.facts` (to enhance taint with alias information), and `PointsTo.facts` is produced by `alias.dl`, they can't run in a single invocation. The pipeline runs alias first, copies results to the facts directory, then runs interprocedural taint.

**Why not inline alias rules into interproc.dl?** Separation allows:
- Running alias analysis independently for non-taint queries
- Caching alias results (skip Pass 1 if PointsTo.facts already exists)
- Testing alias rules in isolation
- Avoiding the compilation cost of a single massive rule file

---

## 7. Rule Composition Map

How analyses build on each other:

```
                    ┌──────────────┐
                    │ signatures.dl │ (library models)
                    │ TaintTransfer │
                    │ BufferWrite   │
                    │ TaintKill     │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ alias.dl │ │ taint.dl │ │ core.dl  │
        │ PointsTo │ │ (intra)  │ │ DefUse   │
        │ HeapAlloc│ │          │ │ Reaches  │
        └────┬─────┘ └──────────┘ └──────────┘
             │
             ▼ (PointsTo.facts)
        ┌────────────────┐
        │  interproc.dl  │ ← also reads: TaintTransfer, TaintKill,
        │  TaintedVar    │   BufferWriteSource, DangerousSink,
        │  TaintedSink   │   EntryTaint, Guard
        │  GuardedSink   │
        │  TaintedField  │
        │  TaintedHeapObj│
        └───┬──────┬─────┘
            │      │
     ┌──────┘      └──────────┐
     ▼                        ▼
┌──────────────┐     ┌────────────────┐
│ inttype      │     │ boil_taint.dl  │ ← also reads BOILCandidate
│ _taint.dl    │     │ TaintedBOIL    │   from boil.dl
│ TaintedIntVuln│    │ TaintedBOILEntry│
└──────────────┘     └────────────────┘

(Standalone — no taint dependency)
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────┐
│ inttype.dl   │  │ boil.dl      │  │patterns_mem  │  │patterns.dl│
│ SignedToUns. │  │ BOILCandidate│  │_interproc.dl │  │UnsafeStr.│
│ IntTrunc.    │  │ BoundsGuarded│  │FreesParam    │  │UnsafeGets│
│ WideningAfter│  │ DataDepTerm  │  │InterDoubleFree│ │UnsafeSpr.│
│ CalleeGuards │  │              │  │GlobalUAF     │  │          │
└──────────────┘  └──────────────┘  │FormatString  │  └──────────┘
                                    └──────────────┘
```

**Two categories of analyses:**

1. **Taint-dependent** (require prior interproc.dl run): `inttype_taint.dl`, `boil_taint.dl`
2. **Standalone** (run directly on extracted facts): `inttype.dl`, `boil.dl`, `patterns.dl`, `patterns_mem.dl`, `patterns_mem_interproc.dl`, `core.dl`, `summary.dl`

---

## 8. Shared Schema (`schema.dl`)

**File:** `schema.dl` (~80 lines)

Contains canonical `.decl` + `.input` declarations for all input relations. Rule files can either include this or redeclare relations locally (Souffle deduplicates identical declarations).

In practice, most rule files redeclare their needed relations locally for self-containedness — each `.dl` file can run independently without depending on `schema.dl`. The schema file serves as documentation and ensures all relation signatures stay consistent.

---

## 9. Design Decisions and Tradeoffs

### SSA as the foundation

MLIL-SSA gives exact def-use chains without the ambiguity of non-SSA forms. Every variable has a unique definition point, which makes `Def(f, v, ver, addr) + Use(f, v, ver, addr)` sufficient for precise flow tracking. The cost is that phi nodes must be modeled explicitly — every analysis that propagates through flow must include a `PhiSource` rule.

### Self-contained rule files

Each `.dl` file redeclares its input relations rather than including a shared header. This means:
- Any rule file can run independently with `souffle rules/X.dl -F facts/ -D output/`
- No build system or include paths needed
- Trade-off: relation declarations are duplicated across files

### Flow-insensitive alias, flow-sensitive taint

Alias analysis (`alias.dl`) is flow-insensitive — PointsTo doesn't track order. This is standard for Andersen-style analysis and keeps the computation tractable. Taint analysis (`interproc.dl`) is flow-sensitive via SSA — different versions of the same variable can have different taint states. The composition (alias feeds into taint) gives alias-enhanced flow-sensitive taint.

### 1-CFA context sensitivity

The `ctx` field in `TaintedVar` records the call address that introduced taint into the current function. This distinguishes:
- `TaintedVar(foo, x, 0, origin, 0x1000)` — taint entered `foo` via call at 0x1000
- `TaintedVar(foo, x, 0, origin, 0x2000)` — taint entered `foo` via call at 0x2000

1-CFA is a good precision/cost tradeoff. Deeper context (k-CFA for k>1) would explode the relation size for recursive call chains.

### Guard detection vs. path sensitivity

BinCodeQL is NOT path-sensitive. A Guard fact means "variable was compared in some conditional branch," but doesn't track which branch was taken. This means:
- A guard on the true branch is indistinguishable from a guard on the false branch
- We can't determine if the vulnerable path is the guarded or unguarded one

This is a deliberate tradeoff. Full path sensitivity in Datalog would require tracking branch predicates through the entire analysis, which is prohibitively expensive for whole-program analysis. Instead, guards provide heuristic triage information — the LLM agent can then do targeted decompilation-level verification for flagged findings.

### Under-approximation for composability

Alias analysis is under-approximate (may miss aliases, never creates false ones). This means:
- `PointsTo` results are always correct — if it says `p` points to `obj`, it does
- Some alias-mediated taint flows may be missed
- But no false positives are introduced by alias imprecision

This property is critical for composability — if alias analysis could produce false points-to facts, every downstream analysis (taint, BOIL, integer) would inherit those false positives.

### BOIL confidence tiers

Rather than a binary BOIL/not-BOIL classification, the analysis outputs three confidence levels. This reflects the reality that binary analysis operates on incomplete information:
- **High**: both pointers confirmed incrementing + data-dependent termination + no bounds guard
- **Medium**: structural match + data-dependent termination, but arithmetic not fully confirmed
- **Low**: structural match only

The LLM agent uses confidence tiers to prioritize investigation — high-confidence BOILs get full decompilation review, low-confidence ones get quick checks.

### Bound type distinction in guards

The `bound_type` field (`"const"` / `"var"` / `"expr"`) enables reasoning about guard effectiveness:
- `Guard(f, addr, len, 0, "slt", "0", "const")` — we know exactly what value is checked
- `Guard(f, addr, len, 0, "sle", "r15_2", "var")` — the bound is a variable; its value depends on context (could be 10MB, could be 1GB, could be user-controlled)

This distinction was added after analyzing libxml2, where guards with computed bounds (like the 1GB limit derived from `XML_PARSE_HUGE` flag processing) blocked exploitation but couldn't be evaluated without understanding the variable's value range.

---

*This document describes BinCodeQL's Datalog subsystem as of its current implementation. The system is under active development — new analyses, fact types, and signatures are added as new vulnerability classes are investigated.*
