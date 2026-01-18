# MC2 (Machine-C Level 2) — Complete Specification

MC2 is one rung above MC1. It introduces *meaningful structure* while remaining fully verifiable:
- regions (typed named DS/ES overlays),
- effect contracts + optional lexical gating (`allow`),
- typed extern APIs that lower to MC1 blocks (often `INT`),
- idioms (named abstractions for common low-level patterns),
- `for` and `switch`,
- provenance annotations (`@origin`, `@cert`).

MC2 has no independent runtime semantics. Its meaning is defined by deterministic lowering:

> `desugar2 : (MC2Program, Mode) → MC1Program`

where `Mode ∈ { PreserveBytes, Canonical }`.

Execution:

> `Exec_MC2(P,S0) = Exec_MC0(desugar1(desugar2(P,Mode)), S0)`

---

## 1. Normative dependencies

- MC1 defines: locals, packed structs, views, macros, structured control, expression lowering.
- MC2 defines only additional syntax, typing constraints, metadata, and deterministic lowering to MC1.

---

## 2. Modes

### 2.1 PreserveBytes
MC2 constructs must be traceable to original bytes. In this mode:
- any **idiom call** or **switch** must be either (a) covered by an `@origin` range that the backend re-emits verbatim, or (b) expand to MC1 statements each covered by origin metadata.
- externs/regions are just *naming sugar* and are allowed if the final emitted MC1 still re-emits the original bytes for origin-covered regions.

### 2.2 Canonical
MC2 constructs may expand to canonical MC1 implementations. Byte identity is not required; semantic checking (stepping / equivalence) is recommended.

---

## 3. Types

MC2 inherits all MC1 types.

### 3.1 Enums
Enums are backed by an explicit integer width and behave as compile-time constants.

- Declaration: `enum E : u8|u16|u32 { A=0; B=1; }`
- Enum values lower to their backing integer literals in MC1.

---

## 4. Effects (static contracts)

Effects describe what an external transition *may read or modify*. Effects are **static metadata**; they do not change runtime behavior.

### 4.1 Declaration
```
effect E {
  reads    { LocSet };
  modifies { LocSet };
};
```

### 4.2 Location sets
A `LocSet` is a (possibly empty) comma-separated set of locations.

Locations:
- registers: `AX,BX,CX,DX,SI,DI,BP,SP,CS,DS,ES,SS,IP`
- flags: `CF,PF,AF,ZF,SF,OF,DF,IF`
- segmented ranges: `MEM[SegExpr:Off0..Off1]` (byte range `[Off0,Off1)` under u16 arithmetic)
- `MEM` (whole memory) and `CPU` (whole cpu state)
- `RegionName.field` (a named region field)

`SegExpr`, `Off0`, and `Off1` must typecheck to `u16`.

### 4.3 Optional enforcement via allow-blocks
If enforcement is enabled, calls requiring effect `E` must appear inside an `allow E { Block }` block. `allow` blocks nest; allowed effects union.

---

## 5. Regions

Regions are grouped, typed overlays over a segment expression (often `DS` or `ES`).

### 5.1 Declaration
```
region R in SegExpr {
  field1 : Type at 0x1234;
  field2 : Type at 0x2000 const;
};
```

Rules:
- `SegExpr : u16`
- `at` offsets are compile-time `u16` constants
- `const` fields are read-only at MC2 level

### 5.2 Use
`R.field` is an lvalue/rvalue behaving like a view/struct.

### 5.3 Lowering (normative)
Each field lowers to a distinct MC1 view:

- `view _r_<R>_<field> at (SegExpr, offset) : Type;`
- every `R.field` reference lowers to `_r_<R>_<field>`

Naming is deterministic; `<R>` and `<field>` are the original identifiers.

---

## 6. Extern APIs

Externs provide typed names for effectful low-level sequences (often `INT`).

### 6.1 Declaration
```
extern F(p1:T1, p2:T2) : Ret
  requires EffName
  lowers { Block }
;
```

- Parameters are typed and passed by value (MC1-style locals).
- `requires` may be omitted; then the effect is `unknown`.
- The `lowers` block must be MC1-compatible (may contain MC0 primitives).
- The `lowers` block must end in `return Expr;` if `Ret` is non-void.

### 6.2 Call
A call expression `F(a,b)` is well-typed if `a:T1` and `b:T2`. It lowers by hygienically inlining the `lowers` block.

### 6.3 Hygiene (deterministic)
Inline expansion uses deterministic renaming for locals created inside the inlined body:
`_m<CallId>_<name>` where `CallId` is preorder index of the call site.

---

## 7. Idioms

Idioms are named abstractions for common patterns (interrupt hooks, fixups, poll loops, memcpy, jump tables). They exist for readability and certified lifting.

### 7.1 Declaration
```
idiom I(p1:T1, p2:T2) : Ret
  requires EffName
  expands { Block }
;
```

Optional tooling hook:
```
idiom I(ParamList) : Ret
  expands { Block }
  pattern { PatternSpec }
;
```

### 7.2 Lowering
Idiom calls lower by hygienically inlining `expands { Block }` (same rules as externs).

### 7.3 PreserveBytes constraint
In `PreserveBytes` mode, every idiom call must either:
- be enclosed in `@origin(start..end)` such that the backend re-emits those bytes verbatim, OR
- expand to MC1 statements each associated to origin bytes (per-statement origin metadata).

---

## 8. Control structures

### 8.1 for
Syntax:
```
for (Init; Cond; Step) { Body }
```

Lowering (normative, deterministic) to MC1 labels/gotos:
```
Init;
goto L_test;
L_body: Body; Step;
L_test:
  if (Cond) goto L_body;
L_end:
```

- `continue` targets `Step`
- `break` targets `L_end`

Deterministic label naming uses `_L_for_<K>_test/_body/_end` where `<K>` increments in preorder.

### 8.2 switch
Syntax:
```
switch (Expr) {
  case K1: { Block1 }
  case K2: { Block2 }
  default: { BlockD }
}
```

Lowering:
- **Canonical mode:** chained compares in case-order:
  - evaluate `Expr` once into a temp
  - compare against each case constant in order
  - branch to corresponding blocks
- **PreserveBytes mode:** `switch` is only legal if covered by `@origin` or re-emitted from original bytes; it may lower to an opaque structure whose body is emitted from origin bytes.

---

## 9. Provenance annotations

### 9.1 origin
`@origin(0xSTART..0xEND)` attaches a construct to machine code bytes in address range `[START,END)`.

### 9.2 cert
`@cert(Name, { k:v; k2:v2; })` attaches a structured certificate for tooling (pattern-match proofs, constraints, dominance facts, etc.).

Annotations are preserved as metadata through lowering.

---

## 10. Syntax (EBNF)

MC2 extends MC1.

### 10.1 Top-level items
```
TopItem ::= MC1TopItem
         | EffectDecl
         | RegionDecl
         | ExternDecl
         | IdiomDecl
         | EnumDecl
```

### 10.2 Declarations
```
EnumDecl   ::= "enum" Ident ":" PrimType "{" { EnumField } "}" ";"
EnumField  ::= Ident "=" ConstExpr ";"

EffectDecl ::= "effect" Ident "{" 
               "reads"    "{" LocSet "}" ";"
               "modifies" "{" LocSet "}" ";"
             "}" ";"

LocSet     ::= [ Loc { "," Loc } ]
Loc        ::= RegOrSeg | Flag | MemRange | "MEM" | "CPU" | RegionRef
RegionRef  ::= Ident "." Ident
MemRange   ::= "MEM" "[" SegExpr ":" OffExpr ".." OffExpr "]"

RegionDecl ::= "region" Ident "in" SegExpr "{" { RegionItem } "}" ";"
RegionItem ::= Ident ":" Type "at" ConstExpr [ "const" ] ";"

ExternDecl ::= "extern" Ident "(" [ ParamList ] ")" ":" Type
               [ "requires" Ident ]
               "lowers" Block ";"

IdiomDecl  ::= "idiom" Ident "(" [ ParamList ] ")" ":" Type
               [ "requires" Ident ]
               "expands" Block
               [ "pattern" Block ] ";"
```

### 10.3 Statements
```
Stmt      ::= MC1Stmt | AllowStmt | ForStmt | SwitchStmt | AnnotatedStmt

AllowStmt ::= "allow" Ident Block

ForStmt   ::= "for" "(" [ ForInit ] ";" [ Expr ] ";" [ ForStep ] ")" Block
ForInit   ::= MC1LocalDecl | MC1Assign
ForStep   ::= MC1Assign | MC1ExprStmt

SwitchStmt ::= "switch" "(" Expr ")" "{" { CaseClause } [ DefaultClause ] "}"
CaseClause ::= "case" ConstExpr ":" Block
DefaultClause ::= "default" ":" Block

AnnotatedStmt ::= { Annotation } (Stmt | Block)
Annotation ::= "@origin" "(" ConstExpr ".." ConstExpr ")"
             | "@cert" "(" Ident "," "{" { CertKV } "}" ")"
CertKV ::= Ident ":" ConstExpr ";"
```

---

## 11. Deterministic lowering to MC1 (normative pipeline)

`desugar2(P,Mode)` runs in this fixed order:

1. Expand extern and idiom calls (hygienic), except for constructs emitted purely by origin in PreserveBytes mode.
2. Lower regions to MC1 views (`_r_<R>_<field>` naming).
3. Replace enums with backing integer constants.
4. Erase/enforce `allow` blocks (static-only).
5. Lower `for` and `switch` per §8 (mode-dependent).
6. Preserve `@origin/@cert` metadata.

The output must be a valid MC1 program.

---

## 12. Compile-time errors

- unknown identifier/type/field/effect
- duplicate enum tag or out-of-range enum value for backing type
- region offset not compile-time constant or out of range
- write to a `const` region field
- call to extern/idiom requiring effect `E` outside an enabled `allow E` (if enforcement enabled)
- PreserveBytes violations (missing origin coverage)
- invalid switch case constant type
