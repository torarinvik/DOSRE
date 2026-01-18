# MC1 (Machine-C Level 1) — Complete Specification

MC1 is one rung above MC0. It adds locals, packed structs, views, macros, and structured control-flow **as deterministic sugar**.

MC1 has no independent runtime semantics. Its meaning is defined by a total deterministic translation:

> `desugar1 : MC1Program → MC0Program`

Execution:

> `Exec_MC1(P,S0) = Exec_MC0(desugar1(P), S0)`

---

## 1. Normative dependencies

- MC0 defines: machine model, primitive operations (ALU ops, CMP/TEST, Jcc predicates, INT, memory ops), and execution semantics.
- MC1 defines only syntax, typing, and deterministic desugaring to MC0.

---

## 2. Additions over MC0

MC1 adds:
- **Locals** (`let`) with explicit types.
- **Packed structs** with deterministic layout.
- Built-in **`farptr16`** (`{off:u16; seg:u16;}`) for common DOS patterns.
- **Views**: typed overlays over `(seg:off)` memory; view field access lowers to `MEM*/LOAD*`.
- **Macros** with hygienic deterministic expansion.
- Structured control flow: `if/else`, `while`, `break`, `continue` (all desugar to labels + gotos).

---

## 3. Types

### 3.1 Primitive types
- `u8`, `u16`, `u32` (optional but allowed), `bool`

### 3.2 Built-in struct `farptr16`
`farptr16 = struct { off:u16; seg:u16; }` (packed)
- size = 4
- `offset(off)=0`, `offset(seg)=2`

### 3.3 User structs (packed)
Type declarations introduce packed structs.

- Field types: primitives, `farptr16`, or other user structs.
- Layout is **packed** (alignment=1), fields laid out in declaration order.
- Sizes: `size(u8)=1`, `size(u16)=2`, `size(u32)=4`, `size(bool)=1`, `size(farptr16)=4`, `size(struct)=Σ size(fields)`.
- Offsets: `offset(f1)=0`; `offset(fi)=offset(f(i-1))+size(f(i-1))`.

---

## 4. Lexical structure

Same as MC0:
- identifiers: `[A-Za-z_][A-Za-z0-9_]*`
- integer literals: decimal or hex (`0x...`)
- comments: `//` and `/* ... */`

---

## 5. Syntax (EBNF)

### 5.1 Program
```
MC1Program ::= { TopItem }
TopItem    ::= TypeDecl | ConstDecl | ViewDecl | MacroDecl | Stmt
```

### 5.2 Declarations
```
TypeDecl   ::= "type" Ident "=" "struct" "{" { FieldDecl } "}" ";"
FieldDecl  ::= Ident ":" Type ";"
Type       ::= PrimType | "farptr16" | Ident
PrimType   ::= "u8" | "u16" | "u32" | "bool"

ConstDecl  ::= "const" Ident ":" Type "=" ConstExpr ";"
ConstExpr  ::= IntegerLiteral | "true" | "false"

ViewDecl   ::= "view" Ident "at" "(" SegExpr "," OffExpr ")" ":" Type ";"
```

### 5.3 Statements and blocks
```
Stmt       ::= LocalDecl
            |  Assign ";"
            |  Store ";"
            |  IfStmt
            |  WhileStmt
            |  Break ";" | Continue ";"
            |  Label
            |  Goto ";"
            |  IfGoto ";"
            |  Return ";"
            |  Halt ";"
            |  ExprStmt ";"
            |  Block

Block      ::= "{" { Stmt } "}"

LocalDecl  ::= "let" Ident ":" Type [ "=" Expr ] ";"

IfStmt     ::= "if" "(" Expr ")" Block [ "else" Block ]
WhileStmt  ::= "while" "(" Expr ")" Block

Break      ::= "break"
Continue   ::= "continue"

Label      ::= Ident ":"
Goto       ::= "goto" Ident
IfGoto     ::= "if" "(" Expr ")" "goto" Ident

Return     ::= "return" [ Expr ]
Halt       ::= "halt"

ExprStmt   ::= Expr
```

### 5.4 LValues
```
Assign     ::= LValue "=" Expr
Store      ::= MemRef "=" Expr

LValue     ::= Reg16 | SegReg | "IP" | FlagBit | Ident | FieldLValue | MemRef

FieldLValue::= Base "." Ident
Base       ::= Ident | ViewRef | "(" Expr ")"
ViewRef    ::= Ident   // must refer to a view

MemRef     ::= "MEM8"  "(" SegExpr "," OffExpr ")"
            |  "MEM16" "(" SegExpr "," OffExpr ")"
```

### 5.5 Expressions (restricted, deterministic)
MC1 expressions are intentionally conservative.

```
Expr       ::= OrExpr
OrExpr     ::= AndExpr { "||" AndExpr }
AndExpr    ::= EqExpr  { "&&" EqExpr  }
EqExpr     ::= RelExpr { ("==" | "!=") RelExpr }
RelExpr    ::= AddExpr { ("<"|"<="|">"|">=") AddExpr }
AddExpr    ::= MulExpr { ("+"|"-") MulExpr }
MulExpr    ::= UnaryExpr { ("&"|"|"|"^") UnaryExpr }
UnaryExpr  ::= ("!"|"~"|"+") UnaryExpr | Primary
Primary    ::= IntegerLiteral | "true" | "false"
            |  Reg16 | SegReg | "IP" | FlagBit
            |  Ident
            |  Load
            |  FieldAccess
            |  Call
            |  Cast
            |  StructLit
            |  "(" Expr ")"

Load       ::= "LOAD8"  "(" SegExpr "," OffExpr ")"
            |  "LOAD16" "(" SegExpr "," OffExpr ")"

FieldAccess::= Primary "." Ident

Call       ::= Ident "(" [ ArgList ] ")"
ArgList    ::= Expr { "," Expr }

Cast       ::= Type "(" Expr ")"

StructLit  ::= Type "{" { InitField } "}"
InitField  ::= Ident ":" Expr ";"

SegExpr    ::= SegReg | Ident | IntegerLiteral
OffExpr    ::= Reg16 | Ident | IntegerLiteral | "(" Expr ")"
```

Notes:
- `||` and `&&` have **short-circuit semantics** and are lowered deterministically via control-flow (see §8.3).
- Integer operators wrap modulo width; no UB.
- Calls are **macros** by default (extern functions belong at MC2).

---

## 6. Static semantics (typing)

### 6.1 Environments
The typing environment `Γ` maps identifiers to one of:
- local variable: `Type`
- const: `Type` with compile-time value
- type name: struct definition
- view binding: `(SegExpr, OffExpr, Type)`
- macro: parameter types + return type + body

Registers/flags have fixed types:
- `Reg16, SegReg, IP : u16`
- `FlagBit : bool`

### 6.2 LValue validity
An `LValue` is assignable iff it is:
- a register / segment reg / IP / flag bit, or
- a local variable identifier (not const, not type, not macro, not view name), or
- `MEM8(seg,off)` or `MEM16(seg,off)`, or
- a field lvalue `base.f` where `base` is a struct local or a view, and `f` exists.

### 6.3 Views
If `v` is a view of type `T`, then:
- `v.f` is an lvalue/value with type `fieldType(T,f)`.
- nested fields are allowed; offsets compose additively.

### 6.4 Operators
- arithmetic/bitwise on `u8/u16/u32` yields same width
- comparisons yield `bool` (unsigned ordering)
- boolean ops require `bool`

No implicit casts.

---

## 7. Views (lowering to MC0)

A view declaration:
```
view v at (seg, off) : T;
```
binds `v` to base address `(seg,off)`.

Field lvalue lowering:
- `v.f` lowers to a `MEM8/MEM16` access at `(seg, off + offset(f))` for primitive fields.
- For nested structs, offsets are summed.
- Offset arithmetic is `u16` modulo 65536.

Example:
```
view state at (DS, 0x0000) : GameState;
state.score = 10;
```
lowers to:
```
MEM16(DS, 0x0000 + offset(score)) = 10;
```

---

## 8. Macros

### 8.1 Syntax
```
MacroDecl ::= "macro" Ident "(" [ ParamList ] ")" ":" Type "expands" Block
ParamList ::= Param { "," Param }
Param     ::= Ident ":" Type
```

### 8.2 Rules
- Macros expand **before** other lowering.
- Macros are not recursive (directly or indirectly). A recursive macro is a compile-time error.
- Macro bodies may contain MC1 statements/blocks.

### 8.3 Hygiene (deterministic)
All macro-local bindings are renamed deterministically per call site:
- Each macro call gets a preorder index `CallId` (starting at 1).
- Any local declared inside the macro named `x` is renamed to `_m<CallId>_x`.

---

## 9. Structured control flow (lowering to MC0)

MC1 control flow is sugar over labels/gotos.

### 9.1 Label naming
MC1 introduces fresh labels deterministically:
- If/else: `_L_if_<K>_then`, `_L_if_<K>_else`, `_L_if_<K>_end`
- While: `_L_while_<K>_test`, `_L_while_<K>_body`, `_L_while_<K>_end`
- `K` increments in source order.

### 9.2 `if`
`if (c) {A} else {B}` lowers to:
- lower `c` into temp `t`
- `if (t) goto L_then; goto L_else;`
- `L_then: A; goto L_end;`
- `L_else: B;`
- `L_end:`

### 9.3 `while`
`while (c) {Body}` lowers to:
```
goto L_test;
L_body: Body
L_test:
  (lower c -> t)
  if (t) goto L_body;
L_end:
```

### 9.4 `break` / `continue`
Within the nearest enclosing while:
- `break` → `goto L_end`
- `continue` → `goto L_test`

### 9.5 Short-circuit `&&` / `||`
`a && b` lowers to:
- evaluate `a` into `ta`
- if `ta` is false, result=false without evaluating `b`
- else evaluate `b` into `tb`, result=`tb`

`a || b` similarly.

This lowering is done by `lowerExpr` (see §10) using fresh labels and a result temp.

---

## 10. Expression lowering to MC0 (normative)

MC1 defines a total function:

> `lowerExpr : Expr → (MC0Stmts, MC0ValueRef)`

Rules:
- **left-to-right** evaluation order
- every non-trivial expression result stored in deterministic temporaries `_t<k>`
- comparisons lower via `CMP*` followed by `Jcc()` to compute a boolean temp deterministically

Example (unsigned `<` on u16):
- lower `a` and `b` to refs `ra, rb`
- emit `CMP16(ra, rb);`
- compute `t = JB()?` (true if `a < b` unsigned)

---

## 11. Deterministic desugaring pipeline

`desugar1` runs in this fixed order:

1. Expand macros (hygienic)
2. Resolve struct literals and field accesses (compute packed offsets; may flatten locals)
3. Resolve view accesses into explicit `MEM*/LOAD*`
4. Lower structured control flow to labels/gotos
5. Lower expressions into MC0 statements and temporaries

Output must be a valid MC0 program.

---

## 12. Compile-time errors

- unknown identifier/type/field
- duplicate label
- goto target missing
- assigning to a const or view name
- type mismatch (no implicit casts)
- recursive macro expansion
- `break/continue` outside a loop
