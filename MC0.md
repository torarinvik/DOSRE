# MC0 (Machine-C Level 0) — Complete Specification

MC0 is a deterministic, correctness-first, C-shaped intermediate representation for **16-bit x86 real-mode** code.

MC0 is the “truth layer” in an abstraction ladder:
- it models registers/flags/memory/INT directly,
- it avoids undefined or unspecified behavior,
- it supports origin metadata for byte-identity verification,
- higher levels (MC1/MC2) are defined by deterministic desugaring to MC0.

---

## 1. Design goals

- **G1 Deterministic semantics:** every well-typed MC0 program has exactly one meaning.
- **G2 No UB:** wrapping arithmetic; fixed evaluation order; explicit memory operations.
- **G3 Verifiability:** statements may carry origin bytes and be checked against a reference binary.
- **G4 Minimal surface:** MC0 is “assembly semantics with a C-ish syntax.”

---

## 2. Machine model

### 2.1 State
A machine state `S` is a tuple:

- general registers (16-bit): `AX,BX,CX,DX,SI,DI,BP,SP ∈ U16`
- segment registers (16-bit): `CS,DS,ES,SS ∈ U16`
- instruction pointer: `IP ∈ U16`
- flags (modeled bits at minimum):
  - arithmetic/control: `CF,PF,AF,ZF,SF,OF ∈ {0,1}`
  - direction/interrupt: `DF,IF ∈ {0,1}`
- memory: `MEM : Addr20 → U8`, where `Addr20 = {0..2^20-1}`
- external environment (optional): `EXT` used to model interrupt side effects

### 2.2 Address calculation
Real-mode segmented linear address:

`lin(seg:U16, off:U16) = ((seg << 4) + off) mod 2^20`

### 2.3 Little-endian memory
- `load8(a)  = MEM[a]`
- `store8(a,v)` sets `MEM[a] := v & 0xFF`
- `load16(a) = MEM[a] + 256*MEM[(a+1) mod 2^20]`
- `store16(a,v)` stores low byte at `a`, high byte at `a+1`

---

## 3. Types and values

### 3.1 Primitive types
- `u8`   integers modulo 2^8
- `u16`  integers modulo 2^16
- `bool` `{false,true}`

No signed integer type exists at MC0. Signed comparisons are expressed via flag predicates (`JL`, `JG`, ...).

### 3.2 Casts
No implicit casts.
- `ZX8_16(x:u8) -> u16` zero-extends
- `TRUNC16_8(x:u16) -> u8` truncates

(These may be represented as builtins or handled by the frontend when typechecking literals.)

---

## 4. Lexical structure

- identifiers: `[A-Za-z_][A-Za-z0-9_]*`
- integer literals: decimal or hex `0x...`
- comments: `//` to end of line, `/* ... */`

Literals default to `u16` unless context requires `u8`. Out-of-range literals are compile-time errors.

---

## 5. Syntax (EBNF)

### 5.1 Program
```
Program   ::= { Stmt }
```

### 5.2 Statements
```
Stmt      ::= Assign ";"
           |  Store  ";"
           |  IfGoto ";"
           |  Goto   ";"
           |  Label
           |  ExprStmt ";"     // restricted: side-effecting primitives only
           |  Return ";"
           |  Halt ";"

Label     ::= Ident ":"
Goto      ::= "goto" Ident
IfGoto    ::= "if" "(" Cond ")" "goto" Ident
Return    ::= "return"
Halt      ::= "halt"
```

### 5.3 Assignments and lvalues
```
Assign    ::= LValue "=" RValue

LValue    ::= Reg16 | SegReg | IPReg | FlagBit | Local
Reg16     ::= "AX"|"BX"|"CX"|"DX"|"SI"|"DI"|"BP"|"SP"
SegReg    ::= "CS"|"DS"|"ES"|"SS"
IPReg     ::= "IP"
FlagBit   ::= "CF"|"PF"|"AF"|"ZF"|"SF"|"OF"|"DF"|"IF"
Local     ::= Ident                 // optional surface feature
```

### 5.4 Explicit memory
Memory is accessed only through `LOAD*` and written only through `MEM*` lvalues.

```
Store     ::= MemRef "=" RValue
MemRef    ::= "MEM8"  "(" SegExpr "," OffExpr ")"
           |  "MEM16" "(" SegExpr "," OffExpr ")"

RValue    ::= Imm | Reg16 | SegReg | IPReg | FlagBit | Local | MemLoad | Prim
MemLoad   ::= "LOAD8"  "(" SegExpr "," OffExpr ")"
           |  "LOAD16" "(" SegExpr "," OffExpr ")"

SegExpr   ::= SegReg | Local | Imm
OffExpr   ::= Reg16  | Local | Imm | Add16
Add16     ::= "ADD16" "(" OffExpr "," OffExpr ")"

Imm       ::= IntegerLiteral
Cond      ::= BoolExpr
BoolExpr  ::= FlagPred | FlagBit
```

### 5.5 Primitives
Primitives are the only operations with defined effects on FLAGS / stack / external state.

```
Prim      ::= ALU | FlagPred | Stack | Sys | Misc

ALU       ::= "ADD8"  "(" X8  "," Y8  ")"
           |  "ADD16" "(" X16 "," Y16 ")"
           |  "SUB8"  "(" X8  "," Y8  ")"
           |  "SUB16" "(" X16 "," Y16 ")"
           |  "AND8"  "(" X8  "," Y8  ")"
           |  "AND16" "(" X16 "," Y16 ")"
           |  "OR8"   "(" X8  "," Y8  ")"
           |  "OR16"  "(" X16 "," Y16 ")"
           |  "XOR8"  "(" X8  "," Y8  ")"
           |  "XOR16" "(" X16 "," Y16 ")"
           |  "INC16" "(" X16 ")"
           |  "DEC16" "(" X16 ")"
           |  "CMP8"  "(" X8  "," Y8  ")"    // flags like SUB, result ignored
           |  "CMP16" "(" X16 "," Y16 ")"
           |  "TEST8"  "(" X8  "," Y8  ")"   // flags like AND, result ignored
           |  "TEST16" "(" X16 "," Y16 ")"

FlagPred  ::= "JZ"() | "JNZ"() | "JC"() | "JNC"()
           |  "JA"() | "JAE"() | "JB"() | "JBE"()
           |  "JL"() | "JLE"() | "JG"() | "JGE"()
           |  "JO"() | "JNO"() | "JS"() | "JNS"()

Stack     ::= "PUSH16" "(" X16 ")"
           |  "POP16"  "()"
           |  "RET_NEAR" "()"
           |  "RET_FAR"  "()"

Sys       ::= "INT" "(" Imm ")"

Misc      ::= "CLI" "()" | "STI" "()"

X8  ::= RValue   // must typecheck to u8
Y8  ::= RValue
X16 ::= RValue   // must typecheck to u16
Y16 ::= RValue
```

`ExprStmt` may contain only side-effecting primitives (e.g., `INT(0x21);`, `PUSH16(AX);`, `CLI();`).

---

## 6. Static semantics (typing)

- `Reg16`, `SegReg`, `IP` have type `u16`.
- `FlagBit` and `FlagPred` have type `bool`.
- `LOAD8` returns `u8`; `LOAD16` returns `u16`.
- `MEM8(...) = v` requires `v:u8`; `MEM16(...) = v` requires `v:u16`.
- `if (Cond) goto L` requires `Cond:bool`.
- No implicit casts. Literals must fit the required type.

**Recommended restriction (normative if you want maximum sanity):** `CMP*` and `TEST*` are statement-only (their returned value, if any, is unusable). Tools can enforce this by rejecting uses of `CMP*`/`TEST*` in rvalue positions.

---

## 7. Dynamic semantics (execution)

MC0 uses strict **left-to-right** evaluation of arguments.

### 7.1 Memory
- `LOAD8(seg,off)` evaluates `seg` then `off`, returns `MEM[lin(seg,off)]`.
- `LOAD16(seg,off)` returns `load16(lin(seg,off))`.
- `MEM8(seg,off)=v` stores one byte at `lin(seg,off)`.
- `MEM16(seg,off)=v` stores two bytes little-endian at `lin(seg,off)`.

All offset arithmetic is modulo 65536.

### 7.2 Parity helper
`parity8(x:u8)=1` iff `x` has an even number of set bits.

### 7.3 ALU flag rules
All arithmetic is modulo bit-width, but flags are computed from the full (unbounded) result.

#### ADD16(a,b)
Let `full = a + b` as unbounded integer, `sum = full mod 65536`.
- `CF = 1` iff `full >= 65536`
- `ZF = 1` iff `sum == 0`
- `SF = 1` iff bit15(sum)==1
- `PF = parity8(sum & 0xFF)`
- `AF = 1` iff `((a xor b xor sum) & 0x10) != 0`
- `OF = 1` iff signed overflow (two's complement):
  `OF = (((a xor sum) & (b xor sum) & 0x8000) != 0)`
Returns `sum`.

#### SUB16(a,b) and CMP16(a,b)
Let `full = a - b`, `diff = full mod 65536`.
- `CF = 1` iff `a < b` (unsigned borrow)
- `ZF = 1` iff `diff == 0`
- `SF = 1` iff bit15(diff)==1
- `PF = parity8(diff & 0xFF)`
- `AF = 1` iff `((a xor b xor diff) & 0x10) != 0`
- `OF = 1` iff signed overflow:
  `OF = (((a xor b) & (a xor diff) & 0x8000) != 0)`
`SUB16` returns `diff`. `CMP16` updates flags identically but its value is ignored.

#### Bitwise (AND16/OR16/XOR16) and TEST16
Let `r = op(a,b) mod 65536`.
- `CF = 0`, `OF = 0`
- `ZF, SF, PF` computed from `r`
- `AF` is implementation-defined on real x86; MC0 sets `AF = 0` deterministically.
`TEST16` updates flags like AND16 but its value is ignored.

#### INC16/DEC16
`INC16(x)` is `x+1` with all flags like ADD16 except **CF is unchanged**.
`DEC16(x)` is `x-1` with all flags like SUB16 except **CF is unchanged**.

8-bit forms (ADD8/SUB8/AND8/...) are identical with width=8.

### 7.4 Flag predicate primitives
All `Jcc()` return `bool` based on current flags:

- `JZ = (ZF==1)`, `JNZ=(ZF==0)`
- `JC=(CF==1)`, `JNC=(CF==0)`
- `JA=(CF==0 && ZF==0)`, `JBE=(CF==1 || ZF==1)`
- `JAE=(CF==0)`, `JB=(CF==1)`
- `JL=(SF!=OF)`, `JGE=(SF==OF)`
- `JG=(ZF==0 && SF==OF)`, `JLE=(ZF==1 || SF!=OF)`
- `JO=(OF==1)`, `JNO=(OF==0)`
- `JS=(SF==1)`, `JNS=(SF==0)`

### 7.5 Stack primitives
Stack uses `SS:SP`.

- `PUSH16(x)`:
  - `SP := (SP - 2) mod 65536`
  - `store16(lin(SS,SP), x)`
- `POP16()`:
  - `x := load16(lin(SS,SP))`
  - `SP := (SP + 2) mod 65536`
  - returns `x`
- `RET_NEAR()`:
  - `IP := POP16()`
  - control returns to caller (or terminates current unit in a whole-program model)
- `RET_FAR()`:
  - `IP := POP16()`
  - `CS := POP16()`
  - control returns far

### 7.6 CLI/STI
`CLI()` sets `IF := 0`. `STI()` sets `IF := 1`.

### 7.7 INT(n)
`INT(n)` is an external transition.

Two compliant semantics options:

- **Uninterpreted external:** `S' = EXT_INT(S,n)` where `EXT_INT` is a deterministic function supplied by the environment.
- **Modeled:** the tool provides concrete interrupt models (BIOS/DOS/etc.).

MC0 itself requires only determinism, not completeness.

### 7.8 Control flow
MC0 control flow is via labels/gotos.
- `goto L` jumps to the statement following label `L`.
- `if (c) goto L` evaluates `c` and jumps if true.
- `return` terminates the current unit.
- `halt` terminates program execution.

---

## 8. Origin metadata and verification

MC0 statements may carry optional metadata:

- `origin.addr : u32` (or `u16:seg+off`),
- `origin.bytes : byte[]` (exact original bytes for the corresponding instruction(s)),
- `origin.note : string` (optional).

### 8.1 Byte-identity verification
A statement is *byte-verified* if its lowering emits exactly `origin.bytes`.

Two common emission strategies:

- **Re-emit-by-origin (always exact):** ignore statement structure and emit stored `origin.bytes` in address order.
- **Canonical encoding (structural):** define one canonical encoding for each statement form (e.g., `AX=imm16` uses `mov ax,imm16`). Verification checks emitted bytes equal `origin.bytes`.

### 8.2 Well-formedness for origin emission
If using origin emission, statements must not overlap in address range; ordering must be consistent with control flow.

---

## 9. Well-formedness constraints (recommended)

- No memory access except `LOAD*/MEM*`.
- No implicit casts.
- Fixed evaluation order (left-to-right).
- `CMP*`/`TEST*` used only as statements.
- All labels unique; all gotos target a label.

---

## 10. Minimal starter subset

A minimal MC0 subset sufficient for many DOS programs:
- register/segment assignments,
- `LOAD16/MEM16` and later `LOAD8/MEM8`,
- `ADD16/SUB16/CMP16/AND16/OR16/XOR16`,
- `Jcc()` predicates,
- labels + `goto` + `if goto`,
- `INT(n)`, `PUSH16/POP16`, `RET_NEAR/RET_FAR`,
- `CLI()/STI()`.
