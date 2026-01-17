using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.Json.Serialization;

namespace DOSRE.Dasm
{
    /// <summary>
    /// A deliberately small, explicit operational semantics model for the "crude" lifted stream.
    ///
    /// This is the start of the "formal model" piece: the goal is to have a single-step function
    /// with well-defined state transitions. Over time we extend the supported instruction subset.
    ///
    /// Note: This currently models only a minimal subset of real-mode-ish 16-bit operations and
    /// treats interrupts and other external effects as opaque events.
    /// </summary>
    public sealed class CrudeCpuModel
    {
        public sealed class State
        {
            public ushort AX, BX, CX, DX, SI, DI, BP, SP;
            public ushort CS, DS, ES, SS;
            public ushort IP;

            // Flags (subset)
            public bool CF, ZF, SF, OF, PF, AF, IF, DF;

            public State Clone() => (State)MemberwiseClone();
        }

        public sealed class StepEvent
        {
            [JsonPropertyName("kind")]
            public string Kind { get; set; }

            [JsonPropertyName("detail")]
            public string Detail { get; set; }
        }

        public static bool TryStep(State s, Bin16AsmLifter.LiftNode node, out StepEvent ev, out string error)
        {
            ev = null;
            error = null;

            if (s == null) { error = "state is null"; return false; }
            if (node == null) { error = "node is null"; return false; }
            if (node.Kind != "insn" && node.Kind != "db") { error = "node is not executable"; return false; }
            if (node.Addr == null || string.IsNullOrWhiteSpace(node.BytesHex)) { error = "missing addr/bytes"; return false; }

            // Default linear execution: advance IP by instruction length.
            // (Control flow is not modeled yet; this is scaffolding for semantics validation.)
            var len = (ushort)(node.BytesHex.Length / 2);

            var asm = (node.Asm ?? string.Empty).Trim();
            if (asm.Length == 0)
            {
                s.IP = (ushort)(s.IP + len);
                return true;
            }

            // Very small subset: enough to validate the earliest prologues in many DOS stubs.
            // mov r16, sreg
            if (asm.Equals("mov ax,cs", StringComparison.OrdinalIgnoreCase)) { s.AX = s.CS; s.IP = (ushort)(s.IP + len); return true; }
            if (asm.Equals("mov ax,ds", StringComparison.OrdinalIgnoreCase)) { s.AX = s.DS; s.IP = (ushort)(s.IP + len); return true; }
            if (asm.Equals("mov ax,es", StringComparison.OrdinalIgnoreCase)) { s.AX = s.ES; s.IP = (ushort)(s.IP + len); return true; }
            if (asm.Equals("mov ax,ss", StringComparison.OrdinalIgnoreCase)) { s.AX = s.SS; s.IP = (ushort)(s.IP + len); return true; }

            // mov sreg, r16 (only a couple used often)
            if (asm.Equals("mov es,ax", StringComparison.OrdinalIgnoreCase)) { s.ES = s.AX; s.IP = (ushort)(s.IP + len); return true; }
            if (asm.Equals("mov ds,ax", StringComparison.OrdinalIgnoreCase)) { s.DS = s.AX; s.IP = (ushort)(s.IP + len); return true; }

            // cli/sti
            if (asm.Equals("cli", StringComparison.OrdinalIgnoreCase)) { s.IF = false; s.IP = (ushort)(s.IP + len); return true; }
            if (asm.Equals("sti", StringComparison.OrdinalIgnoreCase)) { s.IF = true; s.IP = (ushort)(s.IP + len); return true; }

            // ret
            if (asm.Equals("ret", StringComparison.OrdinalIgnoreCase))
            {
                ev = new StepEvent { Kind = "unmodeled", Detail = "ret (stack/memory not modeled yet)" };
                error = "ret not modeled yet";
                return false;
            }

            // int imm8 => external effect.
            if (asm.StartsWith("int ", StringComparison.OrdinalIgnoreCase))
            {
                var tok = asm.Substring(4).Trim();
                // Accept formats: 21h / 0x21 / 21
                byte? intNo = TryParseByte(tok);
                ev = new StepEvent { Kind = "int", Detail = intNo.HasValue ? $"0x{intNo.Value:X2}" : tok };
                s.IP = (ushort)(s.IP + len);
                return true;
            }

            error = $"unsupported semantics for: '{asm}'";
            return false;
        }

        private static byte? TryParseByte(string tok)
        {
            if (string.IsNullOrWhiteSpace(tok)) return null;
            tok = tok.Trim();
            if (tok.EndsWith("h", StringComparison.OrdinalIgnoreCase))
                tok = tok.Substring(0, tok.Length - 1);
            if (tok.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                tok = tok.Substring(2);

            if (byte.TryParse(tok, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                return b;
            if (byte.TryParse(tok, out b))
                return b;
            return null;
        }

        public static IEnumerable<Bin16AsmLifter.LiftNode> ExecutableNodes(Bin16AsmLifter.LiftFile lf)
            => (lf?.Nodes ?? new List<Bin16AsmLifter.LiftNode>()).Where(n => n.Kind == "insn" || n.Kind == "db");
    }
}
