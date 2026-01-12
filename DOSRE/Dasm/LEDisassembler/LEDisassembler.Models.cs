using System;
using System.Collections.Generic;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        public sealed class LeBasicBlockInfo
        {
            public uint Start { get; set; }
            public List<uint> Predecessors { get; set; } = new List<uint>();
            public List<uint> Successors { get; set; } = new List<uint>();
        }

        public sealed class LeFunctionCfg
        {
            public uint FunctionStart { get; set; }
            public Dictionary<uint, LeBasicBlockInfo> Blocks { get; } = new Dictionary<uint, LeBasicBlockInfo>();
        }

        public sealed class LeFunctionInfo
        {
            public uint Start { get; set; }
            public int InstructionCount { get; set; }
            public int BlockCount { get; set; }
            public List<uint> Calls { get; set; } = new List<uint>();
            public List<string> Globals { get; set; } = new List<string>();
            public List<string> Strings { get; set; } = new List<string>();
        }

        public sealed class LeAnalysis
        {
            public string InputFile { get; set; }
            public uint EntryLinear { get; set; }
            public Dictionary<uint, LeFunctionInfo> Functions { get; } = new Dictionary<uint, LeFunctionInfo>();
            public Dictionary<uint, LeFunctionCfg> CfgByFunction { get; } = new Dictionary<uint, LeFunctionCfg>();
        }

        public sealed class LeObjectInfo
        {
            public int index { get; set; }
            public uint virtualSize { get; set; }
            public uint baseAddress { get; set; }
            public uint flags { get; set; }
            public uint pageMapIndex { get; set; }
            public uint pageCount { get; set; }
        }

        public sealed class LeFixupRecordInfo
        {
            public uint siteLinear { get; set; }
            public uint sourceLinear { get; set; }
            public uint? instructionLinear { get; set; }
            public sbyte siteDelta { get; set; }
            public ushort sourceOffsetInPage { get; set; }
            public uint logicalPageNumber { get; set; }
            public uint physicalPageNumber { get; set; }

            public byte type { get; set; }
            public byte flags { get; set; }
            public int recordStreamOffset { get; set; }
            public int stride { get; set; }

            // Raw record bytes (best-effort, truncated to keep JSON manageable).
            public byte[] recordBytes { get; set; }

            // Best-effort parsed spec fields from within the record (never read across stride).
            public ushort? specU16 { get; set; }
            public ushort? specU16b { get; set; }
            public uint? specU32 { get; set; }

            public uint? siteValue32 { get; set; }
            public ushort? siteValue16 { get; set; }

            public string targetKind { get; set; } // "internal", "import", "far", "unknown"
            public int? targetObject { get; set; }
            public uint? targetOffset { get; set; }
            public uint? targetLinear { get; set; }
            public int? addend32 { get; set; }

            public ushort? importModuleIndex { get; set; }
            public string importModule { get; set; }
            public uint? importProcNameOffset { get; set; }
            public string importProc { get; set; }
        }

        public sealed class LeFixupChainInfo
        {
            public string targetKind { get; set; }
            public int? targetObject { get; set; }
            public uint? targetOffset { get; set; }
            public uint? targetLinear { get; set; }
            public ushort? importModuleIndex { get; set; }
            public uint? importProcNameOffset { get; set; }
            public int count { get; set; }
        }

        public sealed class LeFixupTableInfo
        {
            public string inputFile { get; set; }
            public uint entryLinear { get; set; }
            public uint pageSize { get; set; }
            public uint numberOfPages { get; set; }

            public LeObjectInfo[] objects { get; set; }
            public string[] importModules { get; set; }
            public LeFixupRecordInfo[] fixups { get; set; }
            public LeFixupChainInfo[] chains { get; set; }
        }

        public sealed class LeReachabilityRangeInfo
        {
            public uint startLinear { get; set; }
            public uint endLinear { get; set; }
        }

        public sealed class LeReachabilityObjectInfo
        {
            public int index { get; set; }
            public uint baseAddress { get; set; }
            public uint virtualSize { get; set; }
            public uint flags { get; set; }

            public uint decodedStartLinear { get; set; }
            public uint decodedEndLinear { get; set; }

            public int instructionCount { get; set; }
            public int reachableInstructionCount { get; set; }
            public int reachableByteCount { get; set; }

            public LeReachabilityRangeInfo[] reachableCodeRanges { get; set; }
            public LeReachabilityRangeInfo[] dataCandidateRanges { get; set; }
        }

        public sealed class LeReachabilityInfo
        {
            public string inputFile { get; set; }
            public uint entryLinear { get; set; }
            public LeReachabilityObjectInfo[] objects { get; set; }
        }
    }
}
