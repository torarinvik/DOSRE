using System.Collections.Generic;

namespace DOSRE.Dasm
{
    public static partial class LEDisassembler
    {
        private sealed class LEFixup
        {
            public uint SourceLinear;
            public ushort SourceOffsetInPage;
            public uint PageNumber; // 1-based physical page
            public uint SiteLinear;
            public sbyte SiteDelta;
            public uint? Value32;
            public int? TargetObject;
            public uint? TargetOffset;
            public byte Type;
            public byte Flags;

            public byte TargetType;
            public string ImportModule;
            public string ImportProc;
        }

        private struct LEHeader
        {
            public int HeaderOffset;
            public string ModuleName;
            public uint ModuleFlags;
            public uint NumberOfPages;
            public uint EntryEipObject;
            public uint EntryEip;
            public uint EntryEspObject;
            public uint EntryEsp;
            public uint PageSize;
            public uint LastPageSize;
            public uint ObjectTableOffset;
            public uint ObjectCount;
            public uint ObjectPageMapOffset;
            public uint FixupPageTableOffset;
            public uint FixupRecordTableOffset;
            public uint ImportModuleTableOffset;
            public uint ImportModuleTableEntries;
            public uint ImportProcTableOffset;
            public uint DataPagesOffset;
            public uint ResidentNameTableOffset;
            public uint NonResidentNameTableOffset;
            public uint EntryTableOffset;
            public Dictionary<ushort, string> Exports;
        }

        private struct LEObject
        {
            public int Index;
            public uint VirtualSize;
            public uint BaseAddress;
            public uint Flags;
            public uint PageMapIndex; // 1-based
            public uint PageCount;

            public uint RelocBaseAddr => BaseAddress;
            public int ObjectNumber => Index;
        }
    }
}
