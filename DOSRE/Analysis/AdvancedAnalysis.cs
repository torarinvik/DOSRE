using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using DOSRE.Analysis.Artifacts;
using DOSRE.Artifacts;
using DOSRE.Dasm;
using DOSRE.Enums;
using DOSRE.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using NLog;
using SharpDisasm.Udis86;

namespace DOSRE.Analysis
{
    /// <summary>
    ///     Performs best-effort analysis on disassembly output:
    ///     - Imported function annotation (when module definition JSON files are embedded)
    ///     - Subroutine identification
    ///     - Turbo C++ FOR-loop identification
    /// </summary>
    public static class AdvancedAnalysis
    {
        private static readonly Logger _logger = LogManager.GetCurrentClassLogger(typeof(CustomLogger));
        private static readonly List<ModuleDefinition> ModuleDefinitions;

        static AdvancedAnalysis()
        {
            ModuleDefinitions = new List<ModuleDefinition>();

            var assembly = typeof(AdvancedAnalysis).GetTypeInfo().Assembly;
            foreach (var def in assembly.GetManifestResourceNames()
                         .Where(x => x.EndsWith("_def.json", StringComparison.OrdinalIgnoreCase)))
            {
                using (var stream = assembly.GetManifestResourceStream(def))
                {
                    if (stream == null)
                        continue;

                    using (var reader = new StreamReader(stream))
                    {
                        var json = reader.ReadToEnd();
                        if (!LooksLikeModuleDefinition(json))
                            continue;

                        try
                        {
                            var moduleDefinition = JsonConvert.DeserializeObject<ModuleDefinition>(json);
                            if (moduleDefinition?.Name == null || moduleDefinition.Exports == null)
                                continue;
                            ModuleDefinitions.Add(moduleDefinition);
                        }
                        catch (Exception ex)
                        {
                            _logger.Debug(ex, $"Skipping malformed module definition resource: {def}");
                        }
                    }
                }
            }
        }

        private static bool LooksLikeModuleDefinition(string json)
        {
            try
            {
                var obj = JObject.Parse(json);
                return obj["Name"]?.Type == JTokenType.String && obj["Exports"]?.Type == JTokenType.Array;
            }
            catch
            {
                return false;
            }
        }

        public static void Analyze(NEFile file)
        {
            ImportedFunctionIdentification(file);
            SubroutineIdentification(file);
            ForLoopIdentification(file);
        }

        /// <summary>
        ///     Imported function annotation using embedded Module Definition JSON files.
        ///     (If none are present, this pass becomes a no-op.)
        /// </summary>
        private static void ImportedFunctionIdentification(NEFile file)
        {
            _logger.Info($"Identifying Imported Functions");

            if (ModuleDefinitions.Count == 0)
            {
                _logger.Info($"No module definition resources embedded, skipping Imported Function Identification");
                return;
            }

            if (!file.ImportedNameTable.Any(nt => ModuleDefinitions.Select(md => md.Name).Contains(nt.Name)))
            {
                _logger.Info($"No known Module Definitions found in target file, skipping Imported Function Identification");
                return;
            }

            var trackedVariables = new List<TrackedVariable>();

            foreach (var segment in file.SegmentTable.Where(x => x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                foreach (var disassemblyLine in segment.DisassemblyLines.Where(x =>
                             x.BranchToRecords.Any(y => y.BranchType == EnumBranchType.CallImport || y.BranchType == EnumBranchType.SegAddrImport)))
                {
                    var currentImport =
                        disassemblyLine.BranchToRecords.First(z => z.BranchType == EnumBranchType.CallImport || z.BranchType == EnumBranchType.SegAddrImport);

                    var currentModule =
                        ModuleDefinitions.FirstOrDefault(x =>
                            x.Name == file.ImportedNameTable.FirstOrDefault(y => y.Ordinal == currentImport.Segment)?.Name);

                    if (currentModule == null)
                        continue;

                    var definition = currentModule.Exports.FirstOrDefault(x => x.Ord == currentImport.Offset);
                    if (definition == null)
                        continue;

                    disassemblyLine.Comments.Add(!string.IsNullOrEmpty(definition.Signature)
                        ? definition.Signature
                        : $"{currentModule.Name}.{definition.Name}");

                    if (!string.IsNullOrEmpty(definition.SignatureFormat) && definition.PrecedingInstructions != null &&
                        definition.PrecedingInstructions.Count > 0)
                    {
                        var values = new List<object>();
                        foreach (var pi in definition.PrecedingInstructions)
                        {
                            var i = segment.DisassemblyLines.FirstOrDefault(x =>
                                x.Ordinal == disassemblyLine.Ordinal + pi.Offset &&
                                x.Disassembly.Mnemonic.ToString().ToUpper().EndsWith(pi.Op));

                            if (i == null)
                                break;

                            switch (pi.Type)
                            {
                                case "int":
                                    values.Add(i.Disassembly.Operands[0].LvalSDWord);
                                    break;
                                case "string":
                                    if (i.Comments.Any(x => x.Contains("reference")))
                                    {
                                        var resolvedStringComment = i.Comments.First(x => x.Contains("reference"));
                                        values.Add(resolvedStringComment.Substring(resolvedStringComment.IndexOf('\"')));
                                    }
                                    break;
                                case "char":
                                    values.Add((char)i.Disassembly.Operands[0].LvalSDWord);
                                    break;
                            }
                        }

                        if (values.Count == definition.PrecedingInstructions.Count)
                            disassemblyLine.Comments.Add(string.Format($"Resolved Signature: {definition.SignatureFormat}",
                                values.Select(x => x.ToString()).ToArray()));
                    }

                    if (definition.ReturnValues != null && definition.ReturnValues.Count > 0)
                    {
                        foreach (var rv in definition.ReturnValues)
                        {
                            var i = segment.DisassemblyLines.FirstOrDefault(x =>
                                x.Ordinal == disassemblyLine.Ordinal + rv.Offset &&
                                x.Disassembly.Mnemonic.ToString().ToUpper().EndsWith(rv.Op));

                            if (i == null)
                                break;

                            i.Comments.Add($"Return value saved to 0x{i.Disassembly.Operands[0].LvalUWord:X}h");

                            if (!string.IsNullOrEmpty(rv.Comment))
                                i.Comments.Add(rv.Comment);

                            trackedVariables.Add(new TrackedVariable()
                            {
                                Comment = rv.Comment,
                                Segment = segment.Ordinal,
                                Offset = i.Disassembly.Offset,
                                Address = i.Disassembly.Operands[0].LvalUWord
                            });
                        }
                    }

                    if (definition.Comments != null && definition.Comments.Count > 0)
                        disassemblyLine.Comments.AddRange(definition.Comments);
                }

                foreach (var v in trackedVariables)
                {
                    foreach (var disassemblyLine in segment.DisassemblyLines.Where(x =>
                                 x.Disassembly.ToString().Contains($"[0x{v.Address:X}]".ToLower()) && x.Disassembly.Offset != v.Offset))
                    {
                        disassemblyLine.Comments.Add($"Reference to variable created at {v.Segment:0000}.{v.Offset:X4}h");
                    }
                }
            }
        }

        private static void ForLoopIdentification(NEFile file)
        {
            _logger.Info($"Identifying FOR Loops");

            foreach (var segment in file.SegmentTable.Where(x =>
                         x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                foreach (var disassemblyLine in segment.DisassemblyLines.Where(x =>
                             x.Disassembly.Mnemonic == ud_mnemonic_code.UD_Icmp &&
                             x.BranchFromRecords.Any(y => y.BranchType == EnumBranchType.Unconditional)))
                {
                    if (MnemonicGroupings.IncrementDecrementGroup.Contains(segment.DisassemblyLines
                                .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Disassembly.Mnemonic)
                        && segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).BranchToRecords.Count > 0
                        && segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).BranchToRecords
                            .First(x => x.BranchType == EnumBranchType.Conditional)
                            .Offset < disassemblyLine.Disassembly.Offset)
                    {
                        if (MnemonicGroupings.IncrementGroup.Contains(segment.DisassemblyLines
                                .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Disassembly
                                .Mnemonic))
                        {
                            segment.DisassemblyLines
                                .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Comments
                                .Add("[FOR] Increment Value");
                        }
                        else
                        {
                            segment.DisassemblyLines
                                .First(x => x.Ordinal == disassemblyLine.Ordinal - 1).Comments
                                .Add("[FOR] Decrement Value");
                        }

                        disassemblyLine.Comments.Add("[FOR] Evaluate Break Condition");

                        segment.DisassemblyLines
                            .First(x => x.Disassembly.Offset == disassemblyLine.BranchFromRecords
                                            .First(y => y.BranchType == EnumBranchType.Unconditional).Offset).Comments
                            .Add("[FOR] Beginning of FOR logic");

                        segment.DisassemblyLines
                            .First(x => x.Ordinal == disassemblyLine.Ordinal + 1).Comments
                            .Add("[FOR] Branch based on evaluation");
                    }
                }
            }
        }

        private static void SubroutineIdentification(NEFile file)
        {
            _logger.Info($"Identifying Subroutines");

            foreach (var segment in file.SegmentTable.Where(x =>
                         x.Flags.Contains(EnumSegmentFlags.Code) && x.DisassemblyLines.Count > 0))
            {
                ushort subroutineId = 0;
                var bInSubroutine = false;
                for (var i = 0; i < segment.DisassemblyLines.Count; i++)
                {
                    if (bInSubroutine)
                        segment.DisassemblyLines[i].SubroutineID = subroutineId;

                    if (segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Ienter ||
                        segment.DisassemblyLines[i].BranchFromRecords.Any(x => x.BranchType == EnumBranchType.Call) ||
                        segment.DisassemblyLines[i].ExportedFunction != null ||
                        (i > 0 &&
                         (segment.DisassemblyLines[i - 1].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iretf ||
                          segment.DisassemblyLines[i - 1].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iret)))
                    {
                        subroutineId++;
                        bInSubroutine = true;
                        segment.DisassemblyLines[i].SubroutineID = subroutineId;
                        segment.DisassemblyLines[i].Comments.Insert(0, $"/---- BEGIN SUBROUTINE {subroutineId}");
                        continue;
                    }

                    if (bInSubroutine && (segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iret ||
                                          segment.DisassemblyLines[i].Disassembly.Mnemonic == ud_mnemonic_code.UD_Iretf))
                    {
                        bInSubroutine = false;
                        segment.DisassemblyLines[i].Comments.Insert(0, $"\\---- END SUBROUTINE {subroutineId}");
                    }
                }
            }
        }
    }
}
