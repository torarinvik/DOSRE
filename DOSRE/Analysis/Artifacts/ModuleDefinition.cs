using System.Collections.Generic;

namespace DOSRE.Analysis.Artifacts
{
    public class ModuleDefinition
    {
        public string Name { get; set; }
        public string Comment { get; set; }
        public List<Export> Exports { get; set; }
    }
}