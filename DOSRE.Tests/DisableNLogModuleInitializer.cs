using System.Runtime.CompilerServices;
using NLog;
using NLog.Config;

namespace DOSRE.Tests;

internal static class DisableNLogModuleInitializer
{
    [ModuleInitializer]
    internal static void Init()
    {
        // Tests should be quiet by default. The production app configures NLog,
        // but test output shouldn't be polluted by informational logs.
        LogManager.Configuration = new LoggingConfiguration();
        LogManager.ReconfigExistingLoggers();
    }
}
