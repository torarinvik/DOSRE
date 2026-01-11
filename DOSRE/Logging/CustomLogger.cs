using NLog;
using NLog.Layouts;
using System;

namespace DOSRE.Logging
{
    public class CustomLogger : Logger
    {

        static CustomLogger()
        {
            // Don't override an existing NLog configuration.
            // This allows test code (and future hosts) to provide their own config
            // without getting forced into noisy console logging.
            if (LogManager.Configuration != null)
                return;

            var config = new NLog.Config.LoggingConfiguration();

            //Setup Console Logging
            var logconsole = new NLog.Targets.ConsoleTarget("logconsole")
            {
                Error = true,
                Layout = Layout.FromString("${shortdate}\t${time}\t${message}")
            };
            config.AddTarget(logconsole);
            config.AddRuleForAllLevels(logconsole);

            LogManager.Configuration = config;
        }
    }
}
