using DOSRE.UI;
using DOSRE.UI.impl;
using System;

namespace DOSRE
{
    /// <summary>
    ///     Main ConsoleUI Entrypoint
    /// </summary>
    class Program
    {
        

        private static IUserInterface _userInterface;

        static void Main(string[] args)
        {
            // Set the interface based on the args passed in.
            // If TUI initialization fails (common on unsupported/non-interactive terminals), fall back to CLI help.
            if (args.Length == 0)
            {
                try
                {
                    _userInterface = new InteractiveUI();
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Failed to start Text UI (TUI). Falling back to CLI mode.");
                    Console.Error.WriteLine(ex.Message);
                    _userInterface = new ConsoleUI(new[] { "-?" });
                }
            }
            else
            {
                _userInterface = new ConsoleUI(args);
            }

            _userInterface.Run();
        }

        
    }
}