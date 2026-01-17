using System;

namespace DOSRE.Unicorn
{
    public sealed class UnicornException : Exception
    {
        public UnicornException(string message) : base(message)
        {
        }
    }
}
