using System;
using System.Diagnostics;

namespace processMainModule
{
    class Program
    {
        static void Main(string[] args)
        {
            Process p = Process.GetCurrentProcess();
            var moduleName = p.MainModule.ModuleName;
            Console.WriteLine(moduleName);
        }
    }
}
