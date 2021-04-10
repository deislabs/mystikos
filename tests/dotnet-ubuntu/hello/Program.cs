using System;
using System.Diagnostics;

namespace hello
{
    class Program
    {
        static void Main(string[] args)
        {
            Debugger.Break();
            Console.WriteLine("Hello World!");
        }
    }
}
