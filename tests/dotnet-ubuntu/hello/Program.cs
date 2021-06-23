using System;
using System.Diagnostics;

namespace hello
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            int q, a = 5, b = 0;
            try {
                q = a / b;
            } catch (DivideByZeroException e) {
                Console.WriteLine("Exception caught: {0}", e);
                return;
            }
            // unreachable
            Environment.Exit(1);
        }  
    }
}
