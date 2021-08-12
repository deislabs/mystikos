using System;
using System.Diagnostics;
namespace hello
{
    class Program
    {
        static void recurse_until_ovf()
        {
            long a,b,c,d,e,f,g,h,i,j,k,l,m,n; 
            recurse_until_ovf();
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            // Trigger stack overflow test only for linux target
            String mystTarget = Environment.GetEnvironmentVariable("MYST_TARGET");
            if (mystTarget.Equals("linux"))
                recurse_until_ovf();
        }
    }
}
