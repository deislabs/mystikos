using System;
using System.Diagnostics;
namespace hello
{
    class Program
    {
        static void inner()
        {
            long a,b,c,d,e,f,g,h,i,j,k,l,m,n; 
            inner();
        }
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            inner();
        }  
    }
}
