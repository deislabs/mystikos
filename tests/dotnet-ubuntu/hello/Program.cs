using System;
using System.Diagnostics;

namespace hello
{
    class Program
    {
        static void test_divide_by_zero()
        {
            int q, a = 5, b = 0;
            try {
                q = a / b;
            } catch (DivideByZeroException e) {
                Console.WriteLine("Exception caught: {0}", e);
            }
        }
        static void test_null_str_op()
        {
            string s = null;
            try {
                int len = s.Length;
            } catch (NullReferenceException e) {
                Console.WriteLine("Exception caught: {0}", e);
            }
        }

        static void test_process_starttime()
        {
            DateTime startTime = Process.GetCurrentProcess().StartTime;
            Console.WriteLine("process startTime: {0}", startTime);
        }

        static void Main(string[] args)
        {
            // test handling multiple SIGFPEs.
            test_divide_by_zero();
            test_divide_by_zero();
            
            // test handling mutliple SIGSEGVs.
            test_null_str_op();
            test_null_str_op();

            test_process_starttime();
        }  
    }
}
