using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace hello
{
    class Program
    {
        static int ENOTSUP = 95;
        static void fail(String reason)
        {
            Console.WriteLine(reason);
            System.Environment.Exit(1);  
        }

        static void test_bind_to_non_hostfs_path_fail()
        {
            Socket socket = new Socket(
                AddressFamily.Unix, SocketType.Stream, ProtocolType.IP
            );
            try
            {
                socket.Bind(new UnixDomainSocketEndPoint("/tmp/sockbar"));
            }
            catch (SocketException se)
            {
                if (se.ErrorCode != ENOTSUP)
                    fail("Wrong error code: "+se.ErrorCode+". Expected ENOTSUP(95).");
                return;
            }
            catch (Exception e)
            {
                fail("Wrong exception thrown: "+e.ToString()+". Expected SocketException.");
            }
            fail("SocketException not thrown.");
        }

        static void test_connect_to_hostfs_path()
        {
            Socket socket = new Socket(
                AddressFamily.Unix, SocketType.Stream, ProtocolType.IP);
            socket.SendTimeout = 15000; // in milliseconds  
            socket.Connect(new UnixDomainSocketEndPoint("/mnt/host/hostsockfoo"));
            byte[] data = Encoding.ASCII.GetBytes("foo bar baz");
            socket.Send(data, data.Length, SocketFlags.None);

            Byte[] bytesReceived = new Byte[256];
            int nrcv = socket.Receive(bytesReceived, bytesReceived.Length, 0);
            Console.WriteLine("nrcv="+nrcv);
            Console.WriteLine(Encoding.ASCII.GetString(bytesReceived));
            socket.Close();
        }

        static void Main(string[] args)
        {
            test_bind_to_non_hostfs_path_fail();
            test_connect_to_hostfs_path();
        }
    }
}
