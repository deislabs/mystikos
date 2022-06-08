using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace hello
{
    class Program
    {
        static void Main(string[] args)
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
    }
}
