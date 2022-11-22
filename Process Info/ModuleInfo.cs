using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MemoryHacks
{
    public class ModuleInfo
    {
        public IntPtr BaseAddress { get; private set; }
        public uint IntBaseAddress { get; private set; }
        public uint MemorySize { get; private set; }
        public ProcessModule Module { get; private set; }
        public Process DiagnosticsProcess { get; private set; }
        public uint ProcessId { get; private set; }
        public string ModuleName { get; private set; }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

        public ModuleInfo(string moduleName, ProcessModule module, IntPtr baseAddress, uint memorySize, uint processId, Process diagnosticsProcess)
        {
            ModuleName = moduleName;
            Module = module;
            BaseAddress = baseAddress;
            MemorySize = memorySize;
            IntBaseAddress = (uint)baseAddress;
            ProcessId = processId;
            DiagnosticsProcess = diagnosticsProcess;
        }

        public void Eject(CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            try
            {
                IntPtr remoteThread = new IntPtr(0);
                IntPtr freeLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");

                switch (threadFunction)
                {
                    case CreateThreadFunction.CreateRemoteThread:
                        CreateRemoteThread(DiagnosticsProcess.Handle, IntPtr.Zero, 0, freeLibraryAddress, BaseAddress, 0, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.RtlCreateUserThread:
                        RtlCreateUserThread(DiagnosticsProcess.Handle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAddress, BaseAddress, ref remoteThread, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.NtCreateThreadEx:
                        NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, DiagnosticsProcess.Handle, freeLibraryAddress, BaseAddress, false, 0, 0, 0, IntPtr.Zero);
                        break;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while ejecting the module.\r\n{ex.Message}\r\n{ex.Source}\r\n{ex.StackTrace}");
            }
        }
    }
}