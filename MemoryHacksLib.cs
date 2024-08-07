﻿using System.Diagnostics;
using System;
using System.Runtime.InteropServices;
using System.Numerics;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace MemoryHacks
{
    public class MemoryHacksLib
    {
        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, uint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern int ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", PreserveSig = false)]
        private static extern void NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", PreserveSig = false, SetLastError = true)]
        private static extern void NtResumeProcess(IntPtr processHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);

        private delegate bool EnumThreadDelegate(IntPtr hWnd, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumThreadWindows(int dwThreadId, EnumThreadDelegate lpfn, IntPtr lParam);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, ref IntPtr NumberOfBytesRead);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern IntPtr NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

        [StructLayout(LayoutKind.Sequential)]
        private struct ModuleInformation
        {
            public IntPtr lpBaseOfDll;
            public uint SizeOfImage;
            public IntPtr EntryPoint;
        }

        internal enum ModuleFilter
        {
            ListModulesDefault = 0x0,
            ListModules32Bit = 0x01,
            ListModules64Bit = 0x02,
            ListModulesAll = 0x03,
        }

        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModulesEx(IntPtr hProcess, [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] IntPtr[] lphModule, int cb, [MarshalAs(UnmanagedType.U4)] out int lpcbNeeded, uint dwFilterFlag);

        [DllImport("psapi.dll")]
        private static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In][MarshalAs(UnmanagedType.U4)] uint nSize);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetModuleInformation(IntPtr hProcess, IntPtr hModule, out ModuleInformation lpmodinfo, uint cb);

        public int ProcessId { get; private set; }
        public IntPtr ProcessHandle { get; private set; }
        public Process DiagnosticsProcess { get; private set; }
        public IntPtr BaseAddress { get; private set; }
        public MemoryMethod WriteMethod { get; set; }
        public MemoryMethod ReadMethod { get; set; }
        public MemoryMethod ProtectMethod { get; set; }

        private uint MEM_COMMIT = 0x00001000;
        private uint MEM_RESERVE = 0x00002000;
        private uint PAGE_READWRITE = 4;

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process([In] IntPtr processHandle, [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);

        public MemoryHacksLib(int processId)
        {
            bool exists = false;

            foreach (Process process in Process.GetProcesses())
            {
                if (process.Id == processId)
                {
                    exists = true;
                    ProcessHandle = OpenProcess(0x001F0FFF, false, process.Id);
                    DiagnosticsProcess = process;
                    BaseAddress = process.MainModule.BaseAddress;
                    break;
                }
            }

            if (!exists)
            {
                throw new Exception("The specified process is not running.");
            }

            ProcessId = processId;
            ReadMethod = MemoryMethod.KERNEL32;
            WriteMethod = MemoryMethod.KERNEL32;
            ProtectMethod = MemoryMethod.KERNEL32;
        }

        public MemoryHacksLib(string processName)
        {
            int processId = -1;

            foreach (Process process in Process.GetProcesses())
            {
                if (process.ProcessName == processName)
                {
                    processId = process.Id;
                    ProcessHandle = OpenProcess(0x001F0FFF, false, process.Id);
                    DiagnosticsProcess = process;
                    BaseAddress = process.MainModule.BaseAddress;
                    break;
                }
            }

            if (processId == -1)
            {
                throw new Exception("The specified process is not running.");
            }

            ProcessId = processId;
            ReadMethod = MemoryMethod.KERNEL32;
            WriteMethod = MemoryMethod.KERNEL32;
            ProtectMethod = MemoryMethod.KERNEL32;
        }

        public ModuleInfo GetModuleInformations(string moduleName)
        {
            foreach (ModuleInfo module in GetModules())
            {
                try
                {
                    if (module.ModuleName == moduleName)
                    {
                        return module;
                    }
                }
                catch
                {

                }
            }

            throw new Exception("Could not find the informations of the specified module.");
        }

        public void SetMemoryMethod(MemoryMethod memoryMethod)
        {
            ReadMethod = memoryMethod;
            WriteMethod = memoryMethod;
            ProtectMethod = memoryMethod;
        }

        public ModuleInfo GetModule(string moduleName)
        {
            return GetModuleInformations(moduleName);
        }

        public ModuleInfo GetModuleInfo(string moduleName)
        {
            return GetModuleInformations(moduleName);
        }

        public ModuleInfo GetModuleInfos(string moduleName)
        {
            return GetModuleInformations(moduleName);
        }

        public List<ModuleInfo> GetModules()
        {
            List<ModuleInfo> modules = new List<ModuleInfo>();

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    modules.Add(new ModuleInfo(module.ModuleName, module, module.BaseAddress, (uint)module.ModuleMemorySize, (uint) DiagnosticsProcess.Id, DiagnosticsProcess));
                }
                catch
                {

                }
            }

            IntPtr[] modulePointers = new IntPtr[0];
            int bytesNeeded = 0;
            EnumProcessModulesEx(ProcessHandle, modulePointers, 0, out bytesNeeded, (uint)ModuleFilter.ListModulesAll);
            int totalNumberofModules = bytesNeeded / IntPtr.Size;
            modulePointers = new IntPtr[totalNumberofModules];

            if (EnumProcessModulesEx(ProcessHandle, modulePointers, bytesNeeded, out bytesNeeded, (uint)ModuleFilter.ListModulesAll))
            {
                for (int index = 0; index < totalNumberofModules; index++)
                {
                    StringBuilder moduleFilePath = new StringBuilder(1024);
                    GetModuleFileNameEx(ProcessHandle, modulePointers[index], moduleFilePath, (uint)(moduleFilePath.Capacity));

                    string moduleName = Path.GetFileName(moduleFilePath.ToString());

                    ModuleInformation moduleInformation = new ModuleInformation();
                    GetModuleInformation(ProcessHandle, modulePointers[index], out moduleInformation, (uint)(IntPtr.Size * (modulePointers.Length)));

                    bool exists = false;

                    foreach (ModuleInfo newMod in modules)
                    {
                        if (newMod.ModuleName.ToLower().Equals(moduleName.ToLower()) || newMod.BaseAddress.Equals(moduleInformation.lpBaseOfDll))
                        {
                            exists = true;
                            break;
                        }
                    }

                    if (!exists)
                    {
                        modules.Add(new ModuleInfo(moduleName, null, moduleInformation.lpBaseOfDll, moduleInformation.SizeOfImage, (uint)ProcessId, DiagnosticsProcess));
                    }
                }
            }

            return modules;
        }

        public byte[] ReadByteArray(IntPtr offset, uint size)
        {
            try
            {
                byte[] result = new byte[size];
                IntPtr bytesRead = IntPtr.Zero;

                if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                {
                    ReadProcessMemory(ProcessHandle, offset, result, size, out bytesRead);
                }
                else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                {
                    NtReadVirtualMemory(ProcessHandle, offset, result, size, ref bytesRead);
                }

                return result;
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to read memory." + "\r\n" + ex.Message + "\r\n" + ex.StackTrace + "\r\n" + ex.Source + "\r\n");
            }
        }

        public byte[] ReadByteArray(uint offset, uint size)
        {
            return ReadByteArray((IntPtr)offset, size);
        }

        public byte[] ReadBytes(IntPtr offset, uint size)
        {
            return ReadByteArray(offset, size);
        }

        public byte[] ReadBytes(uint offset, uint size)
        {
            return ReadByteArray(offset, size);
        }

        public byte ReadByte(IntPtr offset)
        {
            return ReadBytes(offset, 1)[0];
        }

        public byte ReadByte(uint offset)
        {
            return ReadBytes(offset, 1)[0];
        }

        public char ReadChar(IntPtr offset)
        {
            return BitConverter.ToChar(ReadBytes(offset, 1), 0);
        }

        public char ReadChar(uint offset)
        {
            return BitConverter.ToChar(ReadBytes(offset, 1), 0);
        }

        public char ReadCharacter(IntPtr offset)
        {
            return BitConverter.ToChar(ReadBytes(offset, 1), 0);
        }

        public char ReadCharacter(uint offset)
        {
            return BitConverter.ToChar(ReadBytes(offset, 1), 0);
        }

        public bool ReadBoolean(IntPtr offset)
        {
            return BitConverter.ToBoolean(ReadBytes(offset, 1), 0);
        }

        public bool ReadBoolean(uint offset)
        {
            return BitConverter.ToBoolean(ReadBytes(offset, 1), 0);
        }

        public short ReadInt16(IntPtr offset)
        {
            return BitConverter.ToInt16(ReadBytes(offset, 2), 0);
        }

        public short ReadInt16(uint offset)
        {
            return BitConverter.ToInt16(ReadBytes(offset, 2), 0);
        }

        public short ReadShort(IntPtr offset)
        {
            return BitConverter.ToInt16(ReadBytes(offset, 2), 0);
        }

        public short ReadShort(uint offset)
        {
            return BitConverter.ToInt16(ReadBytes(offset, 2), 0);
        }

        public int ReadInt32(IntPtr offset)
        {
            return BitConverter.ToInt32(ReadBytes(offset, 4), 0);
        }

        public int ReadInt32(uint offset)
        {
            return BitConverter.ToInt32(ReadBytes(offset, 4), 0);
        }

        public IntPtr ReadIntPtr(IntPtr offset)
        {
            return (IntPtr)BitConverter.ToInt32(ReadBytes(offset, 4), 0);
        }

        public IntPtr ReadIntPtr(uint offset)
        {
            return (IntPtr)BitConverter.ToInt32(ReadBytes(offset, 4), 0);
        }

        public int ReadInteger(IntPtr offset)
        {
            return BitConverter.ToInt32(ReadBytes(offset, 4), 0);
        }

        public int ReadInteger(uint offset)
        {
            return BitConverter.ToInt32(ReadBytes(offset, 4), 0);
        }

        public long ReadInt64(IntPtr offset)
        {
            return BitConverter.ToInt64(ReadBytes(offset, 8), 0);
        }

        public long ReadInt64(uint offset)
        {
            return BitConverter.ToInt64(ReadBytes(offset, 8), 0);
        }

        public long ReadLong(IntPtr offset)
        {
            return BitConverter.ToInt64(ReadBytes(offset, 8), 0);
        }

        public long ReadLong(uint offset)
        {
            return BitConverter.ToInt64(ReadBytes(offset, 8), 0);
        }

        public float ReadFloat(IntPtr offset)
        {
            return BitConverter.ToSingle(ReadBytes(offset, 4), 0);
        }

        public float ReadFloat(uint offset)
        {
            return BitConverter.ToSingle(ReadBytes(offset, 4), 0);
        }

        public float ReadSingle(IntPtr offset)
        {
            return BitConverter.ToSingle(ReadBytes(offset, 4), 0);
        }

        public float ReadSingle(uint offset)
        {
            return BitConverter.ToSingle(ReadBytes(offset, 4), 0);
        }

        public double ReadDouble(IntPtr offset)
        {
            return BitConverter.ToDouble(ReadBytes(offset, 8), 0);
        }

        public double ReadDouble(uint offset)
        {
            return BitConverter.ToDouble(ReadBytes(offset, 8), 0);
        }

        public string ReadString(IntPtr offset, uint size, Encoding encoding)
        {
            return encoding.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadString(uint offset, uint size, Encoding encoding)
        {
            return encoding.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringASCII(IntPtr offset, uint size)
        {
            return Encoding.ASCII.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringASCII(uint offset, uint size)
        {
            return Encoding.ASCII.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUTF8(IntPtr offset, uint size)
        {
            return Encoding.UTF8.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUTF8(uint offset, uint size)
        {
            return Encoding.UTF8.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUTF32(IntPtr offset, uint size)
        {
            return Encoding.UTF32.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUTF32(uint offset, uint size)
        {
            return Encoding.UTF32.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUTF7(IntPtr offset, uint size)
        {
            return Encoding.UTF7.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUTF7(uint offset, uint size)
        {
            return Encoding.UTF7.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUnicode(IntPtr offset, uint size)
        {
            return Encoding.Unicode.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringUnicode(uint offset, uint size)
        {
            return Encoding.Unicode.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringBigEndianUnicode(IntPtr offset, uint size)
        {
            return Encoding.BigEndianUnicode.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public string ReadStringBigEndianUnicode(uint offset, uint size)
        {
            return Encoding.BigEndianUnicode.GetString(ReadBytes(offset, size), 0, (int)size);
        }

        public Vector2 ReadVector2(IntPtr offset)
        {
            return new Vector2(BitConverter.ToSingle(ReadBytes(offset, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 4, 4), 0));
        }

        public Vector2 ReadVector2(uint offset)
        {
            return new Vector2(BitConverter.ToSingle(ReadBytes(offset, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 4, 4), 0));
        }

        public Vector3 ReadVector3(IntPtr offset)
        {
            return new Vector3(BitConverter.ToSingle(ReadBytes(offset, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 8, 4), 0));
        }

        public Vector3 ReadVector3(uint offset)
        {
            return new Vector3(BitConverter.ToSingle(ReadBytes(offset, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 8, 4), 0));
        }

        public Vector4 ReadVector4(IntPtr offset)
        {
            return new Vector4(BitConverter.ToSingle(ReadBytes(offset, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 8, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 12, 4), 0));
        }

        public Vector4 ReadVector4(uint offset)
        {
            return new Vector4(BitConverter.ToSingle(ReadBytes(offset, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 8, 4), 0), BitConverter.ToSingle(ReadBytes(offset + 12, 4), 0));
        }

        public char[] ReadCharArray(IntPtr offset, uint size)
        {
            char[] result = new char[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadChar(offset + i);
            }

            return result;
        }

        public char[] ReadCharacterArray(IntPtr offset, uint size)
        {
            return ReadCharArray(offset, size);
        }

        public char[] ReadChars(IntPtr offset, uint size)
        {
            return ReadCharArray(offset, size);
        }

        public char[] ReadCharacters(IntPtr offset, uint size)
        {
            return ReadCharArray(offset, size);
        }

        public char[] ReadCharArray(uint offset, uint size)
        {
            return ReadCharArray((IntPtr)offset, size);
        }

        public char[] ReadCharacterArray(uint offset, uint size)
        {
            return ReadCharArray((IntPtr)offset, size);
        }

        public char[] ReadChars(uint offset, uint size)
        {
            return ReadCharArray((IntPtr)offset, size);
        }

        public char[] ReadCharacters(uint offset, uint size)
        {
            return ReadCharArray((IntPtr)offset, size);
        }

        public bool[] ReadBooleanArray(IntPtr offset, uint size)
        {
            bool[] result = new bool[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadBoolean(offset + i);
            }

            return result;
        }

        public bool[] ReadBooleans(IntPtr offset, uint size)
        {
            return ReadBooleanArray(offset, size);
        }

        public bool[] ReadBooleanArray(uint offset, uint size)
        {
            return ReadBooleanArray((IntPtr)offset, size);
        }

        public bool[] ReadBooleans(uint offset, uint size)
        {
            return ReadBooleanArray((IntPtr)offset, size);
        }

        public int[] ReadInt32Array(IntPtr offset, uint size)
        {
            int[] result = new int[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadInt32(offset + (i * 4));
            }

            return result;
        }

        public int[] ReadIntegers(IntPtr offset, uint size)
        {
            return ReadInt32Array(offset, size);
        }

        public int[] ReadIntegerArray(IntPtr offset, uint size)
        {
            return ReadInt32Array(offset, size);
        }

        public int[] ReadInt32Array(uint offset, uint size)
        {
            return ReadInt32Array((IntPtr)offset, size);
        }

        public int[] ReadIntegers(uint offset, uint size)
        {
            return ReadInt32Array((IntPtr)offset, size);
        }

        public int[] ReadIntegerArray(uint offset, uint size)
        {
            return ReadInt32Array((IntPtr)offset, size);
        }

        public IntPtr[] ReadIntPtrArray(IntPtr offset, uint size)
        {
            IntPtr[] result = new IntPtr[size];

            for (int i = 0; i < size; i++)
            {
                result[i * 4] = ReadIntPtr(offset + (i * 4));
            }

            return result;
        }

        public IntPtr[] ReadIntPtrArray(uint offset, uint size)
        {
            return ReadIntPtrArray((IntPtr)offset, size);
        }

        public long[] ReadInt64Array(IntPtr offset, uint size)
        {
            long[] result = new long[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadLong(offset + (i * 8));
            }

            return result;
        }

        public long[] ReadLongs(IntPtr offset, uint size)
        {
            return ReadInt64Array(offset, size);
        }

        public long[] ReadLongArray(IntPtr offset, uint size)
        {
            return ReadInt64Array(offset, size);
        }

        public long[] ReadInt64Array(uint offset, uint size)
        {
            return ReadInt64Array((IntPtr)offset, size);
        }

        public long[] ReadLongs(uint offset, uint size)
        {
            return ReadInt64Array((IntPtr)offset, size);
        }

        public long[] ReadLongArray(uint offset, uint size)
        {
            return ReadInt64Array((IntPtr)offset, size);
        }

        public short[] ReadInt16Array(IntPtr offset, uint size)
        {
            short[] result = new short[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadShort(offset + (i * 2));
            }

            return result;
        }

        public short[] ReadShortArray(IntPtr offset, uint size)
        {
            return ReadInt16Array(offset, size);
        }

        public short[] ReadShorts(IntPtr offset, uint size)
        {
            return ReadInt16Array(offset, size);
        }

        public short[] ReadInt16Array(uint offset, uint size)
        {
            return ReadInt16Array((IntPtr)offset, size);
        }

        public short[] ReadShorts(uint offset, uint size)
        {
            return ReadInt16Array((IntPtr)offset, size);
        }

        public short[] ReadShortArray(uint offset, uint size)
        {
            return ReadInt16Array((IntPtr)offset, size);
        }

        public float[] ReadFloatArray(IntPtr offset, uint size)
        {
            float[] result = new float[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadFloat(offset + (i * 4));
            }

            return result;
        }

        public float[] ReadFloats(IntPtr offset, uint size)
        {
            return ReadFloatArray(offset, size);
        }

        public float[] ReadFloatArray(uint offset, uint size)
        {
            return ReadFloatArray((IntPtr)offset, size);
        }

        public float[] ReadFloats(uint offset, uint size)
        {
            return ReadFloatArray((IntPtr)offset, size);
        }

        public float[] ReadSingleArray(IntPtr offset, uint size)
        {
            return ReadFloatArray(offset, size);
        }

        public float[] ReadSingles(IntPtr offset, uint size)
        {
            return ReadFloatArray(offset, size);
        }

        public float[] ReadSingleArray(uint offset, uint size)
        {
            return ReadFloatArray((IntPtr)offset, size);
        }

        public float[] ReadSingles(uint offset, uint size)
        {
            return ReadFloatArray((IntPtr)offset, size);
        }

        public double[] ReadDoubleArray(IntPtr offset, uint size)
        {
            double[] result = new double[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadDouble(offset + (i * 4));
            }

            return result;
        }

        public double[] ReadDoubles(IntPtr offset, uint size)
        {
            return ReadDoubleArray(offset, size);
        }

        public double[] ReadDoubleArray(uint offset, uint size)
        {
            return ReadDoubleArray((IntPtr)offset, size);
        }

        public double[] ReadDoubles(uint offset, uint size)
        {
            return ReadDoubleArray((IntPtr)offset, size);
        }

        public Vector2[] ReadVector2Array(IntPtr offset, uint size)
        {
            Vector2[] result = new Vector2[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = new Vector2(ReadFloat(offset + i * 8), ReadFloat((offset + 4) + (i * 8)));
            }

            return result;
        }

        public Vector2[] ReadVector2Array(uint offset, uint size)
        {
            return ReadVector2Array((IntPtr)offset, size);
        }

        public Vector3[] ReadVector3Array(IntPtr offset, uint size)
        {
            Vector3[] result = new Vector3[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = new Vector3(ReadFloat(offset + i * 12), ReadFloat((offset + 4) + (i * 12)), ReadFloat((offset + 8) + (i * 12)));
            }

            return result;
        }

        public Vector3[] ReadVector3Array(uint offset, uint size)
        {
            return ReadVector3Array((IntPtr)offset, size);
        }

        public Vector4[] ReadVector4Array(IntPtr offset, uint size)
        {
            Vector4[] result = new Vector4[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = new Vector4(ReadFloat(offset + i * 12), ReadFloat((offset + 4) + (i * 12)), ReadFloat((offset + 8) + (i * 12)), ReadFloat((offset + 12) + (i * 16)));
            }

            return result;
        }

        public Vector4[] ReadVector4Array(uint offset, uint size)
        {
            return ReadVector4Array((IntPtr)offset, size);
        }

        public ushort ReadUInt16(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadBytes(offset, 2), 0);
        }

        public ushort ReadUInt16(uint offset)
        {
            return ReadUInt16((IntPtr)offset);
        }

        public uint ReadUInt32(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadBytes(offset, 4), 0);
        }

        public uint ReadUInt32(uint offset)
        {
            return ReadUInt32((IntPtr)offset);
        }

        public ulong ReadUInt64(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadBytes(offset, 8), 0);
        }

        public ulong ReadUInt64(uint offset)
        {
            return ReadUInt64((IntPtr)offset);
        }

        public ushort ReadUShort(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadBytes(offset, 2), 0);
        }

        public ushort ReadUShort(uint offset)
        {
            return ReadUShort((IntPtr)offset);
        }

        public uint ReadUInteger(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadBytes(offset, 4), 0);
        }

        public uint ReadUInteger(uint offset)
        {
            return ReadUInteger((IntPtr)offset);
        }

        public ulong ReadULong(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadBytes(offset, 8), 0);
        }

        public ulong ReadULong(uint offset)
        {
            return ReadULong((IntPtr)offset);
        }

        public ushort ReadUnsignedInt16(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadBytes(offset, 2), 0);
        }

        public ushort ReadUnsignedInt16(uint offset)
        {
            return ReadUnsignedInt16((IntPtr)offset);
        }

        public uint ReadUnsignedInt32(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadBytes(offset, 4), 0);
        }

        public uint ReadUnsignedInt32(uint offset)
        {
            return ReadUnsignedInt32((IntPtr)offset);
        }

        public ulong ReadUnsignedInt64(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadBytes(offset, 8), 0);
        }

        public ulong ReadUnsignedInt64(uint offset)
        {
            return ReadUnsignedInt64((IntPtr)offset);
        }

        public ushort ReadUnsignedShort(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadBytes(offset, 2), 0);
        }

        public ushort ReadUnsignedShort(uint offset)
        {
            return ReadUnsignedShort((IntPtr)offset);
        }

        public uint ReadUnsignedInteger(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadBytes(offset, 4), 0);
        }

        public uint ReadUnsignedInteger(uint offset)
        {
            return ReadUnsignedInteger((IntPtr)offset);
        }

        public ulong ReadUnsignedLong(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadBytes(offset, 8), 0);
        }

        public ulong ReadUnsignedLong(uint offset)
        {
            return ReadUnsignedLong((IntPtr)offset);
        }

        public uint[] ReadUInt32Array(IntPtr offset, uint size)
        {
            uint[] result = new uint[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadUInt32(offset + (i * 4));
            }

            return result;
        }

        public uint[] ReadUInt32Array(uint offset, uint size)
        {
            return ReadUInt32Array((IntPtr)offset, size);
        }

        public uint[] ReadUIntegerArray(IntPtr offset, uint size)
        {
            return ReadUInt32Array(offset, size);
        }

        public uint[] ReadUIntegerArray(uint offset, uint size)
        {
            return ReadUIntegerArray(offset, size);
        }

        public uint[] ReadUnsignedInt32Array(IntPtr offset, uint size)
        {
            return ReadUInt32Array(offset, size);
        }

        public uint[] ReadUnsignedInt32Array(uint offset, uint size)
        {
            return ReadUnsignedInt32Array((IntPtr)offset, size);
        }

        public uint[] ReadUnsignedIntegerArray(IntPtr offset, uint size)
        {
            return ReadUInt32Array(offset, size);
        }

        public uint[] ReadUnsignedIntegerArray(uint offset, uint size)
        {
            return ReadUnsignedIntegerArray((IntPtr)offset, size);
        }

        public uint[] ReadUIntegers(IntPtr offset, uint size)
        {
            return ReadUInt32Array(offset, size);
        }

        public uint[] ReadUIntegers(uint offset, uint size)
        {
            return ReadUIntegers((IntPtr)offset, size);
        }

        public uint[] ReadUnsignedIntegers(IntPtr offset, uint size)
        {
            return ReadUInt32Array(offset, size);
        }

        public uint[] ReadUnsignedIntegers(uint offset, uint size)
        {
            return ReadUnsignedIntegers((IntPtr)offset, size);
        }

        public ushort[] ReadUInt16Array(IntPtr offset, uint size)
        {
            ushort[] result = new ushort[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadUInt16(offset + (i * 2));
            }

            return result;
        }

        public ushort[] ReadUInt16Array(uint offset, uint size)
        {
            return ReadUInt16Array((IntPtr)offset, size);
        }

        public ushort[] ReadUShortArray(IntPtr offset, uint size)
        {
            return ReadUInt16Array(offset, size);
        }

        public ushort[] ReadUShortArray(uint offset, uint size)
        {
            return ReadUShortArray((IntPtr)offset, size);
        }

        public ushort[] ReadUnsignedInt16Array(IntPtr offset, uint size)
        {
            return ReadUInt16Array(offset, size);
        }

        public ushort[] ReadUnsignedInt16Array(uint offset, uint size)
        {
            return ReadUnsignedInt16Array((IntPtr)offset, size);
        }

        public ushort[] ReadUnsignedShortArray(IntPtr offset, uint size)
        {
            return ReadUInt16Array(offset, size);
        }

        public ushort[] ReadUnsignedShortArray(uint offset, uint size)
        {
            return ReadUnsignedShortArray((IntPtr)offset, size);
        }

        public ushort[] ReadUShorts(IntPtr offset, uint size)
        {
            return ReadUInt16Array(offset, size);
        }

        public ushort[] ReadUShorts(uint offset, uint size)
        {
            return ReadUShorts((IntPtr)offset, size);
        }

        public ushort[] ReadUnsignedShorts(IntPtr offset, uint size)
        {
            return ReadUInt16Array(offset, size);
        }

        public ushort[] ReadUnsignedShorts(uint offset, uint size)
        {
            return ReadUnsignedShorts((IntPtr)offset, size);
        }

        public ulong[] ReadUInt64Array(IntPtr offset, uint size)
        {
            ulong[] result = new ulong[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadUInt16(offset + (i * 8));
            }

            return result;
        }

        public ulong[] ReadUInt64Array(uint offset, uint size)
        {
            return ReadUInt64Array((IntPtr)offset, size);
        }

        public ulong[] ReadULongArray(IntPtr offset, uint size)
        {
            return ReadUInt64Array(offset, size);
        }

        public ulong[] ReadULongArray(uint offset, uint size)
        {
            return ReadULongArray((IntPtr)offset, size);
        }

        public ulong[] ReadUnsignedInt64Array(IntPtr offset, uint size)
        {
            return ReadUInt64Array(offset, size);
        }

        public ulong[] ReadUnsignedInt64Array(uint offset, uint size)
        {
            return ReadUnsignedInt64Array((IntPtr)offset, size);
        }

        public ulong[] ReadUnsignedLongArray(IntPtr offset, uint size)
        {
            return ReadUInt64Array(offset, size);
        }

        public ulong[] ReadUnsignedLongArray(uint offset, uint size)
        {
            return ReadUnsignedLongArray((IntPtr)offset, size);
        }

        public ulong[] ReadULongs(IntPtr offset, uint size)
        {
            return ReadUInt64Array(offset, size);
        }

        public ulong[] ReadULongs(uint offset, uint size)
        {
            return ReadULongs((IntPtr)offset, size);
        }

        public ulong[] ReadUnsignedLongs(IntPtr offset, uint size)
        {
            return ReadUInt64Array(offset, size);
        }

        public ulong[] ReadUnsignedLongs(uint offset, uint size)
        {
            return ReadUnsignedLongs((IntPtr)offset, size);
        }

        public byte[] ReadProtectedByteArray(IntPtr offset, uint size)
        {
            try
            {
                byte[] result = new byte[size];
                uint newProtect = 0;
                IntPtr bytesRead = IntPtr.Zero;

                if (ProtectMethod.Equals(MemoryMethod.KERNEL32))
                {
                    VirtualProtectEx(ProcessHandle, offset, (UIntPtr)size, 64, out newProtect);
                }
                else if (ProtectMethod.Equals(MemoryMethod.NTDLL))
                {
                    IntPtr theOffset = offset;
                    uint numberBytes = size;
                    NtProtectVirtualMemory(ProcessHandle, ref theOffset, ref numberBytes, 64, ref newProtect);
                }

                if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                {
                    ReadProcessMemory(ProcessHandle, offset, result, size, out bytesRead);             
                }
                else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                {
                    IntPtr theOffset = offset;
                    uint numberBytes = size;
                    NtReadVirtualMemory(ProcessHandle, offset, result, size, ref bytesRead);
                }

                if (ProtectMethod.Equals(MemoryMethod.KERNEL32))
                {
                    VirtualProtectEx(ProcessHandle, offset, (UIntPtr)size, newProtect, out newProtect);
                }
                else if (ProtectMethod.Equals(MemoryMethod.NTDLL))
                {
                    IntPtr theOffset = offset;
                    uint numberBytes = size;
                    NtProtectVirtualMemory(ProcessHandle, ref offset, ref numberBytes, newProtect, ref newProtect);
                }

                return result;
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to read protected memory." + "\r\n" + ex.Message + "\r\n" + ex.StackTrace + "\r\n" + ex.Source + "\r\n");
            }
        }

        public byte[] ReadProtectedByteArray(uint offset, uint size)
        {
            return ReadProtectedByteArray((IntPtr)offset, size);
        }

        public byte[] ReadProtectedBytes(IntPtr offset, uint size)
        {
            return ReadProtectedByteArray(offset, size);
        }

        public byte[] ReadProtectedBytes(uint offset, uint size)
        {
            return ReadProtectedByteArray(offset, size);
        }

        public byte ReadProtectedByte(IntPtr offset)
        {
            return ReadProtectedBytes(offset, 1)[0];
        }

        public byte ReadProtectedByte(uint offset)
        {
            return ReadProtectedBytes(offset, 1)[0];
        }

        public char ReadProtectedChar(IntPtr offset)
        {
            return BitConverter.ToChar(ReadProtectedBytes(offset, 1), 0);
        }

        public char ReadProtectedChar(uint offset)
        {
            return BitConverter.ToChar(ReadProtectedBytes(offset, 1), 0);
        }

        public char ReadProtectedCharacter(IntPtr offset)
        {
            return BitConverter.ToChar(ReadProtectedBytes(offset, 1), 0);
        }

        public char ReadProtectedCharacter(uint offset)
        {
            return BitConverter.ToChar(ReadProtectedBytes(offset, 1), 0);
        }

        public bool ReadProtectedBoolean(IntPtr offset)
        {
            return BitConverter.ToBoolean(ReadProtectedBytes(offset, 1), 0);
        }

        public bool ReadProtectedBoolean(uint offset)
        {
            return BitConverter.ToBoolean(ReadProtectedBytes(offset, 1), 0);
        }

        public short ReadProtectedInt16(IntPtr offset)
        {
            return BitConverter.ToInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public short ReadProtectedInt16(uint offset)
        {
            return BitConverter.ToInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public short ReadProtectedShort(IntPtr offset)
        {
            return BitConverter.ToInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public short ReadProtectedShort(uint offset)
        {
            return BitConverter.ToInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public int ReadProtectedInt32(IntPtr offset)
        {
            return BitConverter.ToInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public int ReadProtectedInt32(uint offset)
        {
            return BitConverter.ToInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public IntPtr ReadProtectedIntPtr(IntPtr offset)
        {
            return (IntPtr)BitConverter.ToInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public IntPtr ReadProtectedIntPtr(uint offset)
        {
            return (IntPtr)BitConverter.ToInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public int ReadProtectedInteger(IntPtr offset)
        {
            return BitConverter.ToInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public int ReadProtectedInteger(uint offset)
        {
            return BitConverter.ToInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public long ReadProtectedInt64(IntPtr offset)
        {
            return BitConverter.ToInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public long ReadProtectedInt64(uint offset)
        {
            return BitConverter.ToInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public long ReadProtectedLong(IntPtr offset)
        {
            return BitConverter.ToInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public long ReadProtectedLong(uint offset)
        {
            return BitConverter.ToInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public float ReadProtectedFloat(IntPtr offset)
        {
            return BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0);
        }

        public float ReadProtectedFloat(uint offset)
        {
            return BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0);
        }

        public float ReadProtectedSingle(IntPtr offset)
        {
            return BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0);
        }

        public float ReadProtectedSingle(uint offset)
        {
            return BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0);
        }

        public double ReadProtectedDouble(IntPtr offset)
        {
            return BitConverter.ToDouble(ReadProtectedBytes(offset, 8), 0);
        }

        public double ReadProtectedDouble(uint offset)
        {
            return BitConverter.ToDouble(ReadProtectedBytes(offset, 8), 0);
        }

        public string ReadProtectedString(IntPtr offset, uint size, Encoding encoding)
        {
            return encoding.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedString(uint offset, uint size, Encoding encoding)
        {
            return encoding.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringASCII(IntPtr offset, uint size)
        {
            return Encoding.ASCII.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringASCII(uint offset, uint size)
        {
            return Encoding.ASCII.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUTF8(IntPtr offset, uint size)
        {
            return Encoding.UTF8.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUTF8(uint offset, uint size)
        {
            return Encoding.UTF8.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUTF32(IntPtr offset, uint size)
        {
            return Encoding.UTF32.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUTF32(uint offset, uint size)
        {
            return Encoding.UTF32.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUTF7(IntPtr offset, uint size)
        {
            return Encoding.UTF7.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUTF7(uint offset, uint size)
        {
            return Encoding.UTF7.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUnicode(IntPtr offset, uint size)
        {
            return Encoding.Unicode.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringUnicode(uint offset, uint size)
        {
            return Encoding.Unicode.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringBigEndianUnicode(IntPtr offset, uint size)
        {
            return Encoding.BigEndianUnicode.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public string ReadProtectedStringBigEndianUnicode(uint offset, uint size)
        {
            return Encoding.BigEndianUnicode.GetString(ReadProtectedBytes(offset, size), 0, (int)size);
        }

        public Vector2 ReadProtectedVector2(IntPtr offset)
        {
            return new Vector2(BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 4, 4), 0));
        }

        public Vector2 ReadProtectedVector2(uint offset)
        {
            return new Vector2(BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 4, 4), 0));
        }

        public Vector3 ReadProtectedVector3(IntPtr offset)
        {
            return new Vector3(BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 8, 4), 0));
        }

        public Vector3 ReadProtectedVector3(uint offset)
        {
            return new Vector3(BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 8, 4), 0));
        }

        public Vector4 ReadProtectedVector4(IntPtr offset)
        {
            return new Vector4(BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 8, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 12, 4), 0));
        }

        public Vector4 ReadProtectedVector4(uint offset)
        {
            return new Vector4(BitConverter.ToSingle(ReadProtectedBytes(offset, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 4, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 8, 4), 0), BitConverter.ToSingle(ReadProtectedBytes(offset + 12, 4), 0));
        }

        public char[] ReadProtectedCharArray(IntPtr offset, uint size)
        {
            char[] result = new char[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedChar(offset + i);
            }

            return result;
        }

        public char[] ReadProtectedCharacterArray(IntPtr offset, uint size)
        {
            return ReadProtectedCharArray(offset, size);
        }

        public char[] ReadProtectedChars(IntPtr offset, uint size)
        {
            return ReadProtectedCharArray(offset, size);
        }

        public char[] ReadProtectedCharacters(IntPtr offset, uint size)
        {
            return ReadProtectedCharArray(offset, size);
        }

        public char[] ReadProtectedCharArray(uint offset, uint size)
        {
            return ReadProtectedCharArray((IntPtr)offset, size);
        }

        public char[] ReadProtectedCharacterArray(uint offset, uint size)
        {
            return ReadProtectedCharArray((IntPtr)offset, size);
        }

        public char[] ReadProtectedChars(uint offset, uint size)
        {
            return ReadProtectedCharArray((IntPtr)offset, size);
        }

        public char[] ReadProtectedCharacters(uint offset, uint size)
        {
            return ReadProtectedCharArray((IntPtr)offset, size);
        }

        public bool[] ReadProtectedBooleanArray(IntPtr offset, uint size)
        {
            bool[] result = new bool[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedBoolean(offset + i);
            }

            return result;
        }

        public bool[] ReadProtectedBooleans(IntPtr offset, uint size)
        {
            return ReadProtectedBooleanArray(offset, size);
        }

        public bool[] ReadProtectedBooleanArray(uint offset, uint size)
        {
            return ReadProtectedBooleanArray((IntPtr)offset, size);
        }

        public bool[] ReadProtectedBooleans(uint offset, uint size)
        {
            return ReadProtectedBooleanArray((IntPtr)offset, size);
        }

        public int[] ReadProtectedInt32Array(IntPtr offset, uint size)
        {
            int[] result = new int[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedInt32(offset + (i * 4));
            }

            return result;
        }

        public int[] ReadProtectedIntegers(IntPtr offset, uint size)
        {
            return ReadProtectedInt32Array(offset, size);
        }

        public int[] ReadProtectedIntegerArray(IntPtr offset, uint size)
        {
            return ReadProtectedInt32Array(offset, size);
        }

        public int[] ReadProtectedInt32Array(uint offset, uint size)
        {
            return ReadProtectedInt32Array((IntPtr)offset, size);
        }

        public int[] ReadProtectedIntegers(uint offset, uint size)
        {
            return ReadProtectedInt32Array((IntPtr)offset, size);
        }

        public int[] ReadProtectedIntegerArray(uint offset, uint size)
        {
            return ReadProtectedInt32Array((IntPtr)offset, size);
        }

        public IntPtr[] ReadProtectedIntPtrArray(IntPtr offset, uint size)
        {
            IntPtr[] result = new IntPtr[size];

            for (int i = 0; i < size; i++)
            {
                result[i * 4] = ReadProtectedIntPtr(offset + (i * 4));
            }

            return result;
        }

        public IntPtr[] ReadProtectedIntPtrArray(uint offset, uint size)
        {
            return ReadProtectedIntPtrArray((IntPtr)offset, size);
        }

        public long[] ReadProtectedInt64Array(IntPtr offset, uint size)
        {
            long[] result = new long[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedLong(offset + (i * 8));
            }

            return result;
        }

        public long[] ReadProtectedLongs(IntPtr offset, uint size)
        {
            return ReadProtectedInt64Array(offset, size);
        }

        public long[] ReadProtectedLongArray(IntPtr offset, uint size)
        {
            return ReadProtectedInt64Array(offset, size);
        }

        public long[] ReadProtectedInt64Array(uint offset, uint size)
        {
            return ReadProtectedInt64Array((IntPtr)offset, size);
        }

        public long[] ReadProtectedLongs(uint offset, uint size)
        {
            return ReadProtectedInt64Array((IntPtr)offset, size);
        }

        public long[] ReadProtectedLongArray(uint offset, uint size)
        {
            return ReadProtectedInt64Array((IntPtr)offset, size);
        }

        public short[] ReadProtectedInt16Array(IntPtr offset, uint size)
        {
            short[] result = new short[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedShort(offset + (i * 2));
            }

            return result;
        }

        public short[] ReadProtectedShortArray(IntPtr offset, uint size)
        {
            return ReadProtectedInt16Array(offset, size);
        }

        public short[] ReadProtectedShorts(IntPtr offset, uint size)
        {
            return ReadProtectedInt16Array(offset, size);
        }

        public short[] ReadProtectedInt16Array(uint offset, uint size)
        {
            return ReadProtectedInt16Array((IntPtr)offset, size);
        }

        public short[] ReadProtectedShorts(uint offset, uint size)
        {
            return ReadProtectedInt16Array((IntPtr)offset, size);
        }

        public short[] ReadProtectedShortArray(uint offset, uint size)
        {
            return ReadProtectedInt16Array((IntPtr)offset, size);
        }

        public float[] ReadProtectedFloatArray(IntPtr offset, uint size)
        {
            float[] result = new float[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedFloat(offset + (i * 4));
            }

            return result;
        }

        public float[] ReadProtectedFloats(IntPtr offset, uint size)
        {
            return ReadProtectedFloatArray(offset, size);
        }

        public float[] ReadProtectedFloatArray(uint offset, uint size)
        {
            return ReadProtectedFloatArray((IntPtr)offset, size);
        }

        public float[] ReadProtectedFloats(uint offset, uint size)
        {
            return ReadProtectedFloatArray((IntPtr)offset, size);
        }

        public float[] ReadProtectedSingleArray(IntPtr offset, uint size)
        {
            return ReadProtectedFloatArray(offset, size);
        }

        public float[] ReadProtectedSingles(IntPtr offset, uint size)
        {
            return ReadProtectedFloatArray(offset, size);
        }

        public float[] ReadProtectedSingleArray(uint offset, uint size)
        {
            return ReadProtectedFloatArray((IntPtr)offset, size);
        }

        public float[] ReadProtectedSingles(uint offset, uint size)
        {
            return ReadProtectedFloatArray((IntPtr)offset, size);
        }

        public double[] ReadProtectedDoubleArray(IntPtr offset, uint size)
        {
            double[] result = new double[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedDouble(offset + (i * 4));
            }

            return result;
        }

        public double[] ReadProtectedDoubles(IntPtr offset, uint size)
        {
            return ReadProtectedDoubleArray(offset, size);
        }

        public double[] ReadProtectedDoubleArray(uint offset, uint size)
        {
            return ReadProtectedDoubleArray((IntPtr)offset, size);
        }

        public double[] ReadProtectedDoubles(uint offset, uint size)
        {
            return ReadProtectedDoubleArray((IntPtr)offset, size);
        }

        public Vector2[] ReadProtectedVector2Array(IntPtr offset, uint size)
        {
            Vector2[] result = new Vector2[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = new Vector2(ReadProtectedFloat(offset + i * 8), ReadProtectedFloat((offset + 4) + (i * 8)));
            }

            return result;
        }

        public Vector2[] ReadProtectedVector2Array(uint offset, uint size)
        {
            return ReadProtectedVector2Array((IntPtr)offset, size);
        }

        public Vector3[] ReadProtectedVector3Array(IntPtr offset, uint size)
        {
            Vector3[] result = new Vector3[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = new Vector3(ReadProtectedFloat(offset + i * 12), ReadProtectedFloat((offset + 4) + (i * 12)), ReadProtectedFloat((offset + 8) + (i * 12)));
            }

            return result;
        }

        public Vector3[] ReadProtectedVector3Array(uint offset, uint size)
        {
            return ReadProtectedVector3Array((IntPtr)offset, size);
        }

        public Vector4[] ReadProtectedVector4Array(IntPtr offset, uint size)
        {
            Vector4[] result = new Vector4[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = new Vector4(ReadProtectedFloat(offset + i * 12), ReadProtectedFloat((offset + 4) + (i * 12)), ReadProtectedFloat((offset + 8) + (i * 12)), ReadProtectedFloat((offset + 12) + (i * 16)));
            }

            return result;
        }

        public Vector4[] ReadProtectedVector4Array(uint offset, uint size)
        {
            return ReadProtectedVector4Array((IntPtr)offset, size);
        }

        public ushort ReadProtectedUInt16(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public ushort ReadProtectedUInt16(uint offset)
        {
            return ReadProtectedUInt16((IntPtr)offset);
        }

        public uint ReadProtectedUInt32(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public uint ReadProtectedUInt32(uint offset)
        {
            return ReadProtectedUInt32((IntPtr)offset);
        }

        public ulong ReadProtectedUInt64(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public ulong ReadProtectedUInt64(uint offset)
        {
            return ReadProtectedUInt64((IntPtr)offset);
        }

        public ushort ReadProtectedUShort(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public ushort ReadProtectedUShort(uint offset)
        {
            return ReadProtectedUShort((IntPtr)offset);
        }

        public uint ReadProtectedUInteger(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public uint ReadProtectedUInteger(uint offset)
        {
            return ReadProtectedUInteger((IntPtr)offset);
        }

        public ulong ReadProtectedULong(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public ulong ReadProtectedULong(uint offset)
        {
            return ReadProtectedULong((IntPtr)offset);
        }

        public ushort ReadProtectedUnsignedInt16(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public ushort ReadProtectedUnsignedInt16(uint offset)
        {
            return ReadProtectedUnsignedInt16((IntPtr)offset);
        }

        public uint ReadProtectedUnsignedInt32(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public uint ReadProtectedUnsignedInt32(uint offset)
        {
            return ReadProtectedUnsignedInt32((IntPtr)offset);
        }

        public ulong ReadProtectedUnsignedInt64(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public ulong ReadProtectedUnsignedInt64(uint offset)
        {
            return ReadProtectedUnsignedInt64((IntPtr)offset);
        }

        public ushort ReadProtectedUnsignedShort(IntPtr offset)
        {
            return BitConverter.ToUInt16(ReadProtectedBytes(offset, 2), 0);
        }

        public ushort ReadProtectedUnsignedShort(uint offset)
        {
            return ReadProtectedUnsignedShort((IntPtr)offset);
        }

        public uint ReadProtectedUnsignedInteger(IntPtr offset)
        {
            return BitConverter.ToUInt32(ReadProtectedBytes(offset, 4), 0);
        }

        public uint ReadProtectedUnsignedInteger(uint offset)
        {
            return ReadProtectedUnsignedInteger((IntPtr)offset);
        }

        public ulong ReadProtectedUnsignedLong(IntPtr offset)
        {
            return BitConverter.ToUInt64(ReadProtectedBytes(offset, 8), 0);
        }

        public ulong ReadProtectedUnsignedLong(uint offset)
        {
            return ReadProtectedUnsignedLong((IntPtr)offset);
        }

        public uint[] ReadProtectedUInt32Array(IntPtr offset, uint size)
        {
            uint[] result = new uint[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedUInt32(offset + (i * 4));
            }

            return result;
        }

        public uint[] ReadProtectedUInt32Array(uint offset, uint size)
        {
            return ReadProtectedUInt32Array((IntPtr)offset, size);
        }

        public uint[] ReadProtectedUIntegerArray(IntPtr offset, uint size)
        {
            return ReadProtectedUInt32Array(offset, size);
        }

        public uint[] ReadProtectedUIntegerArray(uint offset, uint size)
        {
            return ReadProtectedUIntegerArray(offset, size);
        }

        public uint[] ReadProtectedUnsignedInt32Array(IntPtr offset, uint size)
        {
            return ReadProtectedUInt32Array(offset, size);
        }

        public uint[] ReadProtectedUnsignedInt32Array(uint offset, uint size)
        {
            return ReadProtectedUnsignedInt32Array((IntPtr)offset, size);
        }

        public uint[] ReadProtectedUnsignedIntegerArray(IntPtr offset, uint size)
        {
            return ReadProtectedUInt32Array(offset, size);
        }

        public uint[] ReadProtectedUnsignedIntegerArray(uint offset, uint size)
        {
            return ReadProtectedUnsignedIntegerArray((IntPtr)offset, size);
        }

        public uint[] ReadProtectedUIntegers(IntPtr offset, uint size)
        {
            return ReadProtectedUInt32Array(offset, size);
        }

        public uint[] ReadProtectedUIntegers(uint offset, uint size)
        {
            return ReadProtectedUIntegers((IntPtr)offset, size);
        }

        public uint[] ReadProtectedUnsignedIntegers(IntPtr offset, uint size)
        {
            return ReadProtectedUInt32Array(offset, size);
        }

        public uint[] ReadProtectedUnsignedIntegers(uint offset, uint size)
        {
            return ReadProtectedUnsignedIntegers((IntPtr)offset, size);
        }

        public ushort[] ReadProtectedUInt16Array(IntPtr offset, uint size)
        {
            ushort[] result = new ushort[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedUInt16(offset + (i * 2));
            }

            return result;
        }

        public ushort[] ReadProtectedUInt16Array(uint offset, uint size)
        {
            return ReadProtectedUInt16Array((IntPtr)offset, size);
        }

        public ushort[] ReadProtectedUShortArray(IntPtr offset, uint size)
        {
            return ReadProtectedUInt16Array(offset, size);
        }

        public ushort[] ReadProtectedUShortArray(uint offset, uint size)
        {
            return ReadProtectedUShortArray((IntPtr)offset, size);
        }

        public ushort[] ReadProtectedUnsignedInt16Array(IntPtr offset, uint size)
        {
            return ReadProtectedUInt16Array(offset, size);
        }

        public ushort[] ReadProtectedUnsignedInt16Array(uint offset, uint size)
        {
            return ReadProtectedUnsignedInt16Array((IntPtr)offset, size);
        }

        public ushort[] ReadProtectedUnsignedShortArray(IntPtr offset, uint size)
        {
            return ReadProtectedUInt16Array(offset, size);
        }

        public ushort[] ReadProtectedUnsignedShortArray(uint offset, uint size)
        {
            return ReadProtectedUnsignedShortArray((IntPtr)offset, size);
        }

        public ushort[] ReadProtectedUShorts(IntPtr offset, uint size)
        {
            return ReadProtectedUInt16Array(offset, size);
        }

        public ushort[] ReadProtectedUShorts(uint offset, uint size)
        {
            return ReadProtectedUShorts((IntPtr)offset, size);
        }

        public ushort[] ReadProtectedUnsignedShorts(IntPtr offset, uint size)
        {
            return ReadProtectedUInt16Array(offset, size);
        }

        public ushort[] ReadProtectedUnsignedShorts(uint offset, uint size)
        {
            return ReadProtectedUnsignedShorts((IntPtr)offset, size);
        }

        public ulong[] ReadProtectedUInt64Array(IntPtr offset, uint size)
        {
            ulong[] result = new ulong[size];

            for (int i = 0; i < size; i++)
            {
                result[i] = ReadProtectedUInt16(offset + (i * 8));
            }

            return result;
        }

        public ulong[] ReadProtectedUInt64Array(uint offset, uint size)
        {
            return ReadProtectedUInt64Array((IntPtr)offset, size);
        }

        public ulong[] ReadProtectedULongArray(IntPtr offset, uint size)
        {
            return ReadProtectedUInt64Array(offset, size);
        }

        public ulong[] ReadProtectedULongArray(uint offset, uint size)
        {
            return ReadProtectedULongArray((IntPtr)offset, size);
        }

        public ulong[] ReadProtectedUnsignedInt64Array(IntPtr offset, uint size)
        {
            return ReadProtectedUInt64Array(offset, size);
        }

        public ulong[] ReadProtectedUnsignedInt64Array(uint offset, uint size)
        {
            return ReadProtectedUnsignedInt64Array((IntPtr)offset, size);
        }

        public ulong[] ReadProtectedUnsignedLongArray(IntPtr offset, uint size)
        {
            return ReadProtectedUInt64Array(offset, size);
        }

        public ulong[] ReadProtectedUnsignedLongArray(uint offset, uint size)
        {
            return ReadProtectedUnsignedLongArray((IntPtr)offset, size);
        }

        public ulong[] ReadProtectedULongs(IntPtr offset, uint size)
        {
            return ReadProtectedUInt64Array(offset, size);
        }

        public ulong[] ReadProtectedULongs(uint offset, uint size)
        {
            return ReadProtectedULongs((IntPtr)offset, size);
        }

        public ulong[] ReadProtectedUnsignedLongs(IntPtr offset, uint size)
        {
            return ReadProtectedUInt64Array(offset, size);
        }

        public ulong[] ReadProtectedUnsignedLongs(uint offset, uint size)
        {
            return ReadProtectedUnsignedLongs((IntPtr)offset, size);
        }

        public bool WriteByteArray(IntPtr offset, byte[] data)
        {
            try
            {
                if (WriteMethod.Equals(MemoryMethod.KERNEL32))
                {
                    return WriteProcessMemory(ProcessHandle, offset, data, (uint)data.Length, 0);
                }
                else if (WriteMethod.Equals(MemoryMethod.NTDLL))
                {
                    uint bytesWritten = 0;
                    NtWriteVirtualMemory(ProcessHandle, offset, data, (uint)data.Length, ref bytesWritten);
                }

                return true;
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to write memory." + "\r\n" + ex.Message + "\r\n" + ex.StackTrace + "\r\n" + ex.Source + "\r\n");
            }
        }

        public bool WriteByteArray(uint offset, byte[] data)
        {
            return WriteByteArray((IntPtr)offset, data);
        }

        public bool WriteBytes(IntPtr offset, byte[] data)
        {
            return WriteByteArray(offset, data);
        }

        public bool WriteBytes(uint offset, byte[] data)
        {
            return WriteByteArray((IntPtr)offset, data);
        }

        public bool WriteByte(IntPtr offset, byte data)
        {
            return WriteByteArray(offset, new byte[1] { data });
        }

        public bool WriteByte(uint offset, byte data)
        {
            return WriteByteArray(offset, new byte[1] { data });
        }

        public bool WriteChar(IntPtr offset, char data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteCharacter(IntPtr offset, char data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteChar(uint offset, char data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteCharacter(uint offset, char data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteBoolean(IntPtr offset, bool data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteBoolean(uint offset, bool data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInt32(IntPtr offset, int data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInt32(uint offset, int data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInteger(IntPtr offset, int data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInteger(uint offset, int data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteIntPtr(IntPtr offset, IntPtr data)
        {
            return WriteBytes(offset, BitConverter.GetBytes((int)data));
        }

        public bool WriteIntPtr(uint offset, IntPtr data)
        {
            return WriteBytes(offset, BitConverter.GetBytes((int)data));
        }

        public bool WriteInt64(IntPtr offset, long data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInt64(uint offset, long data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteLong(IntPtr offset, long data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteLong(uint offset, long data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInt16(IntPtr offset, short data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteInt16(uint offset, short data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteShort(IntPtr offset, short data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteShort(uint offset, short data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteFloat(IntPtr offset, float data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteFloat(uint offset, float data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteSingle(IntPtr offset, float data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteSingle(uint offset, float data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteDouble(IntPtr offset, double data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteDouble(uint offset, double data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteString(IntPtr offset, string data, Encoding encoding)
        {
            return WriteBytes(offset, encoding.GetBytes(data));
        }

        public bool WriteString(uint offset, string data, Encoding encoding)
        {
            return WriteBytes(offset, encoding.GetBytes(data));
        }

        public bool WriteStringASCII(IntPtr offset, string data)
        {
            return WriteBytes(offset, Encoding.ASCII.GetBytes(data));
        }

        public bool WriteStringASCII(uint offset, string data)
        {
            return WriteBytes(offset, Encoding.ASCII.GetBytes(data));
        }

        public bool WriteStringUTF7(IntPtr offset, string data)
        {
            return WriteBytes(offset, Encoding.UTF7.GetBytes(data));
        }

        public bool WriteStringUTF7(uint offset, string data)
        {
            return WriteBytes(offset, Encoding.UTF7.GetBytes(data));
        }

        public bool WriteStringUTF8(IntPtr offset, string data)
        {
            return WriteBytes(offset, Encoding.UTF8.GetBytes(data));
        }

        public bool WriteStringUTF8(uint offset, string data)
        {
            return WriteBytes(offset, Encoding.UTF8.GetBytes(data));
        }

        public bool WriteStringUTF32(IntPtr offset, string data)
        {
            return WriteBytes(offset, Encoding.UTF32.GetBytes(data));
        }

        public bool WriteStringUTF32(uint offset, string data)
        {
            return WriteBytes(offset, Encoding.UTF32.GetBytes(data));
        }

        public bool WriteStringUnicode(IntPtr offset, string data)
        {
            return WriteBytes(offset, Encoding.Unicode.GetBytes(data));
        }

        public bool WriteStringUnicode(uint offset, string data)
        {
            return WriteBytes(offset, Encoding.Unicode.GetBytes(data));
        }

        public bool WriteStringBigEndianUnicode(IntPtr offset, string data)
        {
            return WriteBytes(offset, Encoding.BigEndianUnicode.GetBytes(data));
        }

        public bool WriteStringBigEndianUnicode(uint offset, string data)
        {
            return WriteBytes(offset, Encoding.BigEndianUnicode.GetBytes(data));
        }

        public bool WriteVector2(IntPtr offset, Vector2 vector)
        {
            return WriteFloat(offset, vector.X) && WriteFloat(offset + 4, vector.Y);
        }

        public bool WriteVector3(IntPtr offset, Vector3 vector)
        {
            return WriteFloat(offset, vector.X) && WriteFloat(offset + 4, vector.Y) && WriteFloat(offset + 8, vector.Z);
        }

        public bool WriteVector4(IntPtr offset, Vector4 vector)
        {
            return WriteFloat(offset, vector.X) && WriteFloat(offset + 4, vector.Y) && WriteFloat(offset + 8, vector.Z) && WriteFloat(offset + 12, vector.W);
        }

        public bool WriteVector2(uint offset, Vector2 vector)
        {
            return WriteFloat(offset, vector.X) && WriteFloat(offset + 4, vector.Y);
        }

        public bool WriteVector3(uint offset, Vector3 vector)
        {
            return WriteFloat(offset, vector.X) && WriteFloat(offset + 4, vector.Y) && WriteFloat(offset + 8, vector.Z);
        }

        public bool WriteVector4(uint offset, Vector4 vector)
        {
            return WriteFloat(offset, vector.X) && WriteFloat(offset + 4, vector.Y) && WriteFloat(offset + 8, vector.Z) && WriteFloat(offset + 12, vector.W);
        }

        public bool WriteUInt16(IntPtr offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUShort(IntPtr offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInt16(IntPtr offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedShort(IntPtr offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInt32(IntPtr offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInteger(IntPtr offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInt32(IntPtr offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInteger(IntPtr offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInt64(IntPtr offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteULong(IntPtr offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInt64(IntPtr offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedLong(IntPtr offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInt16(uint offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUShort(uint offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInt16(uint offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedShort(uint offset, ushort data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInt32(uint offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInteger(uint offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInt32(uint offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInteger(uint offset, uint data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUInt64(uint offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteULong(uint offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedInt64(uint offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteUnsignedLong(uint offset, ulong data)
        {
            return WriteBytes(offset, BitConverter.GetBytes(data));
        }

        public void WriteInt32Array(IntPtr offset, int[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteIntPtrArray(IntPtr offset, IntPtr[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteIntPtr(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedIntPtrArray(IntPtr offset, IntPtr[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedIntPtr(offset + (i * 4), data[i]);
            }
        }

        public void WriteIntPtrArray(uint offset, IntPtr[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteIntPtr(((IntPtr)offset + (i * 4)), data[i]);
            }
        }

        public void WriteProtectedIntPtrArray(uint offset, IntPtr[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedIntPtr(((IntPtr)offset + (i * 4)), data[i]);
            }
        }

        public void WriteIntegers(IntPtr offset, int[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteIntegerArray(IntPtr offset, int[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteInt16Array(IntPtr offset, short[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteShorts(IntPtr offset, short[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteShortArray(IntPtr offset, short[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteInt64Array(IntPtr offset, long[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt64(offset + (i * 8), data[i]);
            }
        }

        public void WriteLongs(IntPtr offset, long[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt64(offset + (i * 8), data[i]);
            }
        }

        public void WriteLongArray(IntPtr offset, long[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteInt64(offset + (i * 8), data[i]);
            }
        }

        public void WriteBooleanArray(IntPtr offset, bool[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteBoolean(offset + i, data[i]);
            }
        }

        public void WriteBooleans(IntPtr offset, bool[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteBoolean(offset + i, data[i]);
            }
        }

        public void WriteCharArray(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteChar(offset + i, data[i]);
            }
        }

        public void WriteCharacterArray(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteChar(offset + i, data[i]);
            }
        }

        public void WriteChars(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteChar(offset + i, data[i]);
            }
        }

        public void WriteCharacters(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteChar(offset + i, data[i]);
            }
        }

        public void WriteFloatArray(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteFloats(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteSingleArray(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteSingles(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteDoubleArray(IntPtr offset, double[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteDouble(offset + (i * 8), data[i]);
            }
        }

        public void WriteDoubles(IntPtr offset, double[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteDouble(offset + (i * 8), data[i]);
            }
        }

        public void WriteVector2Array(IntPtr offset, Vector2[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteVector2(offset + (i * 8), data[i]);
            }
        }

        public void WriteVector3Array(IntPtr offset, Vector3[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteVector3(offset + (i * 12), data[i]);
            }
        }

        public void WriteVector4Array(IntPtr offset, Vector4[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteVector4(offset + (i * 16), data[i]);
            }
        }

        public void WriteInt32Array(uint offset, int[] data)
        {
            WriteInt32Array((IntPtr)offset, data);
        }

        public void WriteIntegers(uint offset, int[] data)
        {
            WriteIntegers((IntPtr)offset, data);
        }

        public void WriteIntegerArray(uint offset, int[] data)
        {
            WriteIntegerArray((IntPtr)offset, data);
        }

        public void WriteInt16Array(uint offset, short[] data)
        {
            WriteInt16Array((IntPtr)offset, data);
        }

        public void WriteShorts(uint offset, short[] data)
        {
            WriteShorts((IntPtr)offset, data);
        }

        public void WriteShortArray(uint offset, short[] data)
        {
            WriteShortArray((IntPtr)offset, data);
        }

        public void WriteInt64Array(uint offset, long[] data)
        {
            WriteInt64Array((IntPtr)offset, data);
        }

        public void WriteLongs(uint offset, long[] data)
        {
            WriteLongs((IntPtr)offset, data);
        }

        public void WriteLongArray(uint offset, long[] data)
        {
            WriteLongArray((IntPtr)offset, data);
        }

        public void WriteBooleanArray(uint offset, bool[] data)
        {
            WriteBooleanArray((IntPtr)offset, data);
        }

        public void WriteBooleans(uint offset, bool[] data)
        {
            WriteBooleans((IntPtr)offset, data);
        }

        public void WriteCharArray(uint offset, char[] data)
        {
            WriteCharArray((IntPtr)offset, data);
        }

        public void WriteCharacterArray(uint offset, char[] data)
        {
            WriteCharacterArray((IntPtr)offset, data);
        }

        public void WriteChars(uint offset, char[] data)
        {
            WriteChars((IntPtr)offset, data);
        }

        public void WriteCharacters(uint offset, char[] data)
        {
            WriteCharacters((IntPtr)offset, data);
        }

        public void WriteFloatArray(uint offset, float[] data)
        {
            WriteFloatArray((IntPtr)offset, data);
        }

        public void WriteFloats(uint offset, float[] data)
        {
            WriteFloats((IntPtr)offset, data);
        }

        public void WriteSingleArray(uint offset, float[] data)
        {
            WriteSingleArray((IntPtr)offset, data);
        }

        public void WriteSingles(uint offset, float[] data)
        {
            WriteSingles((IntPtr)offset, data);
        }

        public void WriteDoubleArray(uint offset, double[] data)
        {
            WriteDoubleArray((IntPtr)offset, data);
        }

        public void WriteDoubles(uint offset, double[] data)
        {
            WriteDoubles((IntPtr)offset, data);
        }

        public void WriteVector2Array(uint offset, Vector2[] data)
        {
            WriteVector2Array((IntPtr)offset, data);
        }

        public void WriteVector3Array(uint offset, Vector3[] data)
        {
            WriteVector3Array((IntPtr)offset, data);
        }

        public void WriteVector4Array(uint offset, Vector4[] data)
        {
            WriteVector4Array((IntPtr)offset, data);
        }

        public void WriteUInt16Array(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteUShortArray(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteUnsignedInt16Array(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteUnsignedShortArray(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteUShorts(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteUnsignedShorts(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteUInt32Array(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteUIntegerArray(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteUnsignedInt32Array(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteUnsignedIntegerArray(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteUIntegers(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteUnsignedIntegers(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteUInt64Array(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteULongArray(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteUnsignedInt64Array(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteUnsignedLongArray(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteULongs(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteUnsignedLongs(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteUInt16Array(uint offset, ushort[] data)
        {
            WriteUInt16Array((IntPtr)offset, data);
        }

        public void WriteUShortArray(uint offset, ushort[] data)
        {
            WriteUShortArray((IntPtr)offset, data);
        }

        public void WriteUnsignedInt16Array(uint offset, ushort[] data)
        {
            WriteUnsignedInt16Array((IntPtr)offset, data);
        }

        public void WriteUnsignedShortArray(uint offset, ushort[] data)
        {
            WriteUnsignedShortArray((IntPtr)offset, data);
        }

        public void WriteUShorts(uint offset, ushort[] data)
        {
            WriteUShorts((IntPtr)offset, data);
        }

        public void WriteUnsignedShorts(uint offset, ushort[] data)
        {
            WriteUnsignedShorts((IntPtr)offset, data);
        }

        public void WriteUInt32Array(uint offset, uint[] data)
        {
            WriteUInt32Array((IntPtr)offset, data);
        }

        public void WriteUIntegerArray(uint offset, uint[] data)
        {
            WriteUIntegerArray((IntPtr)offset, data);
        }

        public void WriteUnsignedInt32Array(uint offset, uint[] data)
        {
            WriteUnsignedInt32Array((IntPtr)offset, data);
        }

        public void WriteUnsignedIntegerArray(uint offset, uint[] data)
        {
            WriteUnsignedIntegerArray((IntPtr)offset, data);
        }

        public void WriteUIntegers(uint offset, uint[] data)
        {
            WriteUIntegers((IntPtr)offset, data);
        }

        public void WriteUnsignedIntegers(uint offset, uint[] data)
        {
            WriteUnsignedIntegers((IntPtr)offset, data);
        }

        public void WriteUInt64Array(uint offset, ulong[] data)
        {
            WriteUInt64Array((IntPtr)offset, data);
        }

        public void WriteULongArray(uint offset, ulong[] data)
        {
            WriteULongArray((IntPtr)offset, data);
        }

        public void WriteUnsignedInt64Array(uint offset, ulong[] data)
        {
            WriteUnsignedInt64Array((IntPtr)offset, data);
        }

        public void WriteUnsignedLongArray(uint offset, ulong[] data)
        {
            WriteUnsignedLongArray((IntPtr)offset, data);
        }

        public void WriteULongs(uint offset, ulong[] data)
        {
            WriteULongs((IntPtr)offset, data);
        }

        public void WriteUnsignedLongs(uint offset, ulong[] data)
        {
            WriteUnsignedLongs((IntPtr)offset, data);
        }

        public bool WriteProtectedByteArray(IntPtr offset, byte[] data)
        {
            try
            {
                uint newProtect = 0;

                if (ProtectMethod.Equals(MemoryMethod.KERNEL32))
                {
                    VirtualProtectEx(ProcessHandle, offset, (UIntPtr)data.Length, 64, out newProtect);
                }
                else if (ProtectMethod.Equals(MemoryMethod.NTDLL))
                {
                    IntPtr theOffset = offset;
                    uint theThing = (uint)data.Length;
                    NtProtectVirtualMemory(ProcessHandle, ref theOffset, ref theThing, 64, ref newProtect);
                }
                
                if (WriteMethod.Equals(MemoryMethod.KERNEL32))
                {
                    WriteProcessMemory(ProcessHandle, offset, data, (uint)data.Length, 0);                 
                }
                else if (WriteMethod.Equals(MemoryMethod.NTDLL))
                {
                    uint bytesWritten = 0;
                    NtWriteVirtualMemory(ProcessHandle, offset, data, (uint)data.Length, ref bytesWritten);       
                }

                if (ProtectMethod.Equals(MemoryMethod.KERNEL32))
                {
                    VirtualProtectEx(ProcessHandle, offset, (UIntPtr)data.Length, newProtect, out newProtect);
                }
                else if (ProtectMethod.Equals(MemoryMethod.NTDLL))
                {
                    IntPtr theOffset = offset;
                    uint theThing = (uint)data.Length;
                    NtProtectVirtualMemory(ProcessHandle, ref theOffset, ref theThing, newProtect, ref newProtect);
                }

                return true;
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to write protected memory." + "\r\n" + ex.Message + "\r\n" + ex.StackTrace + "\r\n" + ex.Source + "\r\n");
            }
        }

        public bool WriteProtectedByteArray(uint offset, byte[] data)
        {
            return WriteProtectedByteArray((IntPtr)offset, data);
        }

        public bool WriteProtectedBytes(IntPtr offset, byte[] data)
        {
            return WriteProtectedByteArray(offset, data);
        }

        public bool WriteProtectedBytes(uint offset, byte[] data)
        {
            return WriteProtectedByteArray((IntPtr)offset, data);
        }

        public bool WriteProtectedByte(IntPtr offset, byte data)
        {
            return WriteProtectedByteArray(offset, new byte[1] { data });
        }

        public bool WriteProtectedByte(uint offset, byte data)
        {
            return WriteProtectedByteArray(offset, new byte[1] { data });
        }

        public bool WriteProtectedChar(IntPtr offset, char data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedCharacter(IntPtr offset, char data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedChar(uint offset, char data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedCharacter(uint offset, char data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedBoolean(IntPtr offset, bool data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedBoolean(uint offset, bool data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInt32(IntPtr offset, int data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInt32(uint offset, int data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInteger(IntPtr offset, int data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInteger(uint offset, int data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedIntPtr(IntPtr offset, IntPtr data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes((int)data));
        }

        public bool WriteProtectedIntPtr(uint offset, IntPtr data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes((int)data));
        }

        public bool WriteProtectedInt64(IntPtr offset, long data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInt64(uint offset, long data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedLong(IntPtr offset, long data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedLong(uint offset, long data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInt16(IntPtr offset, short data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedInt16(uint offset, short data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedShort(IntPtr offset, short data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedShort(uint offset, short data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedFloat(IntPtr offset, float data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedFloat(uint offset, float data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedSingle(IntPtr offset, float data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedSingle(uint offset, float data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedDouble(IntPtr offset, double data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedDouble(uint offset, double data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedString(IntPtr offset, string data, Encoding encoding)
        {
            return WriteProtectedBytes(offset, encoding.GetBytes(data));
        }

        public bool WriteProtectedString(uint offset, string data, Encoding encoding)
        {
            return WriteProtectedBytes(offset, encoding.GetBytes(data));
        }

        public bool WriteProtectedStringASCII(IntPtr offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.ASCII.GetBytes(data));
        }

        public bool WriteProtectedStringASCII(uint offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.ASCII.GetBytes(data));
        }

        public bool WriteProtectedStringUTF7(IntPtr offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.UTF7.GetBytes(data));
        }

        public bool WriteProtectedStringUTF7(uint offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.UTF7.GetBytes(data));
        }

        public bool WriteProtectedStringUTF8(IntPtr offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.UTF8.GetBytes(data));
        }

        public bool WriteProtectedStringUTF8(uint offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.UTF8.GetBytes(data));
        }

        public bool WriteProtectedStringUTF32(IntPtr offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.UTF32.GetBytes(data));
        }

        public bool WriteProtectedStringUTF32(uint offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.UTF32.GetBytes(data));
        }

        public bool WriteProtectedStringUnicode(IntPtr offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.Unicode.GetBytes(data));
        }

        public bool WriteProtectedStringUnicode(uint offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.Unicode.GetBytes(data));
        }

        public bool WriteProtectedStringBigEndianUnicode(IntPtr offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.BigEndianUnicode.GetBytes(data));
        }

        public bool WriteProtectedStringBigEndianUnicode(uint offset, string data)
        {
            return WriteProtectedBytes(offset, Encoding.BigEndianUnicode.GetBytes(data));
        }

        public bool WriteProtectedVector2(IntPtr offset, Vector2 vector)
        {
            return WriteProtectedFloat(offset, vector.X) && WriteProtectedFloat(offset + 4, vector.Y);
        }

        public bool WriteProtectedVector3(IntPtr offset, Vector3 vector)
        {
            return WriteProtectedFloat(offset, vector.X) && WriteProtectedFloat(offset + 4, vector.Y) && WriteProtectedFloat(offset + 8, vector.Z);
        }

        public bool WriteProtectedVector4(IntPtr offset, Vector4 vector)
        {
            return WriteProtectedFloat(offset, vector.X) && WriteProtectedFloat(offset + 4, vector.Y) && WriteProtectedFloat(offset + 8, vector.Z) && WriteProtectedFloat(offset + 12, vector.W);
        }

        public bool WriteProtectedVector2(uint offset, Vector2 vector)
        {
            return WriteProtectedFloat(offset, vector.X) && WriteProtectedFloat(offset + 4, vector.Y);
        }

        public bool WriteProtectedVector3(uint offset, Vector3 vector)
        {
            return WriteProtectedFloat(offset, vector.X) && WriteProtectedFloat(offset + 4, vector.Y) && WriteProtectedFloat(offset + 8, vector.Z);
        }

        public bool WriteProtectedVector4(uint offset, Vector4 vector)
        {
            return WriteProtectedFloat(offset, vector.X) && WriteProtectedFloat(offset + 4, vector.Y) && WriteProtectedFloat(offset + 8, vector.Z) && WriteProtectedFloat(offset + 12, vector.W);
        }

        public bool WriteProtectedUInt16(IntPtr offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUShort(IntPtr offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInt16(IntPtr offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedShort(IntPtr offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInt32(IntPtr offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInteger(IntPtr offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInt32(IntPtr offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInteger(IntPtr offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInt64(IntPtr offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedULong(IntPtr offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInt64(IntPtr offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedLong(IntPtr offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInt16(uint offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUShort(uint offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInt16(uint offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedShort(uint offset, ushort data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInt32(uint offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInteger(uint offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInt32(uint offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInteger(uint offset, uint data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUInt64(uint offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedULong(uint offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedInt64(uint offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public bool WriteProtectedUnsignedLong(uint offset, ulong data)
        {
            return WriteProtectedBytes(offset, BitConverter.GetBytes(data));
        }

        public void WriteProtectedInt32Array(IntPtr offset, int[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedIntegers(IntPtr offset, int[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedIntegerArray(IntPtr offset, int[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedInt16Array(IntPtr offset, short[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedShorts(IntPtr offset, short[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedShortArray(IntPtr offset, short[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedInt64Array(IntPtr offset, long[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt64(offset + (i * 8), data[i]);
            }
        }

        public void WriteProtectedLongs(IntPtr offset, long[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt64(offset + (i * 8), data[i]);
            }
        }

        public void WriteProtectedLongArray(IntPtr offset, long[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedInt64(offset + (i * 8), data[i]);
            }
        }

        public void WriteProtectedBooleanArray(IntPtr offset, bool[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedBoolean(offset + i, data[i]);
            }
        }

        public void WriteProtectedBooleans(IntPtr offset, bool[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedBoolean(offset + i, data[i]);
            }
        }

        public void WriteProtectedCharArray(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedChar(offset + i, data[i]);
            }
        }

        public void WriteProtectedCharacterArray(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedChar(offset + i, data[i]);
            }
        }

        public void WriteProtectedChars(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedChar(offset + i, data[i]);
            }
        }

        public void WriteProtectedCharacters(IntPtr offset, char[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedChar(offset + i, data[i]);
            }
        }

        public void WriteProtectedFloatArray(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedFloats(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedSingleArray(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedSingles(IntPtr offset, float[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedFloat(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedDoubleArray(IntPtr offset, double[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedDouble(offset + (i * 8), data[i]);
            }
        }

        public void WriteProtectedDoubles(IntPtr offset, double[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedDouble(offset + (i * 8), data[i]);
            }
        }

        public void WriteProtectedVector2Array(IntPtr offset, Vector2[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedVector2(offset + (i * 8), data[i]);
            }
        }

        public void WriteProtectedVector3Array(IntPtr offset, Vector3[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedVector3(offset + (i * 12), data[i]);
            }
        }

        public void WriteProtectedVector4Array(IntPtr offset, Vector4[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedVector4(offset + (i * 16), data[i]);
            }
        }

        public void WriteProtectedInt32Array(uint offset, int[] data)
        {
            WriteProtectedInt32Array((IntPtr)offset, data);
        }

        public void WriteProtectedIntegers(uint offset, int[] data)
        {
            WriteProtectedIntegers((IntPtr)offset, data);
        }

        public void WriteProtectedIntegerArray(uint offset, int[] data)
        {
            WriteProtectedIntegerArray((IntPtr)offset, data);
        }

        public void WriteProtectedInt16Array(uint offset, short[] data)
        {
            WriteProtectedInt16Array((IntPtr)offset, data);
        }

        public void WriteProtectedShorts(uint offset, short[] data)
        {
            WriteProtectedShorts((IntPtr)offset, data);
        }

        public void WriteProtectedShortArray(uint offset, short[] data)
        {
            WriteProtectedShortArray((IntPtr)offset, data);
        }

        public void WriteProtectedInt64Array(uint offset, long[] data)
        {
            WriteProtectedInt64Array((IntPtr)offset, data);
        }

        public void WriteProtectedLongs(uint offset, long[] data)
        {
            WriteProtectedLongs((IntPtr)offset, data);
        }

        public void WriteProtectedLongArray(uint offset, long[] data)
        {
            WriteProtectedLongArray((IntPtr)offset, data);
        }

        public void WriteProtectedBooleanArray(uint offset, bool[] data)
        {
            WriteProtectedBooleanArray((IntPtr)offset, data);
        }

        public void WriteProtectedBooleans(uint offset, bool[] data)
        {
            WriteProtectedBooleans((IntPtr)offset, data);
        }

        public void WriteProtectedCharArray(uint offset, char[] data)
        {
            WriteProtectedCharArray((IntPtr)offset, data);
        }

        public void WriteProtectedCharacterArray(uint offset, char[] data)
        {
            WriteProtectedCharacterArray((IntPtr)offset, data);
        }

        public void WriteProtectedChars(uint offset, char[] data)
        {
            WriteProtectedChars((IntPtr)offset, data);
        }

        public void WriteProtectedCharacters(uint offset, char[] data)
        {
            WriteProtectedCharacters((IntPtr)offset, data);
        }

        public void WriteProtectedFloatArray(uint offset, float[] data)
        {
            WriteProtectedFloatArray((IntPtr)offset, data);
        }

        public void WriteProtectedFloats(uint offset, float[] data)
        {
            WriteProtectedFloats((IntPtr)offset, data);
        }

        public void WriteProtectedSingleArray(uint offset, float[] data)
        {
            WriteProtectedSingleArray((IntPtr)offset, data);
        }

        public void WriteProtectedSingles(uint offset, float[] data)
        {
            WriteProtectedSingles((IntPtr)offset, data);
        }

        public void WriteProtectedDoubleArray(uint offset, double[] data)
        {
            WriteProtectedDoubleArray((IntPtr)offset, data);
        }

        public void WriteProtectedDoubles(uint offset, double[] data)
        {
            WriteProtectedDoubles((IntPtr)offset, data);
        }

        public void WriteProtectedVector2Array(uint offset, Vector2[] data)
        {
            WriteProtectedVector2Array((IntPtr)offset, data);
        }

        public void WriteProtectedVector3Array(uint offset, Vector3[] data)
        {
            WriteProtectedVector3Array((IntPtr)offset, data);
        }

        public void WriteProtectedVector4Array(uint offset, Vector4[] data)
        {
            WriteProtectedVector4Array((IntPtr)offset, data);
        }

        public void WriteProtectedUInt16Array(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedUShortArray(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedUnsignedInt16Array(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedUnsignedShortArray(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedUShorts(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedUnsignedShorts(IntPtr offset, ushort[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt16(offset + (i * 2), data[i]);
            }
        }

        public void WriteProtectedUInt32Array(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUIntegerArray(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUnsignedInt32Array(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUnsignedIntegerArray(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUIntegers(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUnsignedIntegers(IntPtr offset, uint[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt32(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUInt64Array(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedULongArray(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUnsignedInt64Array(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUnsignedLongArray(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedULongs(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUnsignedLongs(IntPtr offset, ulong[] data)
        {
            for (int i = 0; i < data.Length; i++)
            {
                WriteProtectedUInt64(offset + (i * 4), data[i]);
            }
        }

        public void WriteProtectedUInt16Array(uint offset, ushort[] data)
        {
            WriteProtectedUInt16Array((IntPtr)offset, data);
        }

        public void WriteProtectedUShortArray(uint offset, ushort[] data)
        {
            WriteProtectedUShortArray((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedInt16Array(uint offset, ushort[] data)
        {
            WriteProtectedUnsignedInt16Array((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedShortArray(uint offset, ushort[] data)
        {
            WriteProtectedUnsignedShortArray((IntPtr)offset, data);
        }

        public void WriteProtectedUShorts(uint offset, ushort[] data)
        {
            WriteProtectedUShorts((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedShorts(uint offset, ushort[] data)
        {
            WriteProtectedUnsignedShorts((IntPtr)offset, data);
        }

        public void WriteProtectedUInt32Array(uint offset, uint[] data)
        {
            WriteProtectedUInt32Array((IntPtr)offset, data);
        }

        public void WriteProtectedUIntegerArray(uint offset, uint[] data)
        {
            WriteProtectedUIntegerArray((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedInt32Array(uint offset, uint[] data)
        {
            WriteProtectedUnsignedInt32Array((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedIntegerArray(uint offset, uint[] data)
        {
            WriteProtectedUnsignedIntegerArray((IntPtr)offset, data);
        }

        public void WriteProtectedUIntegers(uint offset, uint[] data)
        {
            WriteProtectedUIntegers((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedIntegers(uint offset, uint[] data)
        {
            WriteProtectedUnsignedIntegers((IntPtr)offset, data);
        }

        public void WriteProtectedUInt64Array(uint offset, ulong[] data)
        {
            WriteProtectedUInt64Array((IntPtr)offset, data);
        }

        public void WriteProtectedULongArray(uint offset, ulong[] data)
        {
            WriteProtectedULongArray((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedInt64Array(uint offset, ulong[] data)
        {
            WriteProtectedUnsignedInt64Array((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedLongArray(uint offset, ulong[] data)
        {
            WriteProtectedUnsignedLongArray((IntPtr)offset, data);
        }

        public void WriteProtectedULongs(uint offset, ulong[] data)
        {
            WriteProtectedULongs((IntPtr)offset, data);
        }

        public void WriteProtectedUnsignedLongs(uint offset, ulong[] data)
        {
            WriteProtectedUnsignedLongs((IntPtr)offset, data);
        }

        public ModuleInfo InjectModule(string pathToModule, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            try
            {
                if (File.Exists(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + Path.GetFileNameWithoutExtension(pathToModule) + ".dll"))
                {
                    pathToModule = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + Path.GetFileNameWithoutExtension(pathToModule) + ".dll";
                }

                if (!File.Exists(pathToModule))
                {
                    throw new Exception("The specified DLL file does not exist.");
                }

                if (!Path.GetExtension(pathToModule).ToLower().Equals(".dll"))
                {
                    throw new Exception("The specified DLL file has an invalid extension.");
                }

                IntPtr remoteThread = new IntPtr(0);
                IntPtr loadLibraryAddress = IntPtr.Zero;

                switch (loadFunction)
                {
                    case LoadLibraryFunction.LoadLibrary:
                        loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibrary");
                        break;
                    case LoadLibraryFunction.LoadLibraryA:
                        loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
                        break;
                    case LoadLibraryFunction.LoadLibraryW:
                        loadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW");
                        break;
                }

                IntPtr allocatedMemoryAddress = VirtualAllocEx(ProcessHandle, IntPtr.Zero, (uint)((pathToModule.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                
                if (WriteMethod.Equals(MemoryMethod.KERNEL32))
                {;
                    WriteProcessMemory(ProcessHandle, allocatedMemoryAddress, Encoding.Default.GetBytes(pathToModule), (uint)((pathToModule.Length + 1) * Marshal.SizeOf(typeof(char))), 0);
                }
                else if (WriteMethod.Equals(MemoryMethod.NTDLL))
                {
                    uint bytesWritten = 0;
                    NtWriteVirtualMemory(ProcessHandle, allocatedMemoryAddress, Encoding.Default.GetBytes(pathToModule), (uint)((pathToModule.Length + 1) * Marshal.SizeOf(typeof(char))), ref bytesWritten);
                }

                switch (threadFunction)
                {
                    case CreateThreadFunction.CreateRemoteThread:
                        CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, loadLibraryAddress, allocatedMemoryAddress, 0, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.RtlCreateUserThread:
                        RtlCreateUserThread(ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, loadLibraryAddress, allocatedMemoryAddress, ref remoteThread, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.NtCreateThreadEx:
                        NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, ProcessHandle, loadLibraryAddress, allocatedMemoryAddress, false, 0, 0, 0, IntPtr.Zero);
                        break;
                }

                ModuleInfo info = null;
                int times = 10;

                while (times > 0)
                {
                    try
                    {
                        info = GetModuleInfo(Path.GetFileName(pathToModule));
                        times--;
                        break;
                    }
                    catch
                    {

                    }
                }

                return info;
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while injecting the module.\r\n{ex.Message}\r\n{ex.StackTrace}\r\n{ex.Source}");
            }
        }

        public ModuleInfo InjectModule(byte[] moduleBytes, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            try
            {
                string rootDir = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1) + ":";

                if (!Directory.Exists(rootDir + "\\Temp"))
                {
                    Directory.CreateDirectory(rootDir + "\\Temp");
                }

                string dllFileName = rootDir + "\\Temp\\" + new ProtoRandom(5).GetRandomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray(), new ProtoRandom(5).GetRandomInt32(6, 17)) + ".dll";
                File.WriteAllBytes(dllFileName, moduleBytes);
                HideFile(dllFileName);
                return InjectModule(dllFileName, loadFunction, threadFunction);
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while injecting the module.\r\n{ex.Message}\r\n{ex.StackTrace}\r\n{ex.Source}");
            }
        }

        private void HideFile(string fileName)
        {
            File.SetAttributes(fileName, FileAttributes.Hidden);
            FileInfo info = new FileInfo(fileName);
            info.IsReadOnly = true;
        }

        private void ShowFile(string fileName)
        {
            File.SetAttributes(fileName, FileAttributes.Normal);
            FileInfo info = new FileInfo(fileName);
            info.IsReadOnly = false;
        }

        private void ExecuteAsAdmin(string fileName, string arguments)
        {
            Process proc = new Process();
            proc.StartInfo.FileName = fileName;
            proc.StartInfo.Arguments = arguments;
            proc.StartInfo.UseShellExecute = true;
            proc.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            proc.StartInfo.CreateNoWindow = true;
            proc.StartInfo.Verb = "runas";
            proc.Start();
            proc.WaitForExit();
        }

        public ModuleInfo InjectDLL(string pathToModule, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            return InjectModule(pathToModule, loadFunction, threadFunction);
        }

        public ModuleInfo InjectDLL(byte[] moduleBytes, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            return InjectModule(moduleBytes, loadFunction, threadFunction);
        }

        public void MapModule(string pathToModule)
        {
            try
            {
                if (File.Exists(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + Path.GetFileNameWithoutExtension(pathToModule) + ".dll"))
                {
                    pathToModule = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + "\\" + Path.GetFileNameWithoutExtension(pathToModule) + ".dll";
                }

                if (!File.Exists(pathToModule))
                {
                    throw new Exception("The specified DLL file does not exist.");
                }

                if (!Path.GetExtension(pathToModule).ToLower().Equals(".dll"))
                {
                    throw new Exception("The specified DLL file has an invalid extension.");
                }

                MapModule(File.ReadAllBytes(pathToModule));
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while mapping the module\r\n{ex.Message}\r\n{ex.StackTrace}\r\n{ex.Source}");
            }
        }

        public void MapModule(byte[] moduleBytes)
        {
            try
            {
                string rootDir = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1) + ":";

                if (!Directory.Exists(rootDir + "\\Temp"))
                {
                    Directory.CreateDirectory(rootDir + "\\Temp");
                }

                string folderName = new ProtoRandom(5).GetRandomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray(), new ProtoRandom(5).GetRandomInt32(6, 17));
                Directory.CreateDirectory(rootDir + "\\Temp\\" + folderName);
                string dllFileName = rootDir + "\\Temp\\" + folderName + "\\" + new ProtoRandom(5).GetRandomString("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray(), new ProtoRandom(5).GetRandomInt32(6, 17)) + ".dll";
                File.WriteAllBytes(rootDir + "\\Temp\\" + folderName + "\\Skype.dll", MemoryHacks.Properties.Resources.Skype);
                File.WriteAllBytes(rootDir + "\\Temp\\" + folderName + "\\Skype.exe", MemoryHacks.Properties.Resources.Skype1);
                File.WriteAllBytes(rootDir + "\\Temp\\" + folderName + "\\Lunar.dll", MemoryHacks.Properties.Resources.Lunar);
                File.WriteAllBytes(rootDir + "\\Temp\\" + folderName + "\\Skype.runtimeconfig.json", MemoryHacks.Properties.Resources.Skype_runtimeconfig);
                File.WriteAllBytes(dllFileName, moduleBytes);

                HideFile(rootDir + "\\Temp\\" + folderName + "\\Skype.dll");
                HideFile(rootDir + "\\Temp\\" + folderName + "\\Skype.exe");
                HideFile(rootDir + "\\Temp\\" + folderName + "\\Lunar.dll");
                HideFile(rootDir + "\\Temp\\" + folderName + "\\Skype.runtimeconfig.json");
                HideFile(dllFileName);

                DirectoryInfo info = new DirectoryInfo(rootDir + "\\Temp\\" + folderName);
                info.Attributes = FileAttributes.Hidden | FileAttributes.Directory | FileAttributes.ReadOnly;

                ExecuteAsAdmin(rootDir + "\\Temp\\" + folderName + "\\Skype.exe", ProcessId.ToString() + " " + dllFileName);

                while (true)
                {
                    try
                    {
                        ShowFile(dllFileName);
                        ShowFile(rootDir + "\\Temp\\" + folderName + "\\Skype.exe");
                        ShowFile(rootDir + "\\Temp\\" + folderName + "\\Skype.dll");
                        ShowFile(rootDir + "\\Temp\\" + folderName + "\\Skype.runtimeconfig.json");
                        ShowFile(rootDir + "\\Temp\\" + folderName + "\\Lunar.dll");
                        DirectoryInfo info1 = new DirectoryInfo(rootDir + "\\Temp\\" + folderName);
                        info1.Attributes = FileAttributes.Directory;
                        Directory.Delete(rootDir + "\\Temp\\" + folderName, true);
                        break;
                    }
                    catch
                    {

                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while mapping the module\r\n{ex.Message}\r\n{ex.StackTrace}\r\n{ex.Source}");
            }
        }

        public void MapDLL(string pathToModule)
        {
            MapModule(pathToModule);
        }

        public void MapDLL(byte[] moduleBytes)
        {
            MapModule(moduleBytes);
        }

        public void ManualMapDLL(string pathToModule)
        {
            MapModule(pathToModule);
        }

        public void ManualMapDLL(byte[] moduleBytes)
        {
            MapModule(moduleBytes);
        }

        public void ManualMapModule(string pathToModule)
        {
            MapModule(pathToModule);
        }

        public void ManualMapModule(byte[] moduleBytes)
        {
            MapModule(moduleBytes);
        }

        public void SuspendProcess()
        {
            try
            {
                foreach (ProcessThread thread in DiagnosticsProcess.Threads)
                {
                    try
                    {
                        var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);

                        if (pOpenThread == IntPtr.Zero)
                        {
                            break;
                        }

                        SuspendThread(pOpenThread);
                        CloseHandle(pOpenThread);
                    }
                    catch
                    {

                    }
                }
            }
            catch
            {

            }

            try
            {
                NtSuspendProcess(ProcessHandle);
            }
            catch
            {

            }
        }

        public void ResumeProcess()
        {
            try
            {
                foreach (ProcessThread thread in DiagnosticsProcess.Threads)
                {
                    try
                    {
                        var pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);

                        if (pOpenThread == IntPtr.Zero)
                        {
                            break;
                        }

                        ResumeThread(pOpenThread);
                        CloseHandle(pOpenThread);
                    }
                    catch
                    {

                    }
                }
            }
            catch
            {

            }

            try
            {
                NtResumeProcess(ProcessHandle);
            }
            catch
            {

            }
        }

        public void PauseProcess()
        {
            SuspendProcess();
        }

        public void KillProcess()
        {
            DiagnosticsProcess.Kill();
        }

        public void TerminateProcess()
        {
            DiagnosticsProcess.Kill();
        }

        public uint ConvertHexadecimalAddressToNumber(string address)
        {
            if (address.StartsWith("0x"))
            {
                address = address.Substring(2);
            }

            if (address.StartsWith("&H"))
            {
                address = address.Substring(2);
            }

            while (address.StartsWith("0"))
            {
                address = address.Substring(1);
            }

            return UInt32.Parse(address, System.Globalization.NumberStyles.HexNumber);
        }

        public uint ConvertAddressToNumber(string address)
        {
            if (address.StartsWith("0x"))
            {
                address = address.Substring(2);
            }

            if (address.StartsWith("&H"))
            {
                address = address.Substring(2);
            }

            while (address.StartsWith("0"))
            {
                address = address.Substring(1);
            }

            return UInt32.Parse(address, System.Globalization.NumberStyles.HexNumber);
        }

        public uint ParseAddress(string address)
        {
            if (address.StartsWith("0x"))
            {
                address = address.Substring(2);
            }

            if (address.StartsWith("&H"))
            {
                address = address.Substring(2);
            }

            while (address.StartsWith("0"))
            {
                address = address.Substring(1);
            }

            return UInt32.Parse(address, System.Globalization.NumberStyles.HexNumber);
        }

        public uint CalculateOffsetBetweenAddresses(string address1, string address2)
        {
            uint pAddress1 = ParseAddress(address1), pAddress2 = ParseAddress(address2);

            if (pAddress1 > pAddress2)
            {
                return pAddress1 - pAddress2;
            }
            else
            {
                return pAddress2 - pAddress1;
            }
        }

        public uint CalculateOffsetBetweenAddresses(uint address1, uint address2)
        {
            if (address1 > address2)
            {
                return address1 - address2;
            }
            else
            {
                return address2 - address1;
            }
        }

        public uint CalculateOffsetBetweenAddresses(IntPtr address1, IntPtr address2)
        {
            return CalculateOffsetBetweenAddresses((uint)address1, (uint)address2);
        }

        public uint CalculateOffset(string address1, string address2)
        {
            uint pAddress1 = ParseAddress(address1), pAddress2 = ParseAddress(address2);

            if (pAddress1 > pAddress2)
            {
                return pAddress1 - pAddress2;
            }
            else
            {
                return pAddress2 - pAddress1;
            }
        }

        public uint CalculateOffset(uint address1, uint address2)
        {
            if (address1 > address2)
            {
                return address1 - address2;
            }
            else
            {
                return address2 - address1;
            }
        }

        public uint CalculateOffset(IntPtr address1, IntPtr address2)
        {
            return CalculateOffset((uint)address1, (uint)address2);
        }

        public uint GetOffset(string address1, string address2)
        {
            uint pAddress1 = ParseAddress(address1), pAddress2 = ParseAddress(address2);

            if (pAddress1 > pAddress2)
            {
                return pAddress1 - pAddress2;
            }
            else
            {
                return pAddress2 - pAddress1;
            }
        }

        public uint GetOffset(uint address1, uint address2)
        {
            if (address1 > address2)
            {
                return address1 - address2;
            }
            else
            {
                return address2 - address1;
            }
        }

        public uint GetOffset(IntPtr address1, IntPtr address2)
        {
            return GetOffset((uint)address1, (uint)address2);
        }

        public uint GetAddressFromPointerScan(uint baseAddress, uint[] offsets)
        {
            uint newBaseAddress = ReadUInt32((uint)BaseAddress + baseAddress);

            for (int i = 0; i < offsets.Length - 1; i++)
            {
                newBaseAddress = ReadUInt32(newBaseAddress + offsets[i]);
            }

            return newBaseAddress + offsets.Last();
        }

        public uint GetAddressFromPointers(uint baseAddress, uint[] offsets)
        {
            uint newBaseAddress = ReadUInt32((uint)BaseAddress + baseAddress);

            for (int i = 0; i < offsets.Length - 1; i++)
            {
                newBaseAddress = ReadUInt32(newBaseAddress + offsets[i]);
            }

            return newBaseAddress + offsets.Last();
        }

        public uint GetAddressFromOffsets(uint baseAddress, uint[] offsets)
        {
            uint newBaseAddress = ReadUInt32((uint)BaseAddress + baseAddress);

            for (int i = 0; i < offsets.Length - 1; i++)
            {
                newBaseAddress = ReadUInt32(newBaseAddress + offsets[i]);
            }

            return newBaseAddress + offsets.Last();
        }

        public uint FindDmaAddy(uint baseAddress, uint[] offsets)
        {
            uint newBaseAddress = ReadUInt32((uint)BaseAddress + baseAddress);

            for (int i = 0; i < offsets.Length - 1; i++)
            {
                newBaseAddress = ReadUInt32(newBaseAddress + offsets[i]);
            }

            return newBaseAddress + offsets.Last();
        }

        public uint GetAddressFromPointerScan(string address)
        {
            address = address.Replace(",", " ");
            uint baseAddress = 0;
            List<uint> offsets = new List<uint>();

            foreach (string splitted in address.Split(' '))
            {
                if (baseAddress == 0)
                {
                    baseAddress = ParseAddress(splitted);
                }
                else
                {
                    offsets.Add(ParseAddress(splitted));
                }
            }

            return GetAddressFromPointerScan(baseAddress, offsets.ToArray());
        }

        public uint GetAddressFromPointers(string address)
        {
            return GetAddressFromPointerScan(address);
        }

        public uint GetAddressFromOffsets(string address)
        {
            return GetAddressFromPointerScan(address);
        }

        public string GetStringFromAddress(uint address)
        {
            return address.ToString("X4");
        }

        public string GetStringFromAddress(IntPtr address)
        {
            return GetStringFromAddress((uint)address);
        }

        public string ConvertAddressToString(uint address)
        {
            return address.ToString("X4");
        }

        public string ConvertAddressToString(IntPtr address)
        {
            return GetStringFromAddress((uint)address);
        }

        public byte[] GetPatternFromString(string pattern)
        {
            List<byte> bytes = new List<byte>();

            foreach (string segment in pattern.Split(' '))
            {
                if (segment == "??" || segment == "?")
                {
                    bytes.Add(0x00);
                }
                else
                {
                    bytes.Add((byte)UInt32.Parse(segment, System.Globalization.NumberStyles.HexNumber));
                }
            }

            return bytes.ToArray();
        }

        public byte[] GetBytesFromString(string str)
        {
            return GetPatternFromString(str);
        }

        public string GetMaskFromString(string pattern)
        {
            string mask = "";

            foreach (string segment in pattern.Split(' '))
            {
                if (segment == "??" || segment == "?")
                {
                    mask += "?";
                }
                else
                {
                    mask += "x";
                }
            }

            return mask;
        }

        public string GetMaskFromBytes(byte[] bytes)
        {
            string mask = "";

            foreach (byte b in bytes)
            {
                if (b == 0)
                {
                    mask += "?";
                }
                else
                {
                    mask += "x";
                }
            }

            return mask;
        }

        public uint FindPattern(byte[] pattern, string mask = "", uint offset = 0, string module = "")
        {
            try
            {
                if (module == "")
                {
                    if (mask == "")
                    {
                        mask = GetMaskFromBytes(pattern);
                    }

                    uint moduleSize = (uint)DiagnosticsProcess.MainModule.ModuleMemorySize;
                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                    {
                        ReadProcessMemory(ProcessHandle, BaseAddress, moduleBytes, moduleSize, out numBytes);
                    }
                    else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                    {
                        NtReadVirtualMemory(ProcessHandle, BaseAddress, moduleBytes, moduleSize, ref numBytes);
                    }

                    for (int i = 0; i < moduleSize; i++)
                    {
                        bool found = true;

                        for (int l = 0; l < mask.Length; l++)
                        {
                            found = mask[l] == '?' || moduleBytes[l + i] == pattern[l];

                            if (!found)
                            {
                                break;
                            }
                        }

                        if (found)
                        {
                            return (uint)i + offset;
                        }
                    }
                }
                else
                {
                    ModuleInfo moduleInfo = GetModuleInformations(module);
                    uint moduleSize = moduleInfo.MemorySize;
                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                    {
                        ReadProcessMemory(ProcessHandle, BaseAddress, moduleBytes, moduleSize, out numBytes);
                    }
                    else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                    {
                        NtReadVirtualMemory(ProcessHandle, BaseAddress, moduleBytes, moduleSize, ref numBytes);
                    }

                    for (int i = 0; i < moduleSize; i++)
                    {
                        bool found = true;

                        for (int l = 0; l < mask.Length; l++)
                        {
                            found = mask[l] == '?' || moduleBytes[l + i] == pattern[l];

                            if (!found)
                            {
                                break;
                            }
                        }

                        if (found)
                        {
                            return (uint)i + offset;
                        }
                    }
                }

                return 0;
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to run pattern scanning.\r\n{ex.Message}\r\n{ex.StackTrace}\r\n{ex.Source}");
            }
        }

        public uint ScanPattern(byte[] pattern, string mask = "", uint offset = 0, string module = "")
        {
            return FindPattern(pattern, mask, offset, module);
        }

        public uint FindPattern(string pattern, uint offset = 0, string module = "")
        {
            return FindPattern(GetPatternFromString(pattern), GetMaskFromString(pattern), offset, module);
        }

        public uint ScanPattern(string pattern, uint offset = 0, string module = "")
        {
            return FindPattern(GetPatternFromString(pattern), GetMaskFromString(pattern), offset, module);
        }

        public void WriteUIntPtr(IntPtr offset, UIntPtr data)
        {
            WriteUInt32(offset, (uint)data);
        }

        public void WriteUIntPtr(uint offset, UIntPtr data)
        {
            WriteUIntPtr((IntPtr)offset, data);
        }

        public void WriteProtectedUIntPtr(IntPtr offset, UIntPtr data)
        {
            WriteProtectedUInt32(offset, (uint)data);
        }

        public void WriteProtectedUIntPtr(uint offset, UIntPtr data)
        {
            WriteProtectedUIntPtr((IntPtr)offset, data);
        }

        public UIntPtr ReadUIntPtr(IntPtr offset)
        {
            return (UIntPtr)ReadUInt32(offset);
        }

        public UIntPtr ReadUIntPtr(uint offset)
        {
            return (UIntPtr)ReadUInt32(offset);
        }

        public UIntPtr ReadProtectedUIntPtr(IntPtr offset)
        {
            return (UIntPtr)ReadProtectedUInt32(offset);
        }

        public UIntPtr ReadProtectedUIntPtr(uint offset)
        {
            return (UIntPtr)ReadProtectedUInt32(offset);
        }

        public UIntPtr[] ReadUIntPtrArray(IntPtr offset, uint size)
        {
            List<UIntPtr> values = new List<UIntPtr>();
            uint[] array = ReadUInt32Array(offset, size);

            for (int i = 0; i < array.Length; i++)
            {
                values.Add((UIntPtr)array[i]);
            }

            return values.ToArray();
        }

        public UIntPtr[] ReadUIntPtrArray(uint offset, uint size)
        {
            List<UIntPtr> values = new List<UIntPtr>();
            uint[] array = ReadUInt32Array(offset, size);

            for (int i = 0; i < array.Length; i++)
            {
                values.Add((UIntPtr)array[i]);
            }

            return values.ToArray();
        }

        public UIntPtr[] ReadProtectedUIntPtrArray(IntPtr offset, uint size)
        {
            List<UIntPtr> values = new List<UIntPtr>();
            uint[] array = ReadProtectedUInt32Array(offset, size);

            for (int i = 0; i < array.Length; i++)
            {
                values.Add((UIntPtr)array[i]);
            }

            return values.ToArray();
        }

        public UIntPtr[] ReadProtectedUIntPtrArray(uint offset, uint size)
        {
            List<UIntPtr> values = new List<UIntPtr>();
            uint[] array = ReadProtectedUInt32Array(offset, size);

            for (int i = 0; i < array.Length; i++)
            {
                values.Add((UIntPtr)array[i]);
            }

            return values.ToArray();
        }

        public void WriteUIntPtrArray(IntPtr offset, IntPtr[] data)
        {
            List<uint> values = new List<uint>();

            for (int i = 0; i < data.Length; i++)
            {
                values.Add((uint)data[i]);
            }

            WriteUInt32Array(offset, values.ToArray());
        }

        public void WriteUIntPtrArray(uint offset, IntPtr[] data)
        {
            List<uint> values = new List<uint>();

            for (int i = 0; i < data.Length; i++)
            {
                values.Add((uint)data[i]);
            }

            WriteUInt32Array(offset, values.ToArray());
        }

        public void WriteProtectedUIntPtrArray(IntPtr offset, IntPtr[] data)
        {
            List<uint> values = new List<uint>();

            for (int i = 0; i < data.Length; i++)
            {
                values.Add((uint)data[i]);
            }

            WriteProtectedUInt32Array(offset, values.ToArray());
        }

        public void WriteProtectedUIntPtrArray(uint offset, IntPtr[] data)
        {
            List<uint> values = new List<uint>();

            for (int i = 0; i < data.Length; i++)
            {
                values.Add((uint)data[i]);
            }

            WriteProtectedUInt32Array(offset, values.ToArray());
        }

        public void Write(IntPtr offset, dynamic data)
        {
            if (data is int)
            {
                WriteInteger(offset, data);
            }
            else if (data is int[])
            {
                WriteIntegerArray(offset, data);
            }
            else if (data is uint)
            {
                WriteUIntegerArray(offset, data);
            }
            else if (data is float)
            {
                WriteFloat(offset, data);
            }
            else if (data is float[])
            {
                WriteFloatArray(offset, data);
            }
            else if (data is double)
            {
                WriteDouble(offset, data);
            }
            else if (data is double[])
            {
                WriteDoubleArray(offset, data);
            }
            else if (data is byte)
            {
                WriteByte(offset, data);
            }
            else if (data is byte[])
            {
                WriteBytes(offset, data);
            }
            else if (data is long)
            {
                WriteLong(offset, data);
            }
            else if (data is long[])
            {
                WriteLongArray(offset, data);
            }
            else if (data is short)
            {
                WriteShort(offset, data);
            }
            else if (data is ulong)
            {
                WriteULong(offset, data);
            }
            else if (data is ulong[])
            {
                WriteULongArray(offset, data);
            }
            else if (data is short[])
            {
                WriteShortArray(offset, data);
            }
            else if (data is ushort[])
            {
                WriteUShortArray(offset, data);
            }
            else if (data is ushort)
            {
                WriteUShort(offset, data);
            }
            else if (data is Vector2)
            {
                WriteVector2(offset, data);
            }
            else if (data is Vector3)
            {
                WriteVector3(offset, data);
            }
            else if (data is Vector4)
            {
                WriteVector4(offset, data);
            }
            else if (data is Vector2[])
            {
                WriteVector2Array(offset, data);
            }
            else if (data is Vector3[])
            {
                WriteVector3Array(offset, data);
            }
            else if (data is Vector4[])
            {
                WriteVector4Array(offset, data);
            }
            else if (data is string)
            {
                WriteStringUTF8(offset, data);
            }
            else if (data is bool)
            {
                WriteBoolean(offset, data);
            }
            else if (data is char)
            {
                WriteCharacter(offset, data);
            }
            else if (data is bool[])
            {
                WriteBooleanArray(offset, data);
            }
            else if (data is char[])
            {
                WriteCharacterArray(offset, data);
            }
            else if (data is IntPtr)
            {
                WriteIntPtr(offset, data);
            }
            else if (data is IntPtr[])
            {
                WriteIntPtrArray(offset, data);
            }
            else if (data is UIntPtr)
            {
                WriteUIntPtr(offset, data);
            }
            else if (data is UIntPtr[])
            {
                WriteUIntPtrArray(offset, data);
            }
        }

        public void WriteData(IntPtr offset, dynamic data)
        {
            Write(offset, data);
        }

        public void Write(uint offset, dynamic data)
        {
            Write((IntPtr)offset, data);
        }

        public void WriteData(uint offset, dynamic data)
        {
            Write((IntPtr)offset, data);
        }

        public void WriteMemory(IntPtr offset, dynamic data)
        {
            Write(offset, data);
        }

        public void WriteMemory(uint offset, dynamic data)
        {
            Write((IntPtr)offset, data);
        }

        public void WriteProtected(IntPtr offset, dynamic data)
        {
            if (data is int)
            {
                WriteProtectedInteger(offset, data);
            }
            else if (data is int[])
            {
                WriteProtectedIntegerArray(offset, data);
            }
            else if (data is uint)
            {
                WriteProtectedUIntegerArray(offset, data);
            }
            else if (data is float)
            {
                WriteProtectedFloat(offset, data);
            }
            else if (data is float[])
            {
                WriteProtectedFloatArray(offset, data);
            }
            else if (data is double)
            {
                WriteProtectedDouble(offset, data);
            }
            else if (data is double[])
            {
                WriteProtectedDoubleArray(offset, data);
            }
            else if (data is byte)
            {
                WriteProtectedByte(offset, data);
            }
            else if (data is byte[])
            {
                WriteProtectedBytes(offset, data);
            }
            else if (data is long)
            {
                WriteProtectedLong(offset, data);
            }
            else if (data is long[])
            {
                WriteProtectedLongArray(offset, data);
            }
            else if (data is short)
            {
                WriteProtectedShort(offset, data);
            }
            else if (data is ulong)
            {
                WriteProtectedULong(offset, data);
            }
            else if (data is ulong[])
            {
                WriteProtectedULongArray(offset, data);
            }
            else if (data is short[])
            {
                WriteProtectedShortArray(offset, data);
            }
            else if (data is ushort[])
            {
                WriteProtectedUShortArray(offset, data);
            }
            else if (data is ushort)
            {
                WriteProtectedUShort(offset, data);
            }
            else if (data is Vector2)
            {
                WriteProtectedVector2(offset, data);
            }
            else if (data is Vector3)
            {
                WriteProtectedVector3(offset, data);
            }
            else if (data is Vector4)
            {
                WriteProtectedVector4(offset, data);
            }
            else if (data is Vector2[])
            {
                WriteProtectedVector2Array(offset, data);
            }
            else if (data is Vector3[])
            {
                WriteProtectedVector3Array(offset, data);
            }
            else if (data is Vector4[])
            {
                WriteProtectedVector4Array(offset, data);
            }
            else if (data is string)
            {
                WriteProtectedStringUTF8(offset, data);
            }
            else if (data is bool)
            {
                WriteProtectedBoolean(offset, data);
            }
            else if (data is char)
            {
                WriteProtectedCharacter(offset, data);
            }
            else if (data is bool[])
            {
                WriteProtectedBooleanArray(offset, data);
            }
            else if (data is char[])
            {
                WriteProtectedCharacterArray(offset, data);
            }
            else if (data is IntPtr)
            {
                WriteProtectedIntPtr(offset, data);
            }
            else if (data is IntPtr[])
            {
                WriteProtectedIntPtrArray(offset, data);
            }
            else if (data is UIntPtr)
            {
                WriteProtectedUIntPtr(offset, data);
            }
            else if (data is UIntPtr[])
            {
                WriteProtectedUIntPtrArray(offset, data);
            }
        }

        public void WriteProtectedData(IntPtr offset, dynamic data)
        {
            WriteProtected(offset, data);
        }

        public void WriteProtected(uint offset, dynamic data)
        {
            WriteProtected((IntPtr)offset, data);
        }

        public void WriteProtectedData(uint offset, dynamic data)
        {
            WriteProtected((IntPtr)offset, data);
        }

        public void WriteProtectedMemory(IntPtr offset, dynamic data)
        {
            WriteProtected(offset, data);
        }

        public void WriteProtectedMemory(uint offset, dynamic data)
        {
            WriteProtected((IntPtr)offset, data);
        }

        public T Read<T>(IntPtr offset, uint size = 0)
        {
            object ReadOutput = null;
            Type typeParameterType = typeof(T);

            if (typeParameterType == typeof(int))
            {
                ReadOutput = ReadInteger(offset);
            }
            else if (typeParameterType == typeof(int[]))
            {
                ReadOutput = ReadIntegerArray(offset, size);
            }
            else if (typeParameterType == typeof(uint))
            {
                ReadOutput = ReadUIntegerArray(offset, size);
            }
            else if (typeParameterType == typeof(float))
            {
                ReadOutput = ReadFloat(offset);
            }
            else if (typeParameterType == typeof(float[]))
            {
                ReadOutput = ReadFloatArray(offset, size);
            }
            else if (typeParameterType == typeof(double))
            {
                ReadOutput = ReadDouble(offset);
            }
            else if (typeParameterType == typeof(double[]))
            {
                ReadOutput = ReadDoubleArray(offset, size);
            }
            else if (typeParameterType == typeof(byte))
            {
                ReadOutput = ReadByte(offset);
            }
            else if (typeParameterType == typeof(byte[]))
            {
                ReadOutput = ReadBytes(offset, size);
            }
            else if (typeParameterType == typeof(long))
            {
                ReadOutput = ReadLong(offset);
            }
            else if (typeParameterType == typeof(long[]))
            {
                ReadOutput = ReadLongArray(offset, size);
            }
            else if (typeParameterType == typeof(short))
            {
                ReadOutput = ReadShort(offset);
            }
            else if (typeParameterType == typeof(ulong))
            {
                ReadOutput = ReadULong(offset);
            }
            else if (typeParameterType == typeof(ulong[]))
            {
                ReadOutput = ReadULongArray(offset, size);
            }
            else if (typeParameterType == typeof(short[]))
            {
                ReadOutput = ReadShortArray(offset, size);
            }
            else if (typeParameterType == typeof(ushort[]))
            {
                ReadOutput = ReadUShortArray(offset, size);
            }
            else if (typeParameterType == typeof(ushort))
            {
                ReadOutput = ReadUShort(offset);
            }
            else if (typeParameterType == typeof(Vector2))
            {
                ReadOutput = ReadVector2(offset);
            }
            else if (typeParameterType == typeof(Vector3))
            {
                ReadOutput = ReadVector3(offset);
            }
            else if (typeParameterType == typeof(Vector4))
            {
                ReadOutput = ReadVector4(offset);
            }
            else if (typeParameterType == typeof(Vector2[]))
            {
                ReadOutput = ReadVector2Array(offset, size);
            }
            else if (typeParameterType == typeof(Vector3[]))
            {
                ReadOutput = ReadVector3Array(offset, size);
            }
            else if (typeParameterType == typeof(Vector4[]))
            {
                ReadOutput = ReadVector4Array(offset, size);
            }
            else if (typeParameterType == typeof(string))
            {
                ReadOutput = ReadStringUTF8(offset, size);
            }
            else if (typeParameterType == typeof(bool))
            {
                ReadOutput = ReadBoolean(offset);
            }
            else if (typeParameterType == typeof(char))
            {
                ReadOutput = ReadCharacter(offset);
            }
            else if (typeParameterType == typeof(bool[]))
            {
                ReadOutput = ReadBooleanArray(offset, size);
            }
            else if (typeParameterType == typeof(char[]))
            {
                ReadOutput = ReadCharacterArray(offset, size);
            }
            else if (typeParameterType == typeof(IntPtr))
            {
                ReadOutput = ReadIntPtr(offset);
            }
            else if (typeParameterType == typeof(IntPtr[]))
            {
                ReadOutput = ReadIntPtrArray(offset, size);
            }
            else if (typeParameterType == typeof(UIntPtr))
            {
                ReadOutput = ReadUIntPtr(offset);
            }
            else if (typeParameterType == typeof(UIntPtr[]))
            {
                ReadOutput = ReadUIntPtrArray(offset, size);
            }

            if (ReadOutput != null)
            {
                return (T)Convert.ChangeType(ReadOutput, typeof(T));
            }
            else
            {
                return default(T);
            }
        }

        public T ReadMemory<T>(IntPtr offset, uint size = 0)
        {
            return Read<T>(offset, size);
        }

        public T ReadData<T>(IntPtr offset, uint size = 0)
        {
            return Read<T>(offset, size);
        }

        public T Read<T>(uint offset, uint size = 0)
        {
            return Read<T>((IntPtr)offset, size);
        }

        public T ReadData<T>(uint offset, uint size = 0)
        {
            return Read<T>((IntPtr)offset, size);
        }

        public T ReadMemory<T>(uint offset, uint size = 0)
        {
            return Read<T>((IntPtr)offset, size);
        }

        public T ReadProtected<T>(IntPtr offset, uint size = 0)
        {
            object ReadProtectedOutput = null;
            Type typeParameterType = typeof(T);

            if (typeParameterType == typeof(int))
            {
                ReadProtectedOutput = ReadProtectedInteger(offset);
            }
            else if (typeParameterType == typeof(int[]))
            {
                ReadProtectedOutput = ReadProtectedIntegerArray(offset, size);
            }
            else if (typeParameterType == typeof(uint))
            {
                ReadProtectedOutput = ReadProtectedUIntegerArray(offset, size);
            }
            else if (typeParameterType == typeof(float))
            {
                ReadProtectedOutput = ReadProtectedFloat(offset);
            }
            else if (typeParameterType == typeof(float[]))
            {
                ReadProtectedOutput = ReadProtectedFloatArray(offset, size);
            }
            else if (typeParameterType == typeof(double))
            {
                ReadProtectedOutput = ReadProtectedDouble(offset);
            }
            else if (typeParameterType == typeof(double[]))
            {
                ReadProtectedOutput = ReadProtectedDoubleArray(offset, size);
            }
            else if (typeParameterType == typeof(byte))
            {
                ReadProtectedOutput = ReadProtectedByte(offset);
            }
            else if (typeParameterType == typeof(byte[]))
            {
                ReadProtectedOutput = ReadProtectedBytes(offset, size);
            }
            else if (typeParameterType == typeof(long))
            {
                ReadProtectedOutput = ReadProtectedLong(offset);
            }
            else if (typeParameterType == typeof(long[]))
            {
                ReadProtectedOutput = ReadProtectedLongArray(offset, size);
            }
            else if (typeParameterType == typeof(short))
            {
                ReadProtectedOutput = ReadProtectedShort(offset);
            }
            else if (typeParameterType == typeof(ulong))
            {
                ReadProtectedOutput = ReadProtectedULong(offset);
            }
            else if (typeParameterType == typeof(ulong[]))
            {
                ReadProtectedOutput = ReadProtectedULongArray(offset, size);
            }
            else if (typeParameterType == typeof(short[]))
            {
                ReadProtectedOutput = ReadProtectedShortArray(offset, size);
            }
            else if (typeParameterType == typeof(ushort[]))
            {
                ReadProtectedOutput = ReadProtectedUShortArray(offset, size);
            }
            else if (typeParameterType == typeof(ushort))
            {
                ReadProtectedOutput = ReadProtectedUShort(offset);
            }
            else if (typeParameterType == typeof(Vector2))
            {
                ReadProtectedOutput = ReadProtectedVector2(offset);
            }
            else if (typeParameterType == typeof(Vector3))
            {
                ReadProtectedOutput = ReadProtectedVector3(offset);
            }
            else if (typeParameterType == typeof(Vector4))
            {
                ReadProtectedOutput = ReadProtectedVector4(offset);
            }
            else if (typeParameterType == typeof(Vector2[]))
            {
                ReadProtectedOutput = ReadProtectedVector2Array(offset, size);
            }
            else if (typeParameterType == typeof(Vector3[]))
            {
                ReadProtectedOutput = ReadProtectedVector3Array(offset, size);
            }
            else if (typeParameterType == typeof(Vector4[]))
            {
                ReadProtectedOutput = ReadProtectedVector4Array(offset, size);
            }
            else if (typeParameterType == typeof(string))
            {
                ReadProtectedOutput = ReadProtectedStringUTF8(offset, size);
            }
            else if (typeParameterType == typeof(bool))
            {
                ReadProtectedOutput = ReadProtectedBoolean(offset);
            }
            else if (typeParameterType == typeof(char))
            {
                ReadProtectedOutput = ReadProtectedCharacter(offset);
            }
            else if (typeParameterType == typeof(bool[]))
            {
                ReadProtectedOutput = ReadProtectedBooleanArray(offset, size);
            }
            else if (typeParameterType == typeof(char[]))
            {
                ReadProtectedOutput = ReadProtectedCharacterArray(offset, size);
            }
            else if (typeParameterType == typeof(IntPtr))
            {
                ReadProtectedOutput = ReadProtectedIntPtr(offset);
            }
            else if (typeParameterType == typeof(IntPtr[]))
            {
                ReadProtectedOutput = ReadProtectedIntPtrArray(offset, size);
            }
            else if (typeParameterType == typeof(UIntPtr))
            {
                ReadProtectedOutput = ReadProtectedUIntPtr(offset);
            }
            else if (typeParameterType == typeof(UIntPtr[]))
            {
                ReadProtectedOutput = ReadProtectedUIntPtrArray(offset, size);
            }

            if (ReadProtectedOutput != null)
            {
                return (T)Convert.ChangeType(ReadProtectedOutput, typeof(T));
            }
            else
            {
                return default(T);
            }
        }

        public T ReadProtectedMemory<T>(IntPtr offset, uint size = 0)
        {
            return ReadProtected<T>(offset, size);
        }

        public T ReadProtectedData<T>(IntPtr offset, uint size = 0)
        {
            return ReadProtected<T>(offset, size);
        }

        public T ReadProtected<T>(uint offset, uint size = 0)
        {
            return ReadProtected<T>((IntPtr)offset, size);
        }

        public T ReadProtectedData<T>(uint offset, uint size = 0)
        {
            return ReadProtected<T>((IntPtr)offset, size);
        }

        public T ReadProtectedMemory<T>(uint offset, uint size = 0)
        {
            return ReadProtected<T>((IntPtr)offset, size);
        }

        public void WriteBits(IntPtr offset, bool[] bits)
        {
            byte[] buf = new byte[1];

            for (var i = 0; i < 8; i++)
            {
                if (bits[i])
                {
                    buf[0] |= (byte)(1 << i);
                }
            }

            WriteBytes(offset, buf);
        }

        public void WriteBits(uint offset, bool[] bits)
        {
            WriteBits((IntPtr)offset, bits);
        }

        public void WriteProtectedBits(IntPtr offset, bool[] bits)
        {
            byte[] buf = new byte[1];

            for (var i = 0; i < 8; i++)
            {
                if (bits[i])
                {
                    buf[0] |= (byte)(1 << i);
                }
            }

            WriteProtectedBytes(offset, buf);
        }

        public void WriteProtectedBits(uint offset, bool[] bits)
        {
            WriteProtectedBits((IntPtr)offset, bits);
        }

        public bool[] ReadBits(IntPtr offset)
        {
            byte[] buffer = new byte[1] { ReadByte(offset) };
            bool[] result = new bool[8];

            for (var i = 0; i < 8; i++)
            {
                result[i] = Convert.ToBoolean(buffer[0] & (1 << i));
            }

            return result;
        }

        public bool[] ReadProtectedBits(IntPtr offset)
        {
            byte[] buffer = new byte[1] { ReadProtectedByte(offset) };
            bool[] result = new bool[8];

            for (var i = 0; i < 8; i++)
            {
                result[i] = Convert.ToBoolean(buffer[0] & (1 << i));
            }

            return result;
        }

        public bool[] ReadBits(uint offset)
        {
            return ReadBits((IntPtr)offset);
        }

        public bool[] ReadProtectedBits(uint offset)
        {
            return ReadProtectedBits((IntPtr)offset);
        }

        public void Write(string offset, string type, string data)
        {
            uint address = ParseAddress(offset);
            type = type.ToLower().Replace(" ", "").Replace('\t'.ToString(), "");

            if (type == "int" || type == "int32" || type == "integer" || type == "integer32")
            {
                WriteInteger(address, Convert.ToInt32(data));
            }
            else if (type == "double")
            {
                WriteDouble(address, Convert.ToDouble(data));
            }
            else if (type == "float")
            {
                WriteFloat(address, Convert.ToSingle(data));
            }
            else if (type == "short" || type == "int16" || type == "integer16" || type == "short16")
            {
                WriteShort(address, Convert.ToInt16(data));
            }
            else if (type == "long" || type == "int64" || type == "integer64" || type == "long64")
            {
                WriteLong(address, Convert.ToInt64(data));
            }
            else if (type == "bool" || type == "boolean")
            {
                WriteBoolean(address, Convert.ToBoolean(data));
            }
            else if (type == "char" || type == "character")
            {
                WriteCharacter(address, Convert.ToChar(data));
            }
            else if (type == "byte")
            {
                WriteByte(address, Convert.ToByte(data));
            }
            else if (type == "uint" || data == "uint32" || type == "unsigned integer" || type == "unsignedinteger")
            {
                WriteUInteger(address, Convert.ToUInt32(data));
            }
            else if (type == "ushort" || type == "uint16" || type == "unsigned short" || type == "unsignedshort")
            {
                WriteUShort(address, Convert.ToUInt16(data));
            }
            else if (type == "ulong" || type == "uint64" || type == "unsigned long" || type == "unsignedlong")
            {
                WriteULong(address, Convert.ToUInt64(data));
            }
            else if (type == "intptr")
            {
                WriteIntPtr(address, (IntPtr)Convert.ToInt32(data));
            }
            else if (type == "uintptr")
            {
                WriteUIntPtr(address, (UIntPtr)Convert.ToInt32(data));
            }
        }

        public void WriteMemory(string offset, string type, string data)
        {
            Write(offset, type, data);
        }

        public void WriteData(string offset, string type, string data)
        {
            Write(offset, type, data);
        }

        public void WriteProtected(string offset, string type, string data)
        {
            uint address = ParseAddress(offset);
            type = type.ToLower().Replace(" ", "").Replace('\t'.ToString(), "");

            if (type == "int" || type == "int32" || type == "integer" || type == "integer32")
            {
                WriteProtectedInteger(address, Convert.ToInt32(data));
            }
            else if (type == "double")
            {
                WriteProtectedDouble(address, Convert.ToDouble(data));
            }
            else if (type == "float")
            {
                WriteProtectedFloat(address, Convert.ToSingle(data));
            }
            else if (type == "short" || type == "int16" || type == "integer16" || type == "short16")
            {
                WriteProtectedShort(address, Convert.ToInt16(data));
            }
            else if (type == "long" || type == "int64" || type == "integer64" || type == "long64")
            {
                WriteProtectedLong(address, Convert.ToInt64(data));
            }
            else if (type == "bool" || type == "boolean")
            {
                WriteProtectedBoolean(address, Convert.ToBoolean(data));
            }
            else if (type == "char" || type == "character")
            {
                WriteProtectedCharacter(address, Convert.ToChar(data));
            }
            else if (type == "byte")
            {
                WriteProtectedByte(address, Convert.ToByte(data));
            }
            else if (type == "uint" || type == "uint32" || type == "unsigned integer" || type == "unsignedinteger")
            {
                WriteProtectedUInteger(address, Convert.ToUInt32(data));
            }
            else if (type == "ushort" || type == "uint16" || type == "unsigned short" || type == "unsignedshort")
            {
                WriteProtectedUShort(address, Convert.ToUInt16(data));
            }
            else if (type == "ulong" || type == "uint64" || type == "unsigned long" || type == "unsignedlong")
            {
                WriteProtectedULong(address, Convert.ToUInt64(data));
            }
            else if (type == "intptr")
            {
                WriteProtectedIntPtr(address, (IntPtr)Convert.ToInt32(data));
            }
            else if (type == "uintptr")
            {
                WriteProtectedUIntPtr(address, (UIntPtr)Convert.ToInt32(data));
            }
        }

        public void WriteProtectedMemory(string offset, string type, string data)
        {
            WriteProtected(offset, type, data);
        }

        public void WriteProtectedData(string offset, string type, string data)
        {
            WriteProtected(offset, type, data);
        }

        public dynamic Read(string offset, string type)
        {
            uint address = ParseAddress(offset);
            type = type.ToLower().Replace(" ", "").Replace('\t'.ToString(), "");

            if (type == "int" || type == "int32" || type == "integer" || type == "integer32")
            {
                return ReadInteger(address);
            }
            else if (type == "double")
            {
                return ReadDouble(address);
            }
            else if (type == "float")
            {
                return ReadFloat(address);
            }
            else if (type == "short" || type == "int16" || type == "integer16" || type == "short16")
            {
                return ReadShort(address);
            }
            else if (type == "long" || type == "int64" || type == "integer64" || type == "long64")
            {
                return ReadLong(address);
            }
            else if (type == "bool" || type == "boolean")
            {
                return ReadBoolean(address);
            }
            else if (type == "char" || type == "character")
            {
                return ReadCharacter(address);
            }
            else if (type == "byte")
            {
                return ReadByte(address);
            }
            else if (type == "uint" || type == "uint32" || type == "unsigned integer" || type == "unsignedinteger")
            {
                return ReadUInt32(address);
            }
            else if (type == "ushort" || type == "uint16" || type == "unsigned short" || type == "unsignedshort")
            {
                return ReadUShort(address);
            }
            else if (type == "ulong" || type == "uint64" || type == "unsigned long" || type == "unsignedlong")
            {
                return ReadULong(address);
            }
            else if (type == "intptr")
            {
                return ReadIntPtr(address);
            }
            else if (type == "uintptr")
            {
                return ReadUIntPtr(address);
            }

            return null;
        }

        public dynamic ReadMemory(string offset, string type)
        {
            return Read(offset, type);
        }

        public dynamic ReadData(string offset, string type)
        {
            return Read(offset, type);
        }

        public dynamic ReadProtected(string offset, string type)
        {
            uint address = ParseAddress(offset);
            type = type.ToLower().Replace(" ", "").Replace('\t'.ToString(), "");

            if (type == "int" || type == "int32" || type == "integer" || type == "integer32")
            {
                return ReadProtectedInteger(address);
            }
            else if (type == "double")
            {
                return ReadProtectedDouble(address);
            }
            else if (type == "float")
            {
                return ReadProtectedFloat(address);
            }
            else if (type == "short" || type == "int16" || type == "integer16" || type == "short16")
            {
                return ReadProtectedShort(address);
            }
            else if (type == "long" || type == "int64" || type == "integer64" || type == "long64")
            {
                return ReadProtectedLong(address);
            }
            else if (type == "bool" || type == "boolean")
            {
                return ReadProtectedBoolean(address);
            }
            else if (type == "char" || type == "character")
            {
                return ReadProtectedCharacter(address);
            }
            else if (type == "byte")
            {
                return ReadProtectedByte(address);
            }
            else if (type == "uint" || type == "uint32" || type == "unsigned integer" || type == "unsignedinteger")
            {
                return ReadProtectedUInt32(address);
            }
            else if (type == "ushort" || type == "uint16" || type == "unsigned short" || type == "unsignedshort")
            {
                return ReadProtectedUShort(address);
            }
            else if (type == "ulong" || type == "uint64" || type == "unsigned long" || type == "unsignedlong")
            {
                return ReadProtectedULong(address);
            }
            else if (type == "intptr")
            {
                return ReadProtectedIntPtr(address);
            }
            else if (type == "uintptr")
            {
                return ReadProtectedUIntPtr(address);
            }

            return null;
        }

        public dynamic ReadProtectedMemory(string offset, string type)
        {
            return ReadProtected(offset, type);
        }

        public dynamic ReadProtectedData(string offset, string type)
        {
            return ReadProtected(offset, type);
        }

        public bool IsPattern(byte[] data, string mask = "", uint offset = 0, string module = "")
        {
            return FindPattern(data, mask, offset, module) != 0;
        }

        public bool IsPattern(string pattern, uint offset = 0, string module = "")
        {
            return FindPattern(pattern, offset, module) != 0;
        }

        public void Dispose()
        {
            CloseHandle(ProcessHandle);
            ProcessHandle = IntPtr.Zero;
            DiagnosticsProcess = null;
            ProcessId = -1;
            BaseAddress = IntPtr.Zero;
            GC.Collect();
        }

        public void EjectModule(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            try
            {
                IntPtr remoteThread = new IntPtr(0);
                IntPtr freeLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");
                IntPtr moduleBaseAddress = GetModuleInfo(moduleName).BaseAddress;

                switch (threadFunction)
                {
                    case CreateThreadFunction.CreateRemoteThread:
                        CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, freeLibraryAddress, moduleBaseAddress, 0, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.RtlCreateUserThread:
                        RtlCreateUserThread(ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAddress, moduleBaseAddress, ref remoteThread, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.NtCreateThreadEx:
                        NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, ProcessHandle, freeLibraryAddress, moduleBaseAddress, false, 0, 0, 0, IntPtr.Zero);
                        break;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while ejecting the module.\r\n{ex.Message}\r\n{ex.Source}\r\n{ex.StackTrace}");
            }
        }

        public void EjectModule(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            try
            {
                IntPtr remoteThread = new IntPtr(0);
                IntPtr freeLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary");

                switch (threadFunction)
                {
                    case CreateThreadFunction.CreateRemoteThread:
                        CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, freeLibraryAddress, moduleAddress, 0, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.RtlCreateUserThread:
                        RtlCreateUserThread(ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, freeLibraryAddress, moduleAddress, ref remoteThread, IntPtr.Zero);
                        break;
                    case CreateThreadFunction.NtCreateThreadEx:
                        NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, ProcessHandle, freeLibraryAddress, moduleAddress, false, 0, 0, 0, IntPtr.Zero);
                        break;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"An error occurred while ejecting the module.\r\n{ex.Message}\r\n{ex.Source}\r\n{ex.StackTrace}");
            }
        }

        public void EjectModule(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule((IntPtr)moduleAddress, threadFunction);
        }

        public void EjectDLL(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void EjectLibrary(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void FreeLibrary(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void FreeDLL(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void FreeModule(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void UninjectDLL(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void UninjectLibrary(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void UninjectModule(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void DejectLibrary(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void DejectDLL(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void DejectModule(string moduleName, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleName, threadFunction);
        }

        public void EjectDLL(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void EjectLibrary(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void FreeLibrary(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void FreeDLL(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void FreeModule(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void UninjectDLL(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void UninjectLibrary(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void UninjectModule(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void DejectLibrary(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void DejectDLL(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void DejectModule(IntPtr moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void EjectDLL(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void EjectLibrary(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void FreeLibrary(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void FreeDLL(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void FreeModule(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void UninjectDLL(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void UninjectLibrary(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void UninjectModule(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void DejectLibrary(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void DejectDLL(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void DejectModule(uint moduleAddress, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            EjectModule(moduleAddress, threadFunction);
        }

        public void ManualMapLibrary(string pathToModule)
        {
            MapModule(pathToModule);
        }

        public void ManualMapLibrary(byte[] moduleBytes)
        {
            MapModule(moduleBytes);
        }

        public void MapLibrary(string pathToModule)
        {
            MapModule(pathToModule);
        }

        public void MapLibrary(byte[] moduleBytes)
        {
            MapModule(moduleBytes);
        }

        public ModuleInfo InjectLibrary(string pathToModule, LoadLibraryFunction libraryFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            return InjectModule(pathToModule, libraryFunction, threadFunction);
        }

        public ModuleInfo LoadLibrary(string pathToModule, LoadLibraryFunction libraryFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            return InjectModule(pathToModule, libraryFunction, threadFunction);
        }

        public ModuleInfo InjectLibrary(byte[] bytes, LoadLibraryFunction libraryFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            return InjectModule(bytes, libraryFunction, threadFunction);
        }

        public ModuleInfo LoadLibrary(byte[] bytes, LoadLibraryFunction libraryFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            return InjectModule(bytes, libraryFunction, threadFunction);
        }

        public ScanResultInt32 ScanMemoryForInt32(int value, bool allModules = false)
        {
            List<ScanValueInt32> values = new List<ScanValueInt32>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] theBytes = new byte[4] { moduleBytes[i], moduleBytes[i + 1], moduleBytes[i + 2], moduleBytes[i + 3] };
                                int newValue = BitConverter.ToInt32(theBytes, 0);

                                if (newValue == value)
                                {
                                    values.Add(new ScanValueInt32((IntPtr)i, newValue, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultInt32(values);
        }

        public ScanResultInt32 ScanMemoryForInteger(int value, bool allModules = false)
        {
            return ScanMemoryForInt32(value, allModules);
        }

        public ScanResultInt16 ScanMemoryForInt16(short value, bool allModules = false)
        {
            List<ScanValueInt16> values = new List<ScanValueInt16>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] theBytes = new byte[2] { moduleBytes[i], moduleBytes[i + 1] };
                                short newValue = BitConverter.ToInt16(theBytes, 0);

                                if (newValue == value)
                                {
                                    values.Add(new ScanValueInt16((IntPtr)i, newValue, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultInt16(values);
        }

        public ScanResultInt16 ScanMemoryForShort(short value, bool allModules = false)
        {
            return ScanMemoryForInt16(value, allModules);
        }

        public ScanResultInt64 ScanMemoryForInt64(long value, bool allModules = false)
        {
            List<ScanValueInt64> values = new List<ScanValueInt64>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] theBytes = new byte[8] { moduleBytes[i], moduleBytes[i + 1], moduleBytes[i + 2], moduleBytes[i + 3], moduleBytes[i + 4], moduleBytes[i + 5], moduleBytes[i + 6], moduleBytes[i + 7] };
                                long newValue = BitConverter.ToInt64(theBytes, 0);

                                if (newValue == value)
                                {
                                    values.Add(new ScanValueInt64((IntPtr)i, newValue, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultInt64(values);
        }

        public ScanResultInt64 ScanMemoryForLong(long value, bool allModules = false)
        {
            return ScanMemoryForInt64(value, allModules);
        }

        public ScanResultUInt32 ScanMemoryForUInt32(uint value, bool allModules = false)
        {
            List<ScanValueUInt32> values = new List<ScanValueUInt32>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] theBytes = new byte[4] { moduleBytes[i], moduleBytes[i + 1], moduleBytes[i + 2], moduleBytes[i + 3] };
                                uint newValue = BitConverter.ToUInt32(theBytes, 0);

                                if (newValue == value)
                                {
                                    values.Add(new ScanValueUInt32((IntPtr)i, newValue, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultUInt32(values);
        }

        public ScanResultUInt32 ScanMemoryForUnsignedInteger(uint value, bool allModules = false)
        {
            return ScanMemoryForUInt32(value, allModules);
        }

        public ScanResultUInt32 ScanMemoryForUnsignedInt32(uint value, bool allModules = false)
        {
            return ScanMemoryForUInt32(value, allModules);
        }

        public ScanResultUInt32 ScanMemoryForUInteger(uint value, bool allModules = false)
        {
            return ScanMemoryForUInt32(value, allModules);
        }

        public ScanResultUInt16 ScanMemoryForUInt16(ushort value, bool allModules = false)
        {
            List<ScanValueUInt16> values = new List<ScanValueUInt16>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] theBytes = new byte[2] { moduleBytes[i], moduleBytes[i + 1] };
                                ushort newValue = BitConverter.ToUInt16(theBytes, 0);

                                if (newValue == value)
                                {
                                    values.Add(new ScanValueUInt16((IntPtr)i, newValue, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultUInt16(values);
        }

        public ScanResultUInt16 ScanMemoryForUnsignedShort(ushort value, bool allModules = false)
        {
            return ScanMemoryForUInt16(value, allModules);
        }

        public ScanResultUInt16 ScanMemoryForUnsignedInt16(ushort value, bool allModules = false)
        {
            return ScanMemoryForUInt16(value, allModules);
        }

        public ScanResultUInt16 ScanMemoryForUShort(ushort value, bool allModules = false)
        {
            return ScanMemoryForUInt16(value, allModules);
        }

        public ScanResultUInt64 ScanMemoryForUInt64(ulong value, bool allModules = false)
        {
            List<ScanValueUInt64> values = new List<ScanValueUInt64>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] theBytes = new byte[8] { moduleBytes[i], moduleBytes[i + 1], moduleBytes[i + 2], moduleBytes[i + 3], moduleBytes[i + 4], moduleBytes[i + 5], moduleBytes[i + 6], moduleBytes[i + 7] };
                                ulong newValue = BitConverter.ToUInt64(theBytes, 0);

                                if (newValue == value)
                                {
                                    values.Add(new ScanValueUInt64((IntPtr)i, newValue, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultUInt64(values);
        }

        public ScanResultUInt64 ScanMemoryForUnsignedLong(ulong value, bool allModules = false)
        {
            return ScanMemoryForUInt64(value, allModules);
        }

        public ScanResultUInt64 ScanMemoryForUnsignedInt64(ulong value, bool allModules = false)
        {
            return ScanMemoryForUInt64(value, allModules);
        }

        public ScanResultUInt64 ScanMemoryForULong(ulong value, bool allModules = false)
        {
            return ScanMemoryForUInt64(value, allModules);
        }

        public ScanResultByte ScanMemoryForByte(byte value, bool allModules = false)
        {
            List<ScanValueByte> values = new List<ScanValueByte>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                if (value == moduleBytes[i])
                                {
                                    values.Add(new ScanValueByte((IntPtr)i, value, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultByte(values);
        }

        public byte[] GetBeforeBytes(IntPtr address, uint size)
        {
            uint theAddress = (uint)address;
            theAddress = theAddress - size;
            return ReadBytes(theAddress, size);
        }

        public byte[] GetBeforePattern(IntPtr address, uint size)
        {
            return GetBeforeBytes(address, size);
        }

        public byte[] GetBeforeBytes(uint address, uint size)
        {
            return GetBeforeBytes((IntPtr)address, size);
        }

        public byte[] GetBeforePattern(uint address, uint size)
        {
            return GetBeforeBytes((IntPtr)address, size);
        }

        public ScanResultByteArray ScanMemoryForByteArray(byte[] value, bool allModules = false)
        {
            List<ScanValueByteArray> values = new List<ScanValueByteArray>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] newValue = moduleBytes.Skip(i).Take(value.Length).ToArray();

                                if (CompareByteArrays(newValue, value))
                                {
                                    values.Add(new ScanValueByteArray((IntPtr)i, value, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultByteArray(values);
        }

        public ScanResultString ScanMemoryForString(string value, Encoding encoding, bool allModules = false)
        {
            List<ScanValueString> values = new List<ScanValueString>();
            string mainModuleName = DiagnosticsProcess.MainModule.ModuleName;

            foreach (ProcessModule module in DiagnosticsProcess.Modules)
            {
                try
                {
                    uint moduleSize = (uint)module.ModuleMemorySize;
                    IntPtr moduleBaseAddress = module.BaseAddress;
                    string moduleName = module.ModuleName;

                    if (!allModules)
                    {
                        if (moduleName != mainModuleName)
                        {
                            continue;
                        }
                    }

                    byte[] moduleBytes = new byte[moduleSize];
                    IntPtr numBytes = IntPtr.Zero;
                    byte[] bytesValue = encoding.GetBytes(value);

                    try
                    {
                        if (ReadMethod.Equals(MemoryMethod.KERNEL32))
                        {
                            ReadProcessMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, out numBytes);
                        }
                        else if (ReadMethod.Equals(MemoryMethod.NTDLL))
                        {
                            NtReadVirtualMemory(ProcessHandle, moduleBaseAddress, moduleBytes, moduleSize, ref numBytes);
                        }

                        for (int i = 0; i < moduleSize; i++)
                        {
                            try
                            {
                                byte[] newValue = moduleBytes.Skip(i).Take(bytesValue.Length).ToArray();

                                if (CompareByteArrays(newValue, bytesValue))
                                {
                                    values.Add(new ScanValueString((IntPtr)i, value, moduleName));
                                }
                            }
                            catch
                            {

                            }
                        }
                    }
                    catch
                    {

                    }
                }
                catch
                {

                }
            }

            return new ScanResultString(values);
        }

        public static bool CompareByteArrays(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                return false;
            }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                {
                    return false;
                }
            }

            return true;
        }

        public ScanResultByteArray ScanMemoryForBytes(byte[] value, bool allModules = false)
        {
            return ScanMemoryForByteArray(value, allModules);
        }

        public List<WindowInfo> GetWindows()
        {
            List<WindowInfo> windows = new List<WindowInfo>();

            foreach (ProcessThread thread in DiagnosticsProcess.Threads)
            {
                EnumThreadWindows(thread.Id,
                (hWnd, lParam) =>
                {
                    try
                    {
                        windows.Add(new WindowInfo(hWnd, DiagnosticsProcess, thread, (uint)DiagnosticsProcess.Id, (uint)thread.Id));
                    }
                    catch
                    {

                    }

                    return true;
                },
                IntPtr.Zero);
            }

            return windows;
        }

        public List<WindowInfo> GetWindowsInformations()
        {
            return GetWindows();
        }

        public List<WindowInfo> GetWindowsInfos()
        {
            return GetWindows();
        }

        public List<WindowInfo> GetWindowsInfo()
        {
            return GetWindows();
        }

        public WindowInfo GetMainWindow()
        {
            foreach (WindowInfo windowInfo in GetWindows())
            {
                try
                {
                    if (windowInfo.IsMainWindow)
                    {
                        return windowInfo;
                    }
                }
                catch
                {

                }
            }

            throw new Exception("Can not find the main window of the process.");
        }

        public List<WindowInfo> GetVisibleWindows()
        {
            List<WindowInfo> windows = new List<WindowInfo>();

            foreach (WindowInfo info in GetWindows())
            {
                try
                {
                    if (info.IsVisible)
                    {
                        windows.Add(info);
                    }
                }
                catch
                {

                }
            }

            return windows;
        }

        public WindowInfo GetWindowByTitle(string title)
        {
            foreach (WindowInfo info in GetWindows())
            {
                try
                {
                    if (info.WindowTitle.Equals(title))
                    {
                        return info;
                    }
                }
                catch
                {

                }
            }

            throw new Exception("Could not find a window with that title.");
        }

        public WindowInfo GetWindowByClassName(string className)
        {
            foreach (WindowInfo info in GetWindows())
            {
                try
                {
                    if (info.ClassName.Equals(className))
                    {
                        return info;
                    }
                }
                catch
                {

                }
            }

            throw new Exception("Could not find a window with that class name.");
        }

        public List<WindowInfo> GetWindowsByTitle(string title)
        {
            List<WindowInfo> windows = new List<WindowInfo>();

            foreach (WindowInfo info in GetWindows())
            {
                try
                {
                    if (info.WindowTitle.Equals(title))
                    {
                        windows.Add(info);
                    }
                }
                catch
                {

                }
            }

            return windows;
        }

        public List<WindowInfo> GetWindowsByCaption(string title)
        {
            List<WindowInfo> windows = new List<WindowInfo>();

            foreach (WindowInfo info in GetWindows())
            {
                try
                {
                    if (info.WindowTitle.Equals(title))
                    {
                        windows.Add(info);
                    }
                }
                catch
                {

                }
            }

            return windows;
        }

        public List<WindowInfo> GetWindowsByClassName(string className)
        {
            List<WindowInfo> windows = new List<WindowInfo>();

            foreach (WindowInfo info in GetWindows())
            {
                try
                {
                    if (info.ClassName.Equals(className))
                    {
                        windows.Add(info);
                    }
                }
                catch
                {

                }
            }

            return windows;
        }

        public WindowInfo GetWindowByCaption(string caption)
        {
            return GetWindowByTitle(caption);
        }

        public List<WindowInfo> GetVisibleWindowsInformations()
        {
            return GetVisibleWindows();
        }

        public List<WindowInfo> GetVisibleWindowsInfos()
        {
            return GetVisibleWindows();
        }

        public void SetMainWindowTitle(string title)
        {
            GetMainWindow().SetWindowTitle(title);
        }

        public void SetMainWindowText(string title)
        {
            GetMainWindow().SetWindowTitle(title);
        }

        public void MinimizeMainWindow()
        {
            GetMainWindow().MinimizeWindow();
        }

        public void MaximizeMainWindow()
        {
            GetMainWindow().MaximizeWindow();
        }

        public void CloseMainWindow()
        {
            GetMainWindow().CloseWindow();
        }

        public void FocusMainWindow()
        {
            GetMainWindow().FocusWindow();
        }

        public string GetMainWindowTitle()
        {
            return GetMainWindow().WindowTitle;
        }

        public string GetMainWindowText()
        {
            return GetMainWindow().WindowTitle;
        }

        public bool IsProcessFocused()
        {
            foreach (WindowInfo info in GetWindows())
            {
                if (info.IsFocused)
                {
                    return true;
                }
            }

            return false;
        }

        public bool IsProcessInFocus()
        {
            return IsProcessFocused();
        }

        public void ExecuteCppCode(CppCode code, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            try
            {
                string completeCode = Properties.Resources.BaseCode;
                string theIncludes = "";

                foreach (CppInclude include in code.Includes)
                {
                    string pInclude = include.Include;

                    if (!pInclude.StartsWith("#include <"))
                    {
                        pInclude = "#include <" + pInclude + ">";
                    }

                    if (theIncludes == "")
                    {
                        theIncludes = pInclude;
                    }
                    else
                    {
                        theIncludes += "\r\n" + pInclude;
                    }
                }

                completeCode = completeCode.Replace("#INCLUDES_CODE#", theIncludes);
                completeCode = completeCode.Replace("#CODE_INTO_DLL_MAIN#", code.DllMainCode);
                completeCode = completeCode.Replace("#BEFORE_DLL_MAIN_CODE#", code.BeforeDllMainCode);
                completeCode = completeCode.Replace("#AFTER_DLL_MAIN_CODE#", code.AfterDllMainCode);

                string rootDir = Environment.GetFolderPath(Environment.SpecialFolder.System).Substring(0, 1) + ":";

                if (!Directory.Exists(rootDir + "\\Temp"))
                {
                    Directory.CreateDirectory(rootDir + "\\Temp");
                }

                char[] characters = "abcdefghijklmnopqrstuvwxyzACBDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
                ProtoRandom random = new ProtoRandom(5);
                string folderName = random.GetRandomString(characters, random.GetRandomInt32(7, 18));
                Directory.CreateDirectory(rootDir + "\\Temp\\" + folderName);

                DirectoryInfo info = new DirectoryInfo(rootDir + "\\Temp\\" + folderName);
                info.Attributes = FileAttributes.Hidden | FileAttributes.Directory | FileAttributes.ReadOnly;

                string cppFileName = random.GetRandomString(characters, random.GetRandomInt32(7, 18)) + ".cpp";
                string dllFileName = random.GetRandomString(characters, random.GetRandomInt32(7, 18)) + ".dll";

                File.WriteAllText(rootDir + "\\Temp\\" + folderName + "\\" + cppFileName, completeCode);
                HideFile(rootDir + "\\Temp\\" + folderName + "\\" + cppFileName);

                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.FileName = "gcc.exe";

                if (Is64BitProcess())
                {
                    startInfo.Arguments = "-shared -o \"" + rootDir + "\\Temp\\" + folderName + "\\" + dllFileName + "\" \"" + rootDir + "\\Temp\\" + folderName + "\\" + cppFileName + "\"";
                }
                else
                {
                    startInfo.Arguments = "-m32 -shared -o \"" + rootDir + "\\Temp\\" + folderName + "\\" + dllFileName + "\" \"" + rootDir + "\\Temp\\" + folderName + "\\" + cppFileName + "\"";
                }

                startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                startInfo.CreateNoWindow = true;

                Process proc = Process.Start(startInfo);
                proc.WaitForExit();

                while (!File.Exists(rootDir + "\\Temp\\" + folderName + "\\" + dllFileName))
                {
                    Thread.Sleep(5);
                }

                HideFile(rootDir + "\\Temp\\" + folderName + "\\" + dllFileName);   
                InjectDLL(rootDir + "\\Temp\\" + folderName + "\\" + dllFileName, loadFunction, threadFunction);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to execute the C++ code.\r\n{ex.Message}\r\n{ex.StackTrace}\r\n{ex.Source}");
            }
        }

        public void InjectCppCode(CppCode code, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            ExecuteCppCode(code, loadFunction, threadFunction);
        }

        public void RunCppCode(CppCode code, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            ExecuteCppCode(code, loadFunction, threadFunction);
        }

        public void ForceCppCode(CppCode code, LoadLibraryFunction loadFunction = LoadLibraryFunction.LoadLibraryA, CreateThreadFunction threadFunction = CreateThreadFunction.CreateRemoteThread)
        {
            ExecuteCppCode(code, loadFunction, threadFunction);
        }

        public bool IsProcessRunning()
        {
            foreach (Process proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.Id == ProcessId)
                    {
                        return true;
                    }
                }
                catch
                {

                }
            }

            return false;
        }

        public bool IsProcessWorking()
        {
            return IsProcessRunning();
        }

        public bool IsProcessAlive()
        {
            return IsProcessRunning();
        }

        public string ConvertBytesToString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", " ");
        }

        public byte[] ConvertStringToBytes(string str)
        {
            if (str.Contains(",") || str.Contains(" "))
            {
                if (str.Contains(","))
                {
                    str = str.Replace(",", " ");
                }

                List<byte> bytes = new List<byte>();

                foreach (string segment in str.Split(' '))
                {
                    if (segment == "??" || segment == "?")
                    {
                        bytes.Add(0x00);
                    }
                    else
                    {
                        bytes.Add((byte)UInt32.Parse(segment, System.Globalization.NumberStyles.HexNumber));
                    }
                }

                return bytes.ToArray();
            }
            else
            {
                return new byte[1] { (byte)UInt32.Parse(str, System.Globalization.NumberStyles.HexNumber) };
            }
        }

        public byte[] CompileAssemblyCode(string asm)
        {
            List<string> theList = new List<string>();

            foreach (string line in SplitToLines(asm))
            {
                theList.Add(line);
            }

            return Binarysharp.Assemblers.Fasm.FasmNet.Assemble(theList.ToArray(), 1000, 10);
        }

        public byte[] CompileAssembly(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] CompileAsmCode(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] CompileAsm(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] GetAsm(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] GetAssembly(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] GetAsmBytes(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] GetAssemblyBytes(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] ConvertAsmToBytes(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] ConvertAssemblyToBytes(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] CompileShellcode(string asm)
        {
            return CompileAssembly(asm);
        }

        public byte[] CompileShell(string asm)
        {
            return CompileAssembly(asm);
        }

        public byte[] GetShellcode(string asm)
        {
            return CompileAssembly(asm);
        }

        public byte[] GetShell(string asm)
        {
            return CompileAssembly(asm);
        }

        public byte[] GetShellcodeBytes(string asm)
        {
            return CompileAssembly(asm);
        }

        public byte[] GetShellBytes(string asm)
        {
            return CompileAssembly(asm);
        }

        public byte[] ConvertAsmToShellcode(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] ConvertAssemblyToShellcode(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] ConvertAsmToShell(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        public byte[] ConvertAssemblyToShell(string asm)
        {
            return CompileAssemblyCode(asm);
        }

        private IEnumerable<string> SplitToLines(string input)
        {
            if (input == null)
            {
                yield break;
            }

            using (StringReader reader = new StringReader(input))
            {
                string line;

                while ((line = reader.ReadLine()) != null)
                {
                    yield return line;
                }
            }
        }

        public void InjectAssemblyCode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectAsmCode(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectAsmCode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectAssembly(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectAssembly(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectAsm(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectAsm(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectAssemblyBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectAssemblyString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectAsmBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectAsmString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectShellcode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectShell(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectShellcodeString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectShellcodeBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void InjectShell(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunAssemblyCode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunAsmCode(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunAsmCode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunAssembly(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunAssembly(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunAsm(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunAsm(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunAssemblyBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunAssemblyString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunAsmBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunAsmString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunShellcode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunShell(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunShellcodeString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void RunShellcodeBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void RunShell(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteAssemblyCode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteAsmCode(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteAsmCode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteAssembly(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteAssembly(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteAsm(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteAsm(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteAssemblyBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteAssemblyString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteAsmBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteAsmString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteShellcode(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteShell(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteShellcodeString(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void ExecuteShellcodeBytes(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, method);
        }

        public void ExecuteShell(string asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            try
            {
                InjectAssemblyCode(ConvertStringToBytes(asm), method);
            }
            catch
            {
                InjectAssemblyCode(CompileAsm(asm), method);
            }
        }

        public void InjectAssemblyCode(byte[] asm, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            IntPtr remoteThread = IntPtr.Zero;
            IntPtr allocatedMemoryAddress = VirtualAllocEx(ProcessHandle, IntPtr.Zero, (uint)asm.Length, MEM_COMMIT | MEM_RESERVE, 0x40);
            
            if (WriteMethod.Equals(MemoryMethod.KERNEL32))
            {
                WriteProcessMemory(ProcessHandle, allocatedMemoryAddress, asm, (uint)asm.Length, 0);
            }
            else if (WriteMethod.Equals(MemoryMethod.NTDLL))
            {
                uint bytesWritten = 0;
                NtWriteVirtualMemory(ProcessHandle, allocatedMemoryAddress, asm, (uint)asm.Length, ref bytesWritten);
            }

            if (method.Equals(AssemblyInjectionMethod.ClassicCreateThread))
            {            
                CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, allocatedMemoryAddress, IntPtr.Zero, 0, IntPtr.Zero);
            }
            else if (method.Equals(AssemblyInjectionMethod.ClassicRtlCreateUserThread))
            {
                RtlCreateUserThread(ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, allocatedMemoryAddress, IntPtr.Zero, ref remoteThread, IntPtr.Zero);
            }
            else if (method.Equals(AssemblyInjectionMethod.ClassicNtCreateThreadEx))
            {
                NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, ProcessHandle, allocatedMemoryAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            }
        }

        public void FillNOPs(IntPtr address, uint nops)
        {
            byte[] bytes = new byte[nops];

            for (int i = 0; i < nops; i++)
            {
                bytes[i] = 0x90;
            }

            WriteByteArray(address, bytes);
        }

        public void SetNOPs(IntPtr address, uint nops)
        {
            FillNOPs(address, nops);
        }

        public void FillNOPs(uint address, uint nops)
        {
            FillNOPs((IntPtr)address, nops);
        }

        public void SetNOPs(uint address, uint nops)
        {
            FillNOPs((IntPtr)address, nops);
        }

        public void DeleteInstructions(IntPtr address, uint size)
        {
            FillNOPs(address, size);
        }

        public void DeleteInstructions(uint address, uint size)
        {
            FillNOPs(address, size);
        }

        public void DeleteFunction(IntPtr address, uint size)
        {
            FillNOPs(address, size);
        }

        public void DeleteFunction(uint address, uint size)
        {
            FillNOPs(address, size);
        }

        public byte[] ParseStringBytes(string str)
        {
            return Encoding.ASCII.GetBytes(str);
        }

        public void PatchBytes(IntPtr address, byte[] bytes)
        {
            WriteByteArray(address, bytes);
        }

        public void PatchBytes(IntPtr address, string bytes)
        {
            WriteByteArray(address, ParseStringBytes(bytes));
        }

        public void PatchBytes(uint address, byte[] bytes)
        {
            WriteByteArray(address, bytes);
        }

        public void PatchBytes(uint address, string bytes)
        {
            WriteByteArray(address, ParseStringBytes(bytes));
        }

        public void WriteByteArray(IntPtr address, string bytes)
        {
            WriteByteArray(address, ParseStringBytes(bytes));
        }

        public void WriteBytes(IntPtr address, string bytes)
        {
            WriteByteArray(address, ParseStringBytes(bytes));
        }

        public void WriteByteArray(uint address, string bytes)
        {
            WriteByteArray(address, ParseStringBytes(bytes));
        }

        public void WriteBytes(uint address, string bytes)
        {
            WriteByteArray(address, ParseStringBytes(bytes));
        }

        public void UnprotectMemory(IntPtr offset, uint size)
        {
            uint newProtect = 0;

            if (ProtectMethod.Equals(MemoryMethod.KERNEL32))
            {
                VirtualProtectEx(ProcessHandle, offset, (UIntPtr)size, 64, out newProtect);
            }
            else if (ProtectMethod.Equals(MemoryMethod.NTDLL))
            {
                IntPtr theOffset = offset;
                uint numberBytes = size;
                NtProtectVirtualMemory(ProcessHandle, ref theOffset, ref numberBytes, 64, ref newProtect);
            }
        }

        public void UnprotectMemory(uint offset, uint size)
        {
            UnprotectMemory((IntPtr)offset, size);
        }

        public void UnprotectBytes(IntPtr offset, uint size)
        {
            UnprotectMemory(offset, size);
        }

        public void UnprotectRegion(IntPtr offset, uint size)
        {
            UnprotectMemory(offset, size);
        }

        public void UnprotectBytes(uint offset, uint size)
        {
            UnprotectMemory(offset, size);
        }

        public void UnprotectRegion(uint offset, uint size)
        {
            UnprotectMemory(offset, size);
        }

        public IntPtr GetFunctionAddress(string moduleName, string functionName)
        {
            ModuleInfo info = null;

            foreach (ModuleInfo theInfo in GetModules())
            {
                try
                {
                    if (theInfo.ModuleName.ToLower().StartsWith(moduleName.ToLower()))
                    {
                        info = theInfo;
                        break;
                    }
                }
                catch
                {

                }
            }

            var offset = GetProcAddress(info.Module.BaseAddress, functionName).ToInt64() - info.BaseAddress.ToInt64();
            return new IntPtr(info.Module.BaseAddress.ToInt64() + offset);
        }

        public IntPtr GetFunction(string moduleName, string functionName)
        {
            return GetFunctionAddress(moduleName, functionName);
        }

        public IntPtr GetFunctionAddress(string functionName)
        {
            return GetFunctionAddress(DiagnosticsProcess.MainModule.ModuleName, functionName);
        }

        public IntPtr GetFunction(string functionName)
        {
            return GetFunctionAddress(DiagnosticsProcess.MainModule.ModuleName, functionName);
        }

        public IntPtr GetGlobalFunction(string moduleName, string functionName)
        {
             return GetProcAddress(GetModuleHandle(moduleName), functionName);
        }

        public IntPtr AllocateMemory(uint size)
        {
            return VirtualAllocEx(ProcessHandle, IntPtr.Zero, size, MEM_COMMIT | MEM_RESERVE, 0x40);
        }

        public IntPtr Allocate(uint size)
        {
            return AllocateMemory(size);
        }

        public IntPtr MakeAbsolute(IntPtr address)
        {
            return new IntPtr(DiagnosticsProcess.MainModule.BaseAddress.ToInt64() + address.ToInt64());
        }

        public IntPtr MakeRelative(IntPtr address)
        {
            return new IntPtr(address.ToInt64() - DiagnosticsProcess.MainModule.BaseAddress.ToInt64());
        }

        public IntPtr MakeAbsoluteAddress(IntPtr address)
        {
            return new IntPtr(DiagnosticsProcess.MainModule.BaseAddress.ToInt64() + address.ToInt64());
        }

        public IntPtr MakeRelativeAddress(IntPtr address)
        {
            return new IntPtr(address.ToInt64() - DiagnosticsProcess.MainModule.BaseAddress.ToInt64());
        }

        public uint MakeAbsolute(uint address)
        {
            return (uint)MakeAbsolute((IntPtr)address);
        }

        public uint MakeRelative(uint address)
        {
            return (uint)MakeRelative((IntPtr)address);
        }

        public uint MakeAbsoluteAddress(uint address)
        {
            return (uint)MakeAbsolute((IntPtr)address);
        }

        public uint MakeRelativeAddress(uint address)
        {
            return (uint)MakeRelative((IntPtr)address);
        }

        public IntPtr GetAbsolute(IntPtr address)
        {
            return new IntPtr(DiagnosticsProcess.MainModule.BaseAddress.ToInt64() + address.ToInt64());
        }

        public IntPtr GetRelative(IntPtr address)
        {
            return new IntPtr(address.ToInt64() - DiagnosticsProcess.MainModule.BaseAddress.ToInt64());
        }

        public IntPtr GetAbsoluteAddress(IntPtr address)
        {
            return new IntPtr(DiagnosticsProcess.MainModule.BaseAddress.ToInt64() + address.ToInt64());
        }

        public IntPtr GetRelativeAddress(IntPtr address)
        {
            return new IntPtr(address.ToInt64() - DiagnosticsProcess.MainModule.BaseAddress.ToInt64());
        }

        public uint GetAbsolute(uint address)
        {
            return (uint)MakeAbsolute((IntPtr)address);
        }

        public uint GetRelative(uint address)
        {
            return (uint)MakeRelative((IntPtr)address);
        }

        public uint GetAbsoluteAddress(uint address)
        {
            return (uint)MakeAbsolute((IntPtr)address);
        }

        public uint GetRelativeAddress(uint address)
        {
            return (uint)MakeRelative((IntPtr)address);
        }

        public void Write<T>(IntPtr address, T[] array)
        {
            var valuesInBytes = new byte[MarshalType<T>.Size * array.Length];

            for (var i = 0; i < array.Length; i++)
            {
                var offsetInArray = MarshalType<T>.Size * i;
                Buffer.BlockCopy(MarshalType<T>.ObjectToByteArray(array[i]), 0, valuesInBytes, offsetInArray, MarshalType<T>.Size);
            }

            WriteBytes(address, valuesInBytes);
        }

        public void Write<T>(IntPtr address, T val)
        {
            Write(address, new T[1] { val });
        }

        public void Execute(IntPtr address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            string assemblyCode = "";

            if (callingConvention.Equals(CallingConvention.Stdcall))
            {
                var marshalledParameters = parameters.Select(p => MarshalValue.Marshal(this, p)).Cast<IMarshalledValue>().ToArray();
                var ret = new StringBuilder();

                foreach (var parameter in marshalledParameters.Reverse())
                {
                    ret.AppendLine("push " + parameter.Reference);
                }

                assemblyCode = $"{ret}\ncall {address}\nretn\n";
            }
            else if (callingConvention.Equals(CallingConvention.Cdecl))
            {
                var marshalledParameters = parameters.Select(p => MarshalValue.Marshal(this, p)).Cast<IMarshalledValue>().ToArray();
                var ret = new StringBuilder();

                foreach (var parameter in marshalledParameters.Reverse())
                {
                    ret.AppendLine("push " + parameter.Reference);
                }

                assemblyCode = $"{ret}\ncall {address}\nadd esp, {marshalledParameters.Length * 4}\nretn\n";
            }
            else if (callingConvention.Equals(CallingConvention.Fastcall))
            {
                var marshalledParameters = parameters.Select(p => MarshalValue.Marshal(this, p)).Cast<IMarshalledValue>().ToArray();
                var ret = new StringBuilder();
                List<IntPtr> paramList = new List<IntPtr>();

                foreach (var param in marshalledParameters)
                {
                    paramList.Add(param.Reference);
                }

                if (paramList.Count > 0)
                {
                    ret.AppendLine("mov ecx, " + paramList[0]);
                    paramList.RemoveAt(0);
                }

                if (paramList.Count > 0)
                {
                    ret.AppendLine("mov edx, " + paramList[0]);
                    paramList.RemoveAt(0);
                }

                paramList.Reverse();

                foreach (var parameter in paramList)
                {
                    ret.AppendLine("push " + parameter);
                }

                assemblyCode = $"{ret}\ncall {address}\nretn\n";
            }
            else if (callingConvention.Equals(CallingConvention.Thiscall))
            {
                var marshalledParameters = parameters.Select(p => MarshalValue.Marshal(this, p)).Cast<IMarshalledValue>().ToArray();
                var ret = new StringBuilder();
                List<IntPtr> paramList = new List<IntPtr>();

                foreach (var param in marshalledParameters)
                {
                    paramList.Add(param.Reference);
                }

                if (paramList.Count > 0)
                {
                    ret.AppendLine("mov ecx, " + paramList[0]);
                    paramList.RemoveAt(0);
                }

                paramList.Reverse();

                foreach (var parameter in paramList)
                {
                    ret.AppendLine("push " + parameter);
                }

                assemblyCode = $"{ret}\ncall {address}\nretn\n";
            }

            byte[] compiled = Binarysharp.Assemblers.Fasm.FasmNet.Assemble("use32\norg 0x0\n" + assemblyCode);

            IntPtr remoteThread = IntPtr.Zero;
            IntPtr allocatedMemoryAddress = VirtualAllocEx(ProcessHandle, IntPtr.Zero, (uint)compiled.Length, MEM_COMMIT | MEM_RESERVE, 0x40);

            byte[] newCompiled = Binarysharp.Assemblers.Fasm.FasmNet.Assemble(string.Format("use32\norg 0x{0:X8}\n", allocatedMemoryAddress.ToInt64()) + assemblyCode);

            if (WriteMethod.Equals(MemoryMethod.KERNEL32))
            {
                WriteProcessMemory(ProcessHandle, allocatedMemoryAddress, newCompiled, (uint)newCompiled.Length, 0);
            }
            else if (WriteMethod.Equals(MemoryMethod.NTDLL))
            {
                uint bytesWritten = 0;
                NtWriteVirtualMemory(ProcessHandle, allocatedMemoryAddress, newCompiled, (uint)newCompiled.Length, ref bytesWritten);
            }

            if (assemblyInjectionMethod.Equals(AssemblyInjectionMethod.ClassicCreateThread))
            {
                CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, allocatedMemoryAddress, IntPtr.Zero, 0, IntPtr.Zero);
            }
            else if (assemblyInjectionMethod.Equals(AssemblyInjectionMethod.ClassicRtlCreateUserThread))
            {
                RtlCreateUserThread(ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, allocatedMemoryAddress, IntPtr.Zero, ref remoteThread, IntPtr.Zero);
            }
            else if (assemblyInjectionMethod.Equals(AssemblyInjectionMethod.ClassicNtCreateThreadEx))
            {
                NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, ProcessHandle, allocatedMemoryAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            }
        }

        public void Execute(string moduleName, string functionName, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(GetFunction(moduleName, functionName), callingConvention, assemblyInjectionMethod, parameters);
        }

        public void Execute(uint address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute((IntPtr)address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void ExecuteFunction(IntPtr address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void ExecuteFunction(string moduleName, string functionName, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(moduleName, functionName, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void ExecuteFunction(uint address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void CallFunction(IntPtr address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void CallFunction(string moduleName, string functionName, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(moduleName, functionName, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void CallFunction(uint address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void InvokeFunction(IntPtr address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void InvokeFunction(string moduleName, string functionName, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(moduleName, functionName, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void InvokeFunction(uint address, CallingConvention callingConvention, AssemblyInjectionMethod assemblyInjectionMethod, params dynamic[] parameters)
        {
            Execute(address, callingConvention, assemblyInjectionMethod, parameters);
        }

        public void InjectAssemblyCode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            byte[] compiled = Binarysharp.Assemblers.Fasm.FasmNet.Assemble("use32\norg 0x0\n" + asm);

            IntPtr remoteThread = IntPtr.Zero;
            IntPtr allocatedMemoryAddress = VirtualAllocEx(ProcessHandle, IntPtr.Zero, (uint)compiled.Length, MEM_COMMIT | MEM_RESERVE, 0x40);

            byte[] newCompiled = Binarysharp.Assemblers.Fasm.FasmNet.Assemble(string.Format("use32\norg 0x{0:X8}\n", address == IntPtr.Zero ? allocatedMemoryAddress.ToInt64() : address.ToInt64()) + asm);

            if (WriteMethod.Equals(MemoryMethod.KERNEL32))
            {
                WriteProcessMemory(ProcessHandle, allocatedMemoryAddress, newCompiled, (uint)newCompiled.Length, 0);
            }
            else if (WriteMethod.Equals(MemoryMethod.NTDLL))
            {
                uint bytesWritten = 0;
                NtWriteVirtualMemory(ProcessHandle, allocatedMemoryAddress, newCompiled, (uint)newCompiled.Length, ref bytesWritten);
            }

            if (method.Equals(AssemblyInjectionMethod.ClassicCreateThread))
            {
                CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, allocatedMemoryAddress, IntPtr.Zero, 0, IntPtr.Zero);
            }
            else if (method.Equals(AssemblyInjectionMethod.ClassicRtlCreateUserThread))
            {
                RtlCreateUserThread(ProcessHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, allocatedMemoryAddress, IntPtr.Zero, ref remoteThread, IntPtr.Zero);
            }
            else if (method.Equals(AssemblyInjectionMethod.ClassicNtCreateThreadEx))
            {
                NtCreateThreadEx(ref remoteThread, 0x1FFFFF, IntPtr.Zero, ProcessHandle, allocatedMemoryAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            }
        }

        public void InjectAsmCode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectAssembly(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectAsm(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectAssemblyString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectShell(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectShellcode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectShellcodeString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void InjectShellString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteAsmCode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteAssembly(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteAsm(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteAssemblyString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteShell(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteShellcode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteShellcodeString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void ExecuteShellString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunAsmCode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunAssembly(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunAsm(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunAssemblyString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunShell(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunShellcode(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunShellcodeString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public void RunShellString(string asm, IntPtr address, AssemblyInjectionMethod method = AssemblyInjectionMethod.ClassicCreateThread)
        {
            InjectAssemblyCode(asm, address, method);
        }

        public bool Is64Bit()
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }
            
            bool isWow64Process = false;
            bool theResult = IsWow64Process(ProcessHandle, out isWow64Process);
            return theResult && !isWow64Process;
        }

        public bool Is64BitProcess()
        {
            return Is64Bit();
        }

        public bool Is64Bits()
        {
            return Is64Bit();
        }

        public bool Is64BitsProcess()
        {
            return Is64Bit();
        }

        public bool Is32Bit()
        {
            return !Is64Bit();
        }

        public bool Is32Bits()
        {
            return !Is64Bit();
        }

        public bool Is32BitProcess()
        {
            return !Is64Bit();
        }

        public bool Is32BitsProcess()
        {
            return !Is64Bit();
        }
    }
}