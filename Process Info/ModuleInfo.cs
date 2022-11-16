﻿using System;
using System.Diagnostics;

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

        public ModuleInfo(ProcessModule module, IntPtr baseAddress, uint memorySize, uint processId, Process diagnosticsProcess)
        {
            Module = module;
            BaseAddress = baseAddress;
            MemorySize = memorySize;
            IntBaseAddress = (uint)baseAddress;
            ProcessId = processId;
            DiagnosticsProcess = diagnosticsProcess;
        }
    }
}