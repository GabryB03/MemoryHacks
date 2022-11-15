using System;

namespace MemoryHacks
{
    public class ScanValueUInt64
    {
        public IntPtr Address { get; private set; }
        public ulong Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueUInt64(IntPtr address, ulong value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}