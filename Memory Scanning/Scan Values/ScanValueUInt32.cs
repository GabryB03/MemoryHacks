using System;

namespace MemoryHacks
{
    public class ScanValueUInt32
    {
        public IntPtr Address { get; private set; }
        public uint Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueUInt32(IntPtr address, uint value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}