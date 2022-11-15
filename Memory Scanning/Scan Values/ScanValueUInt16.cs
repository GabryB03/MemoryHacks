using System;

namespace MemoryHacks
{
    public class ScanValueUInt16
    {
        public IntPtr Address { get; private set; }
        public ushort Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueUInt16(IntPtr address, ushort value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}