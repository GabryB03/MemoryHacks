using System;

namespace MemoryHacks
{
    public class ScanValueInt16
    {
        public IntPtr Address { get; private set; }
        public short Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueInt16(IntPtr address, short value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}