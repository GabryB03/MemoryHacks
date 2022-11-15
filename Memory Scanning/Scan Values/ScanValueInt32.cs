using System;

namespace MemoryHacks
{
    public class ScanValueInt32
    {
        public IntPtr Address { get; private set; }
        public int Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueInt32(IntPtr address, int value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}