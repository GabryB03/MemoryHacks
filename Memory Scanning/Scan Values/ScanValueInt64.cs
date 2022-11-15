using System;

namespace MemoryHacks
{
    public class ScanValueInt64
    {
        public IntPtr Address { get; private set; }
        public long Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueInt64(IntPtr address, long value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}