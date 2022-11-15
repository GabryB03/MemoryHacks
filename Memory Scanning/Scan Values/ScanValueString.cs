using System;

namespace MemoryHacks
{
    public class ScanValueString
    {
        public IntPtr Address { get; private set; }
        public string Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueString(IntPtr address, string value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}