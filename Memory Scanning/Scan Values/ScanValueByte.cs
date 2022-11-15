using System;

namespace MemoryHacks
{
    public class ScanValueByte
    {
        public IntPtr Address { get; private set; }
        public byte Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueByte(IntPtr address, byte value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}