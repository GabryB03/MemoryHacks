using System;

namespace MemoryHacks
{
    public class ScanValueByteArray
    {
        public IntPtr Address { get; private set; }
        public byte[] Value { get; private set; }
        public string Module { get; private set; }

        public ScanValueByteArray(IntPtr address, byte[] value, string module)
        {
            Address = address;
            Value = value;
            Module = module;
        }
    }
}