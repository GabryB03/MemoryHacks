using System;

namespace MemoryHacks
{
    public interface IMarshalledValue : IDisposable
    {
        IntPtr Reference { get; }
    }
}