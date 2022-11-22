using System.Runtime.InteropServices;
using System;

namespace MemoryHacks
{
    public class LocalUnmanagedMemory : IDisposable
    {
        public IntPtr Address { get; private set; }
        public int Size { get; private set; }

        public LocalUnmanagedMemory(int size)
        {
            Size = size;
            Address = Marshal.AllocHGlobal(Size);
        }

        ~LocalUnmanagedMemory()
        {
            Dispose();
        }

        public virtual void Dispose()
        {
            Marshal.FreeHGlobal(Address);
            Address = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        public T Read<T>()
        {
            return (T)Marshal.PtrToStructure(Address, typeof(T));
        }

        public byte[] Read()
        {
            var bytes = new byte[Size];
            Marshal.Copy(Address, bytes, 0, Size);
            return bytes;
        }

        public override string ToString()
        {
            return string.Format("Size = {0:X}", Size);
        }

        public void Write(byte[] byteArray, int index = 0)
        {
            Marshal.Copy(byteArray, index, Address, Size);
        }

        public void Write<T>(T data)
        {
            Marshal.StructureToPtr(data, Address, false);
        }
    }
}