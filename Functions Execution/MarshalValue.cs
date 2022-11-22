using System;
using System.Text;

namespace MemoryHacks
{
    public static class MarshalValue
    {
        public static MarshalledValue<T> Marshal<T>(MemoryHacksLib mem, T value)
        {
            return new MarshalledValue<T>(mem, value);
        }
    }

    public class MarshalledValue<T> : IMarshalledValue
    {
        protected readonly MemoryHacksLib Memory;
        public IntPtr Reference { get; private set; }
        public T Value { get; private set; }

        public MarshalledValue(MemoryHacksLib mem, T value)
        {
            Memory = mem;
            Value = value;
            Marshal();
        }

        ~MarshalledValue()
        {
            Dispose();
        }

        public void Dispose()
        {
            Reference = IntPtr.Zero;
            GC.SuppressFinalize(this);
        }

        private void Marshal()
        {
            if (typeof(T) == typeof(string))
            {
                var text = Value.ToString();
                IntPtr address = Memory.Allocate((uint) (text.Length + 1));
                // Memory.WriteStringUTF8(address, text + '\0');
                Memory.WriteBytes(address, Combine(Encoding.UTF8.GetBytes(text), new byte[1] { 0x00 }));
                Reference = address;
            }
            else
            {
                var byteArray = MarshalType<T>.ObjectToByteArray(Value);

                if (MarshalType<T>.CanBeStoredInRegisters)
                {
                    Reference = MarshalType<IntPtr>.ByteArrayToObject(byteArray);
                }
                else
                {
                    IntPtr address = Memory.Allocate((uint) MarshalType<T>.Size);
                    Memory.Write(Memory.MakeRelative(address), Value);
                    Reference = address;
                }
            }
        }

        private byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];

            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);

            return ret;
        }
    }
}