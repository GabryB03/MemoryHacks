using System.Runtime.InteropServices;
using System.Text;
using System;

namespace MemoryHacks
{
    public static class MarshalType<T>
    {
        public static bool CanBeStoredInRegisters { get; private set; }
        public static bool IsIntPtr { get; private set; }
        public static Type RealType { get; private set; }
        public static int Size { get; private set; }
        public static TypeCode TypeCode { get; private set; }
        static MarshalType()
        {
            IsIntPtr = typeof(T) == typeof(IntPtr);
            RealType = typeof(T);
            Size = TypeCode == TypeCode.Boolean ? 1 : Marshal.SizeOf(RealType);
            TypeCode = Type.GetTypeCode(RealType);
            CanBeStoredInRegisters =
                IsIntPtr ||
#if x64
                TypeCode == TypeCode.Int64 ||
                TypeCode == TypeCode.UInt64 ||
#endif
 TypeCode == TypeCode.Boolean ||
                TypeCode == TypeCode.Byte ||
                TypeCode == TypeCode.Char ||
                TypeCode == TypeCode.Int16 ||
                TypeCode == TypeCode.Int32 ||
                TypeCode == TypeCode.Int64 ||
                TypeCode == TypeCode.SByte ||
                TypeCode == TypeCode.Single ||
                TypeCode == TypeCode.UInt16 ||
                TypeCode == TypeCode.UInt32;
        }

        public static byte[] ObjectToByteArray(T obj)
        {
            switch (TypeCode)
            {
                case TypeCode.Object:
                    if (IsIntPtr)
                    {
                        switch (Size)
                        {
                            case 4:
                                return BitConverter.GetBytes(((IntPtr)(object)obj).ToInt32());
                            case 8:
                                return BitConverter.GetBytes(((IntPtr)(object)obj).ToInt64());
                        }
                    }
                    break;
                case TypeCode.Boolean:
                    return BitConverter.GetBytes((bool)(object)obj);
                case TypeCode.Char:
                    return Encoding.UTF8.GetBytes(new[] { (char)(object)obj });
                case TypeCode.Double:
                    return BitConverter.GetBytes((double)(object)obj);
                case TypeCode.Int16:
                    return BitConverter.GetBytes((short)(object)obj);
                case TypeCode.Int32:
                    return BitConverter.GetBytes((int)(object)obj);
                case TypeCode.Int64:
                    return BitConverter.GetBytes((long)(object)obj);
                case TypeCode.Single:
                    return BitConverter.GetBytes((float)(object)obj);
                case TypeCode.String:
                    throw new InvalidCastException("This method doesn't support string conversion.");
                case TypeCode.UInt16:
                    return BitConverter.GetBytes((ushort)(object)obj);
                case TypeCode.UInt32:
                    return BitConverter.GetBytes((uint)(object)obj);
                case TypeCode.UInt64:
                    return BitConverter.GetBytes((ulong)(object)obj);

            }

            using (var unmanaged = new LocalUnmanagedMemory(Size))
            {
                unmanaged.Write(obj);
                return unmanaged.Read();
            }
        }

        public static T ByteArrayToObject(byte[] byteArray, int index = 0)
        {
            switch (TypeCode)
            {
                case TypeCode.Object:
                    if (IsIntPtr)
                    {
                        switch (byteArray.Length)
                        {
                            case 1:
                                return (T)(object)new IntPtr(BitConverter.ToInt32(new byte[] { byteArray[index], 0x0, 0x0, 0x0 }, index));
                            case 2:
                                return (T)(object)new IntPtr(BitConverter.ToInt32(new byte[] { byteArray[index], byteArray[index + 1], 0x0, 0x0 }, index));
                            case 4:
                                return (T)(object)new IntPtr(BitConverter.ToInt32(byteArray, index));
                            case 8:
                                return (T)(object)new IntPtr(BitConverter.ToInt64(byteArray, index));
                        }
                    }
                    break;
                case TypeCode.Boolean:
                    return (T)(object)BitConverter.ToBoolean(byteArray, index);
                case TypeCode.Byte:
                    return (T)(object)byteArray[index];
                case TypeCode.Char:
                    return (T)(object)Encoding.UTF8.GetChars(byteArray)[index];
                case TypeCode.Double:
                    return (T)(object)BitConverter.ToDouble(byteArray, index);
                case TypeCode.Int16:
                    return (T)(object)BitConverter.ToInt16(byteArray, index);
                case TypeCode.Int32:
                    return (T)(object)BitConverter.ToInt32(byteArray, index);
                case TypeCode.Int64:
                    return (T)(object)BitConverter.ToInt64(byteArray, index);
                case TypeCode.Single:
                    return (T)(object)BitConverter.ToSingle(byteArray, index);
                case TypeCode.String:
                    throw new InvalidCastException("This method doesn't support string conversion.");
                case TypeCode.UInt16:
                    return (T)(object)BitConverter.ToUInt16(byteArray, index);
                case TypeCode.UInt32:
                    return (T)(object)BitConverter.ToUInt32(byteArray, index);
                case TypeCode.UInt64:
                    return (T)(object)BitConverter.ToUInt64(byteArray, index);
            }

            using (var unmanaged = new LocalUnmanagedMemory(Size))
            {
                unmanaged.Write(byteArray, index);
                return unmanaged.Read<T>();
            }
        }

        public static T PtrToObject(MemoryHacksLib mem, IntPtr pointer)
        {
            return ByteArrayToObject(CanBeStoredInRegisters ? BitConverter.GetBytes(pointer.ToInt64()) : mem.ReadByteArray(pointer, (uint) Size));
        }
    }
}