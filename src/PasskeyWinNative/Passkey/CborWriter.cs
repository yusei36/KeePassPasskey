using System.IO;
using System.Text;

namespace PasskeyWinNative.Passkey
{
    internal sealed class CborWriter
    {
        private readonly MemoryStream _stream;

        internal CborWriter()
        {
            _stream = new MemoryStream();
        }

        internal void WriteUnsignedInt(ulong value)
        {
            WriteTypeAndValue(0, value);
        }

        internal void WriteNegativeInt(long value)
        {
            // CBOR negative int encodes -1-n, so -7 becomes type 1, value 6
            WriteTypeAndValue(1, (ulong)(-1 - value));
        }

        internal void WriteByteString(byte[] data)
        {
            WriteTypeAndValue(2, (ulong)data.Length);
            _stream.Write(data, 0, data.Length);
        }

        internal void WriteTextString(string value)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            WriteTypeAndValue(3, (ulong)bytes.Length);
            _stream.Write(bytes, 0, bytes.Length);
        }

        internal void WriteMapStart(int count)
        {
            WriteTypeAndValue(5, (ulong)count);
        }

        internal void WriteEmptyMap()
        {
            WriteMapStart(0);
        }

        internal byte[] ToArray()
        {
            return _stream.ToArray();
        }

        private void WriteTypeAndValue(byte majorType, ulong value)
        {
            var type = (byte)(majorType << 5);
            if (value < 24)
            {
                _stream.WriteByte((byte)(type | (byte)value));
            }
            else if (value <= byte.MaxValue)
            {
                _stream.WriteByte((byte)(type | 24));
                _stream.WriteByte((byte)value);
            }
            else if (value <= ushort.MaxValue)
            {
                _stream.WriteByte((byte)(type | 25));
                _stream.WriteByte((byte)(value >> 8));
                _stream.WriteByte((byte)value);
            }
            else if (value <= uint.MaxValue)
            {
                _stream.WriteByte((byte)(type | 26));
                _stream.WriteByte((byte)(value >> 24));
                _stream.WriteByte((byte)(value >> 16));
                _stream.WriteByte((byte)(value >> 8));
                _stream.WriteByte((byte)value);
            }
            else
            {
                _stream.WriteByte((byte)(type | 27));
                _stream.WriteByte((byte)(value >> 56));
                _stream.WriteByte((byte)(value >> 48));
                _stream.WriteByte((byte)(value >> 40));
                _stream.WriteByte((byte)(value >> 32));
                _stream.WriteByte((byte)(value >> 24));
                _stream.WriteByte((byte)(value >> 16));
                _stream.WriteByte((byte)(value >> 8));
                _stream.WriteByte((byte)value);
            }
        }
    }
}
