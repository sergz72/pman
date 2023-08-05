namespace pman.keepass;

public class KeePassInnerHeader
{
    public enum HeaderFieldType
    {
        EndOfHeader = 0,
        InnerRandomStreamId = 1,
        InnerRandomStreamKey = 2,
        Binary = 3
    }

    public struct HeaderField
    {
        public readonly HeaderFieldType FieldType;
        public readonly byte[]? FieldData;

        internal int Length { get; private set; }

        internal HeaderField(byte[] bytes, int offset)
        {
            FieldType = ValidateFieldType(bytes[offset]);
            Length = 1;
            var size = ReadFieldSize(bytes, offset + Length);
            if (size <= 0) return;
            FieldData = new byte[size];
            Array.Copy(bytes, offset + Length, FieldData, 0, size);
            Length += size;
        }

        private static HeaderFieldType ValidateFieldType(byte b)
        {
            if (Enum.IsDefined(typeof(HeaderFieldType), (Int32)b))
                return (HeaderFieldType)b;
            throw new FormatException(KeePassDb.FileCorrupted);
        }

        private int ReadFieldSize(byte[] bytes, int offset)
        {
            var size = BitConverter.ToInt32(bytes, offset);
            Length += 4;
            if (size < 0)
                throw new FormatException(KeePassDb.FileCorrupted);
            return size;
        }
    }
    
    internal readonly Dictionary<HeaderFieldType, HeaderField> HeaderFields;
    internal readonly int DataOffset;
    
    public KeePassInnerHeader(byte[] bytes)
    {
        HeaderFields = new Dictionary<HeaderFieldType, HeaderField>();
        DataOffset = 0;
        for (;;)
        {
            var field = new HeaderField(bytes, DataOffset);
            DataOffset += field.Length;
            if (field.FieldType == HeaderFieldType.EndOfHeader)
                break;
            if (HeaderFields.ContainsKey(field.FieldType))
                throw new FormatException("duplicate inner header field type");
            HeaderFields[field.FieldType] = field;
        }
    }
}