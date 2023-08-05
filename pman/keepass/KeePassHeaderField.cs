namespace pman.keepass;

public class KeePassHeaderField<T> where T: Enum
{
    private const int HeaderLength = 5;

    public readonly T FieldType;
    public readonly byte[]? FieldData;

    internal int Length { get; private set; }

    internal KeePassHeaderField(byte[] bytes, int offset)
    {
        FieldType = ValidateFieldType(bytes[offset]);
        Length = 1;
        var size = ReadFieldSize(bytes, offset + Length);
        if (size == 0)
            return;
        if (offset + size > bytes.Length)
            throw new FormatException(KeePassDb.FileCorrupted);
        FieldData = new byte[size];
        Array.Copy(bytes, offset + Length, FieldData, 0, size);
        Length += size;
    }

    private static T ValidateFieldType(byte b)
    {
        Type underlyingType = Enum.GetUnderlyingType(typeof(T));
        var value = Convert.ChangeType(b, underlyingType);
        if (Enum.IsDefined(typeof(T), value))
            return (T)value;
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

    public static Dictionary<T, KeePassHeaderField<T>> ReadHeaderFields(byte[] bytes, int offset, out int outOffset, string headerName, T endOfHeader)
    {
        var headerFields = new Dictionary<T, KeePassHeaderField<T>>();
        var maxLength = bytes.Length - HeaderLength;
        while (offset <= maxLength)
        {
            var field = new KeePassHeaderField<T>(bytes, offset);
            offset += field.Length;
            if (field.FieldType.Equals(endOfHeader))
                break;
            if (headerFields.ContainsKey(field.FieldType))
                throw new FormatException($"duplicate {headerName} field type");
            headerFields[field.FieldType] = field;
        }

        outOffset = offset;
        
        return headerFields;
    }
}