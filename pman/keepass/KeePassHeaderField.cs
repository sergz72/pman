namespace pman.keepass;

internal sealed class KeePassHeaderField<T>: IDisposable
    where T: Enum
{
    private const int HeaderLength = 5;

    private readonly T _fieldType;
    internal readonly byte[]? FieldData;

    private int _length;

    private KeePassHeaderField(byte[] bytes, int offset)
    {
        _fieldType = ValidateFieldType(bytes[offset]);
        _length = 1;
        var size = ReadFieldSize(bytes, offset + _length);
        if (size == 0)
            return;
        if (offset + size > bytes.Length)
            throw new FormatException(KeePassDb.FileCorrupted);
        FieldData = new byte[size];
        Array.Copy(bytes, offset + _length, FieldData, 0, size);
        _length += size;
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
        _length += 4;
        if (size < 0)
            throw new FormatException(KeePassDb.FileCorrupted);
        return size;
    }

    internal static Dictionary<T, KeePassHeaderField<T>> ReadHeaderFields(byte[] bytes, int offset, out int outOffset, string headerName, T endOfHeader)
    {
        var headerFields = new Dictionary<T, KeePassHeaderField<T>>();
        var maxLength = bytes.Length - HeaderLength;
        while (offset <= maxLength)
        {
            var field = new KeePassHeaderField<T>(bytes, offset);
            offset += field._length;
            if (field._fieldType.Equals(endOfHeader))
                break;
            if (headerFields.ContainsKey(field._fieldType))
                throw new FormatException($"duplicate {headerName} field type");
            headerFields[field._fieldType] = field;
        }

        outOffset = offset;
        
        return headerFields;
    }
    
    public void Dispose()
    {
        if (FieldData != null)
            Array.Clear(FieldData, 0, FieldData.Length);
    }
}