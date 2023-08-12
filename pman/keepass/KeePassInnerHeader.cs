namespace pman.keepass;

internal sealed class KeePassInnerHeader: IDisposable
{
    internal enum HeaderFieldType
    {
        EndOfHeader = 0,
        InnerRandomStreamId = 1,
        InnerRandomStreamKey = 2,
        Binary = 3
    }

    internal readonly Dictionary<HeaderFieldType, KeePassHeaderField<HeaderFieldType>> HeaderFields;
    internal readonly int DataOffset;
    
    internal KeePassInnerHeader(byte[] bytes)
    {
        HeaderFields = KeePassHeaderField<HeaderFieldType>.ReadHeaderFields(bytes, 0, out var offset, "inner header", HeaderFieldType.EndOfHeader);
        DataOffset = offset;
    }
    
    public void Dispose()
    {
        foreach (var field in HeaderFields.Values)
            field.Dispose();
    }
}