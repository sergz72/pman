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

    internal readonly Dictionary<HeaderFieldType, KeePassHeaderField<HeaderFieldType>> HeaderFields;
    internal readonly int DataOffset;
    
    public KeePassInnerHeader(byte[] bytes)
    {
        HeaderFields = KeePassHeaderField<HeaderFieldType>.ReadHeaderFields(bytes, 0, out var offset, "inner header", HeaderFieldType.EndOfHeader);
        DataOffset = offset;
    }
}