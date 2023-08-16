using pman.crypto;

namespace pman.keepass;

internal sealed class KeePassInnerHeader: IDisposable
{
    internal enum CrsAlgorithm
    {
        Null,
        ArcFourVariant,
        Salsa20,
        ChaCha20,
        Count,
    }
    
    internal enum HeaderFieldType
    {
        EndOfHeader = 0,
        InnerRandomStreamId = 1,
        InnerRandomStreamKey = 2,
        Binary = 3
    }

    internal readonly Dictionary<HeaderFieldType, KeePassHeaderField<HeaderFieldType>> HeaderFields;
    internal readonly int DataOffset;
    private readonly ChaCha20 _decryptor;
    
    internal KeePassInnerHeader(byte[] bytes)
    {
        HeaderFields = KeePassHeaderField<HeaderFieldType>.ReadHeaderFields(bytes, 0, out var offset, "inner header", HeaderFieldType.EndOfHeader);
        _decryptor = CreateDecryptor();
        DataOffset = offset;
    }

    private ChaCha20 CreateDecryptor()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.InnerRandomStreamId, out var streamId))
            throw new FormatException("inner header stream id is missing");
        if (streamId.FieldData is not { Length: 4 } || BitConverter.ToInt32(streamId.FieldData) != (int)CrsAlgorithm.ChaCha20)
            throw new FormatException("inner header stream id is wrong");
        if (!HeaderFields.TryGetValue(HeaderFieldType.InnerRandomStreamKey, out var streamKey))
            throw new FormatException("inner header stream key is missing");
        if (streamKey.FieldData is not { Length: 64 })
            throw new FormatException("inner header stream key is wrong");
        var hash = System.Security.Cryptography.SHA512.HashData(streamKey.FieldData);
        var key = new byte[32];
        var iv = new byte[12];
        Array.Copy(hash, 0, key, 0, key.Length);
        Array.Copy(hash, key.Length, iv, 0, iv.Length);
        return new ChaCha20(key, iv);
    }

    internal void Decrypt(byte[] data)
    {
        _decryptor.Encrypt(data);
    }

    public void Dispose()
    {
        foreach (var field in HeaderFields.Values)
            field.Dispose();
        _decryptor.Dispose();
    }
}