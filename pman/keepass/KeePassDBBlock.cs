using System.Security.Cryptography;

namespace pman.keepass;

public class KeePassDbBlock
{
    private const int HmacHashLength = 32;
    internal const int HeaderLength = HmacHashLength + 4;
    public readonly int Length;
    internal readonly int DataLength;
    private readonly int _dataOffset;
    
    public KeePassDbBlock(byte[] bytes, int offset, KeePassDbHeader header, long blockNumber)
    {
        _dataOffset = offset + HeaderLength;
        DataLength = BitConverter.ToInt32(bytes, offset + HmacHashLength);
        Length = DataLength + HeaderLength;
        if ((DataLength < 0) || (offset + Length > bytes.Length))
            throw new FormatException("wrong db block size");
        ValidateDbBlock(bytes, offset, header, blockNumber);
    }

    private void ValidateDbBlock(byte[] bytes, int offset, KeePassDbHeader header, long blockNumber)
    {
        var hmac256 = CalculateHmac256(bytes, header, blockNumber);
        if (!hmac256.SequenceEqual(new ArraySegment<byte>(bytes, offset, HmacHashLength)))
            throw new FormatException(string.Format("db block {0} HMAC does not match", blockNumber));
    }

    private byte[] CalculateHmac256(byte[] bytes, KeePassDbHeader header, long blockNumber)
    {
        var blockNumberBytes = BitConverter.GetBytes(blockNumber);
        var transformedKey = header.TransformHmacKey(blockNumberBytes);
        HMACSHA256 hmacsha256 = new HMACSHA256(transformedKey);
        hmacsha256.TransformBlock(blockNumberBytes, 0, blockNumberBytes.Length, null, 0);
        var lengthBytes = BitConverter.GetBytes(DataLength);
        hmacsha256.TransformBlock(lengthBytes, 0, lengthBytes.Length, null, 0);
        hmacsha256.TransformFinalBlock(bytes, _dataOffset, DataLength);
        return hmacsha256.Hash!;
    }

    public bool IsEmpty() => DataLength == 0;

    public byte[] Decrypt(byte[] bytes, KeePassDbHeader header)
    {
        return header.Decrypt(bytes, _dataOffset, DataLength);
    }
}