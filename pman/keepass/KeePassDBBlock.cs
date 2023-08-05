using System.Security.Cryptography;

namespace pman.keepass;

public class KeePassDbBlock
{
    private const int HmacHashLength = 32;
    internal const int HeaderLength = HmacHashLength + 4;
    public readonly int Length;
    private readonly int _dataLength;
    private readonly int _dataOffset;
    
    public KeePassDbBlock(byte[] bytes, int offset, KeePassDbHeader header, long blockNumber)
    {
        _dataOffset = offset + HeaderLength;
        _dataLength = BitConverter.ToInt32(bytes, offset + HmacHashLength);
        Length = _dataLength + HeaderLength;
        if ((_dataLength < 0) || (offset + Length > bytes.Length))
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
        var transformedKey = KeePassDbHeader.TransformHmacKey(header.HmacKey, blockNumberBytes);
        HMACSHA256 hmacsha256 = new HMACSHA256(transformedKey);
        hmacsha256.TransformBlock(blockNumberBytes, 0, blockNumberBytes.Length, null, 0);
        var lengthBytes = BitConverter.GetBytes(_dataLength);
        hmacsha256.TransformBlock(lengthBytes, 0, lengthBytes.Length, null, 0);
        hmacsha256.TransformFinalBlock(bytes, _dataOffset, _dataLength);
        return hmacsha256.Hash!;
    }

    public bool IsEmpty() => _dataLength == 0;

    public byte[] Decrypt()
    {
        
    }
}