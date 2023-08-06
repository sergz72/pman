using System.Security.Cryptography;

namespace pman.keepass;

public class KeePassDbBlock
{
    private const int HmacHashLength = 32;
    internal const int HeaderLength = HmacHashLength + 4;
    public readonly int Length;
    private readonly byte[] _hmac;
    private readonly byte[]? _data;
    
    public KeePassDbBlock(byte[] bytes, int offset)
    {
        _hmac = new byte[HmacHashLength];
        Array.Copy(bytes, offset, _hmac, 0, HmacHashLength);
        var dataOffset = offset + HeaderLength;
        var dataLength = BitConverter.ToInt32(bytes, offset + HmacHashLength);
        Length = dataLength + HeaderLength;
        if ((dataLength < 0) || (offset + Length > bytes.Length))
            throw new FormatException("wrong db block size");
        if (dataLength <= 0) return;
        _data = new byte[dataLength];
        Array.Copy(bytes, dataOffset, _data, 0, dataLength);
    }

    public int Validate(KeePassDbHeader header, long blockNumber)
    {
        var hmac256 = CalculateHmac256(header, blockNumber);
        if (!hmac256.SequenceEqual(_hmac))
            throw new FormatException($"db block {blockNumber} HMAC does not match");
        return _data!.Length;
    }

    private byte[] CalculateHmac256(KeePassDbHeader header, long blockNumber)
    {
        var blockNumberBytes = BitConverter.GetBytes(blockNumber);
        var transformedKey = header.TransformHmacKey(blockNumberBytes);
        HMACSHA256 hmacsha256 = new HMACSHA256(transformedKey);
        Array.Clear(transformedKey, 0, transformedKey.Length);
        hmacsha256.TransformBlock(blockNumberBytes, 0, blockNumberBytes.Length, null, 0);
        var lengthBytes = BitConverter.GetBytes(_data!.Length);
        hmacsha256.TransformBlock(lengthBytes, 0, lengthBytes.Length, null, 0);
        hmacsha256.TransformFinalBlock(_data, 0, _data.Length);
        return hmacsha256.Hash!;
    }

    public bool IsEmpty() => _data == null;

    public byte[] Decrypt(KeePassDbHeader header)
    {
        return header.DecryptData(_data!);
    }
}