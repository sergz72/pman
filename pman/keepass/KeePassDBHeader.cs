using System.Security.Cryptography;

namespace pman.keepass;

public struct KeePassDbHeader
{
    private static readonly byte[] Minus1 = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    private static readonly byte[] AesCipherId =
    {
        0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
        0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF
    };

    public enum HeaderFieldType
    {
        EndOfHeader = 0,
        Comment = 1,
        CipherId = 2,
        CompressionFlags = 3,
        MasterSeed = 4,
        EncryptionIv = 7,
        KdfParameters = 11, // KDBX 4, superseding Transform*
        PublicCustomData = 12 // KDBX 4
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

    /// <summary>
    /// File identifier, first 32-bit value.
    /// </summary>
    private const UInt32 FileSignature1 = 0x9AA2D903;

    /// <summary>
    /// File identifier, second 32-bit value.
    /// </summary>
    private const UInt32 FileSignature2 = 0xB54BFB67;

    internal readonly uint VersionMajor;

    internal readonly uint VersionMinor;

    internal int Length { get; private set; }

    internal readonly Dictionary<HeaderFieldType, HeaderField> HeaderFields;

    private readonly byte[] _masterSeed;
    private readonly byte[] _encryptionIv;
    internal readonly VariantDictionary KdfParameters;
    private readonly byte[] _hmacKey;
    private readonly byte[] _encryptionKey;
    private readonly IEncryptionEngine _encryptionEngine;

    internal KeePassDbHeader(byte[] bytes, KeePassCredentials credentials)
    {
        var sig1 = BitConverter.ToUInt32(bytes, 0);
        var sig2 = BitConverter.ToUInt32(bytes, 4);
        if ((sig1 != FileSignature1) || (sig2 != FileSignature2))
            throw new FormatException("invalid file signature");
        var version = BitConverter.ToUInt32(bytes, 8);
        VersionMajor = version >> 16;
        if (VersionMajor != 4)
            throw new FormatException("unsupported DB version");
        VersionMinor = version & 0xFFFF;
        Length = 12;

        HeaderFields = new Dictionary<HeaderFieldType, HeaderField>();
        for (;;)
        {
            var field = new HeaderField(bytes, Length);
            Length += field.Length;
            if (field.FieldType == HeaderFieldType.EndOfHeader)
                break;
            if (HeaderFields.ContainsKey(field.FieldType))
                throw new FormatException("duplicate header field type");
            HeaderFields[field.FieldType] = field;
        }

        _masterSeed = GetMasterSeed();
        _encryptionIv = GetEncryptionIv();
        _encryptionEngine = GetEncryptionEngine();


        KdfParameters = BuildKdfParameters();

        IKeyDerivationFunction kdf = new Argon2Kdf(KdfParameters);

        var transformedKey = kdf.GetTransformedKey(credentials.Key);
        _hmacKey = CalculateHmacKey(transformedKey);
        _encryptionKey = CalculateEncryptionKey(transformedKey);

        ValidateHeader(bytes);
    }

    private IEncryptionEngine GetEncryptionEngine()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.CipherId, out var cipherId))
            throw new FormatException("cipher id header is missing");
        if (cipherId.FieldData == null || cipherId.FieldData.Length != 16)
            throw new FormatException("cipher id header is wrong");
        if (!cipherId.FieldData!.SequenceEqual(AesCipherId))
            throw new FormatException("unsupported cipher engine");
        return new AesEngine(_encryptionKey, _encryptionIv);
    }

    private byte[] CalculateEncryptionKey(byte[] transformedKey)
    {
        SHA256 sha = SHA256.Create();
        sha.TransformBlock(_masterSeed, 0, _masterSeed.Length, null, 0);
        sha.TransformFinalBlock(transformedKey, 0, transformedKey.Length);
        return sha.Hash!;
    }

    private VariantDictionary BuildKdfParameters()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.KdfParameters, out var kdfParameters))
            throw new FormatException("kdfParameters header is missing");
        return new VariantDictionary(kdfParameters.FieldData!);
    }

    private void ValidateHeader(byte[] bytes)
    {
        var sha256 = CalculateSha256(bytes);
        if (!sha256.SequenceEqual(new ArraySegment<byte>(bytes, Length, 32)))
            throw new FormatException("header hash does not match");
        var hmac256 = CalculateHmac256(bytes);
        Length += 32;
        if (!hmac256.SequenceEqual(new ArraySegment<byte>(bytes, Length, 32)))
            throw new FormatException("header HMAC does not match");
        Length += 32;
    }

    private byte[] GetMasterSeed()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.MasterSeed, out var masterSeed))
            throw new FormatException("master seed header is missing");
        if (masterSeed.FieldData == null || masterSeed.FieldData.Length != 32)
            throw new FormatException("master seed header is wrong");
        return masterSeed.FieldData!;
    }

    private byte[] GetEncryptionIv()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.EncryptionIv, out var encryptionIv))
            throw new FormatException("encryptionIv header is missing");
        if (encryptionIv.FieldData == null)
            throw new FormatException("encryptionIv header is wrong");
        return encryptionIv.FieldData!;
    }

    private byte[] CalculateHmacKey(byte[] transformedKey)
    {
        var buffer = new byte[65];
        Array.Copy(_masterSeed, buffer, _masterSeed.Length);
        Array.Copy(transformedKey, 0, buffer, _masterSeed.Length, transformedKey.Length);
        buffer[64] = 1;
        return SHA512.HashData(buffer);
    }

    private byte[] CalculateHmac256(byte[] bytes)
    {
        var hmacKey64 = TransformHmacKey(Minus1);
        HMACSHA256 hmacsha256 = new HMACSHA256(hmacKey64);
        return hmacsha256.ComputeHash(bytes, 0, Length);
    }

    public byte[] TransformHmacKey(byte[] bytes)
    {
        var sha = SHA512.Create();
        sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
        sha.TransformFinalBlock(_hmacKey, 0, _hmacKey.Length);
        return sha.Hash!;
    }

    private byte[] CalculateSha256(byte[] bytes)
    {
        return SHA256.HashData(bytes.AsSpan(0, Length));
    }

    public byte[] Decrypt(byte[] bytes, int offset, int length)
    {
        return _encryptionEngine.Decrypt(bytes, offset, length);
    }
}