using System.Security.Cryptography;
using pman.utils;

namespace pman.keepass;

public class KeePassDbHeader
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

    internal readonly Dictionary<HeaderFieldType, KeePassHeaderField<HeaderFieldType>> HeaderFields;

    private readonly byte[] _data;
    private readonly byte[] _hmac;
    private readonly byte[] _masterSeed;
    private readonly byte[] _encryptionIv;
    internal readonly VariantDictionary KdfParameters;
    private readonly IEncryptionEngine _encryptionEngine;
    private readonly ICompressionEngine _compressionEngine;
    private readonly IKeyDerivationFunction _kdf;

    private ProtectedBytes? _hmacKey;
    
    internal KeePassDbHeader(byte[] bytes)
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
    
        HeaderFields =
            KeePassHeaderField<HeaderFieldType>.ReadHeaderFields(bytes, 12, out var offset, "header",
                HeaderFieldType.EndOfHeader);
        Length = offset;

        _masterSeed = GetMasterSeed();
        _encryptionIv = GetEncryptionIv();
        _compressionEngine = GetCompressionEngine();
        _encryptionEngine = GetEncryptionEngine();
        
        KdfParameters = BuildKdfParameters();

        _kdf = new Argon2Kdf(KdfParameters);

        _data = new byte[Length];
        Array.Copy(bytes, 0, _data, 0, Length);
        ValidateHeaderSha(bytes);
        Length += 32;
        _hmac = new byte[32];
        Array.Copy(bytes, Length, _hmac, 0, 32);
        Length += 32;
    }

    internal void Decrypt(KeePassCredentials credentials)
    {
        var transformedKey = _kdf.GetTransformedKey(credentials.Key);
        _hmacKey = CalculateHmacKey(transformedKey);
        ValidateHeaderHmac();
        var encryptionKey = CalculateEncryptionKey(transformedKey);
        _encryptionEngine.Init(encryptionKey);
    }
    
    private ICompressionEngine GetCompressionEngine()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.CompressionFlags, out var compressionFlags))
            throw new FormatException("compression flags header is missing");
        if (compressionFlags.FieldData == null || compressionFlags.FieldData.Length != 4)
            throw new FormatException("compression flags header is wrong");

        switch (BitConverter.ToInt32(compressionFlags.FieldData!))
        {
            case 0:
                return new NoCompressionEngine();
            case 1:
                return new GzipCompressionEngine();
            default:
                throw new FormatException("unsupported compression type");
        }
    }

    private IEncryptionEngine GetEncryptionEngine()
    {
        if (!HeaderFields.TryGetValue(HeaderFieldType.CipherId, out var cipherId))
            throw new FormatException("cipher id header is missing");
        if (cipherId.FieldData == null || cipherId.FieldData.Length != 16)
            throw new FormatException("cipher id header is wrong");
        if (!cipherId.FieldData!.SequenceEqual(AesCipherId))
            throw new FormatException("unsupported cipher engine");
        return new AesEngine(_encryptionIv);
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

    private void ValidateHeaderSha(byte[] bytes)
    {
        var sha256 = CalculateSha256();
        if (!sha256.SequenceEqual(new ArraySegment<byte>(bytes, Length, 32)))
            throw new FormatException("header hash does not match");
    }

    private void ValidateHeaderHmac()
    {
        var hmac256 = CalculateHmac256();
        if (!hmac256.SequenceEqual(_hmac))
            throw new FormatException("header HMAC does not match");
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

    private ProtectedBytes CalculateHmacKey(byte[] transformedKey)
    {
        var buffer = new byte[65];
        Array.Copy(_masterSeed, buffer, _masterSeed.Length);
        Array.Copy(transformedKey, 0, buffer, _masterSeed.Length, transformedKey.Length);
        buffer[64] = 1;
        return ProtectedBytes.Protect(SHA512.HashData(buffer));
    }

    private byte[] CalculateHmac256()
    {
        var hmacKey64 = TransformHmacKey(Minus1);
        HMACSHA256 hmacsha256 = new HMACSHA256(hmacKey64);
        return hmacsha256.ComputeHash(_data, 0, _data.Length);
    }

    public byte[] TransformHmacKey(byte[] bytes)
    {
        var sha = SHA512.Create();
        sha.TransformBlock(bytes, 0, bytes.Length, null, 0);
        var hmacKey = _hmacKey!.Unprotect();
        sha.TransformFinalBlock(hmacKey, 0, hmacKey.Length);
        Array.Clear(hmacKey, 0, hmacKey.Length);
        return sha.Hash!;
    }

    private byte[] CalculateSha256()
    {
        return SHA256.HashData(_data);
    }

    public byte[] DecryptData(byte[] bytes)
    {
        return _encryptionEngine.Decrypt(bytes);
    }
    
    public byte[] Decompress(byte[] bytes)
    {
        return _compressionEngine.Decompress(bytes);
    }
}