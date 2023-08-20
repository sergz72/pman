using System.Security.Cryptography;

namespace pman.keepass;

internal sealed class Argon2Kdf: IKeyDerivationFunction
{
    private static readonly byte[] Argon2Duuid =
    {
        0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B,
        0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C
    };

    private static readonly byte[] Argon2Iduuid =
    {
        0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73,
        0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6
    };

    private readonly Argon2PasswordHasher _hasher;
    private readonly byte[] _salt;
    
    internal Argon2Kdf(VariantDictionary kdfParameters)
    {
        var t = kdfParameters.IsArray("$UUID", Argon2Duuid) ? Argon2Type.Argon2d : 
            kdfParameters.IsArray("$UUID", Argon2Iduuid) ? Argon2Type.Argon2id :
            throw new FormatException("unsupported key derivation function");
        if (kdfParameters.AsUint32("V") != 19)
            throw new FormatException("unsupported Argon2 version");
        _salt = kdfParameters.AsArray("S", -1);
        _hasher = new Argon2PasswordHasher((uint)kdfParameters.AsUint64("I"), (uint)(kdfParameters.AsUint64("M") / 1024),
            kdfParameters.AsUint32("P"), t, 32, (uint)_salt.Length);
    }

    public byte[] GetTransformedKey(byte[] digest)
    {
        var buffer = new byte[32];
        _hasher.Hash(digest, new ReadOnlySpan<byte>(_salt), new Span<byte>(buffer));
        return buffer;
    }
}