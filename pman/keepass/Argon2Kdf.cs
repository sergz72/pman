using Konscious.Security.Cryptography;

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

    private enum Argon2Type
    {
        Argon2Id,
        Argon2d
    }
    
    private readonly byte[] _salt;
    private readonly Argon2Type _hasherType;
    private readonly ulong _iterations;
    private readonly uint _parallelism;
    private readonly ulong _memory;
    
    internal Argon2Kdf(VariantDictionary kdfParameters)
    {
        _hasherType = kdfParameters.IsArray("$UUID", Argon2Duuid) ? Argon2Type.Argon2d : 
            kdfParameters.IsArray("$UUID", Argon2Iduuid) ? Argon2Type.Argon2Id :
            throw new FormatException("unsupported key derivation function");
        if (kdfParameters.AsUint32("V") != 19)
            throw new FormatException("unsupported Argon2 version");
        _salt = kdfParameters.AsArray("S", -1);
        _iterations = kdfParameters.AsUint64("I");
        _parallelism = kdfParameters.AsUint32("P");
        _memory = kdfParameters.AsUint64("M") / 1024;
    }

    public byte[] GetTransformedKey(byte[] digest)
    {
        Argon2 hasher = _hasherType == Argon2Type.Argon2d ? new Argon2d(digest) : new Argon2id(digest);
        hasher.Iterations = (int)_iterations;
        hasher.Salt = _salt;
        hasher.DegreeOfParallelism = (int)_parallelism;
        hasher.MemorySize = (int)_memory;
        return hasher.GetBytes(32);
    }
}