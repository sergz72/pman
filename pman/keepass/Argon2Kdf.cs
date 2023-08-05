using Isopoh.Cryptography.Argon2;

namespace pman.keepass;

public class Argon2Kdf: IKeyDerivationFunction
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

    private readonly Argon2Config _config;
    
    public Argon2Kdf(VariantDictionary kdfParameters)
    {
        _config = new Argon2Config
        {
            Version = (Argon2Version)kdfParameters.AsUint32("V"),
            Salt = kdfParameters.AsArray("S", -1),
            Lanes = (int)kdfParameters.AsUint32("P"),
            MemoryCost = (int)kdfParameters.AsUint64("M") / 1024,
            TimeCost = (int)kdfParameters.AsUint64("I"),
            Threads = Environment.ProcessorCount,
            HashLength = 32,
            ClearSecret = true,
            ClearPassword = true
        };
        if (kdfParameters.IsArray("$UUID", Argon2Duuid))
            _config.Type = Argon2Type.DataDependentAddressing;
        else
        {
            if (kdfParameters.IsArray("$UUID", Argon2Iduuid))
                _config.Type = Argon2Type.HybridAddressing;
            else
                throw new FormatException("unsupported key derivation function");
        }
    }

    public byte[] GetTransformedKey(byte[] digest)
    {
        _config.Password = digest;
        var hasher = new Argon2(_config);
        return hasher.Hash().Buffer;
    }
}