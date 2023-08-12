namespace pman.keepass;

internal interface IKeyDerivationFunction
{
    byte[] GetTransformedKey(byte[] digest);
}

internal interface IEncryptionEngine
{
    byte[] Decrypt(byte[] bytes);
    void Init(byte[] key);
}

internal interface ICompressionEngine
{
    byte[] Decompress(byte[] bytes);
}