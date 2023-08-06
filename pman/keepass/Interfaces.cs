namespace pman.keepass;

public interface IKeyDerivationFunction
{
    byte[] GetTransformedKey(byte[] digest);
}

public interface IEncryptionEngine
{
    byte[] Decrypt(byte[] bytes);
    void Init(byte[] key);
}

public interface ICompressionEngine
{
    byte[] Decompress(byte[] bytes);
}