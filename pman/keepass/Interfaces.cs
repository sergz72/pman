namespace pman.keepass;

public interface IKeyDerivationFunction
{
    byte[] GetTransformedKey(byte[] digest);
}

public interface IEncryptionEngine
{
    byte[] Decrypt(byte[] bytes, int offset, int length);
}

public interface ICompressionEngine
{
    byte[] Decompress(byte[] bytes);
}