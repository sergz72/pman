namespace pman.keepass;

public interface IKeyDerivationFunction
{
    byte[] GetTransformedKey(byte[] digest);
}

public interface IEncryptionEngine
{
    byte[] Decrypt(byte[] buffer, int offset, int length);
}