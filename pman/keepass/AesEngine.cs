namespace pman.keepass;

public class AesEngine: IEncryptionEngine
{
    public AesEngine(byte[] key, byte[] iv)
    {
        
    }

    public byte[] Decrypt(byte[] buffer, int offset, int length)
    {
        throw new NotImplementedException();
    }
}