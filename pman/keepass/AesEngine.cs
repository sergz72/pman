using System.Security.Cryptography;

namespace pman.keepass;

public class AesEngine: IEncryptionEngine
{
    private readonly ICryptoTransform _decryptor;
    
    public AesEngine(byte[] key, byte[] iv)
    {
        var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        _decryptor = aes.CreateDecryptor();
    }

    public byte[] Decrypt(byte[] bytes, int offset, int length)
    {
        return _decryptor.TransformFinalBlock(bytes, offset, length);
    }
}