using System.Security.Cryptography;

namespace pman.keepass;

public class AesEngine: IEncryptionEngine
{
    private readonly Aes _aes;
    private ICryptoTransform _decryptor;
    
    public AesEngine(byte[] iv)
    {
        _aes = Aes.Create();
        _aes.IV = iv;
        _aes.Mode = CipherMode.CBC;
        _aes.Padding = PaddingMode.PKCS7;
    }

    public void Init(byte[] key)
    {
        _aes.Key = key;
        _decryptor = _aes.CreateDecryptor();
    }

    public byte[] Decrypt(byte[] bytes)
    {
        return _decryptor.TransformFinalBlock(bytes, 0, bytes.Length);
    }
}