using System.Security.Cryptography;
using pman.keepass;

namespace pman;

internal sealed class AesEngine: IEncryptionEngine
{
    private readonly Aes _aes;
    private ICryptoTransform? _decryptor;
    private ICryptoTransform? _encryptor;
    
    internal AesEngine(byte[] iv)
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
        _encryptor = _aes.CreateEncryptor();
    }

    public byte[] Encrypt(byte[] bytes)
    {
        return _encryptor!.TransformFinalBlock(bytes, 0, bytes.Length);
    }
    
    public byte[] Decrypt(byte[] bytes)
    {
        return _decryptor!.TransformFinalBlock(bytes, 0, bytes.Length);
    }
}