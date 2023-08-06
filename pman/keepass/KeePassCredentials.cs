using System.Security;
using System.Security.Cryptography;
using pman.utils;

namespace pman.keepass;

public class KeePassCredentials: IDisposable
{
    public readonly byte[] Key;
    
    public KeePassCredentials(SecureString password, string? keyFileName)
    {
        var bytes = Utils.SecureStringToByteArray(password);
        var keyHash = SHA256.HashData(bytes);
        Array.Clear(bytes, 0, bytes.Length);
        if (keyFileName == null)
            Key = SHA256.HashData(keyHash);
        else
        {
            var sha = SHA256.Create();
            sha.TransformBlock(keyHash, 0, keyHash.Length, null, 0);
            var fileBytes = File.ReadAllBytes(keyFileName);
            sha.TransformFinalBlock(fileBytes, 0, fileBytes.Length);
            Array.Clear(fileBytes, 0, fileBytes.Length);
            Key = sha.Hash!;
        }
        Array.Clear(keyHash, 0, keyHash.Length);
    }

    public void Dispose()
    {
        Array.Clear(Key, 0, Key.Length);
    }
}
