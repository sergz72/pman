using System.Security;
using System.Security.Cryptography;
using System.Text;
using pman.utils;

namespace pman.keepass;

public class KeePassCredentials
{
    public readonly byte[] Key;
    
    public KeePassCredentials(SecureString password, string? keyFileName)
    {
        var bytes = Utils.SecureStringToByteArray(password);
        Key = SHA256.HashData(SHA256.HashData(bytes));
        Array.Clear(bytes, 0, bytes.Length);
    }
}