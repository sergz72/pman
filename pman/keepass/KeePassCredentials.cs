using System.Security.Cryptography;
using System.Text;

namespace pman.keepass;

public class KeePassCredentials
{
    public readonly byte[] Key;
    
    public KeePassCredentials(string password, string? keyFileName)
    {
        Key = SHA256.HashData(SHA256.HashData(Encoding.UTF8.GetBytes(password)));
    }
}