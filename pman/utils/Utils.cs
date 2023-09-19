using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace pman.utils;

public static class Utils
{
    public static byte[] SecureStringToByteArray(SecureString secureString)
    {
        var unmanagedString = IntPtr.Zero;
        try
        {
            unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
            var result = Encoding.UTF8.GetBytes(Marshal.PtrToStringUni(unmanagedString)!);
            return result;
        }
        finally
        {
            if (unmanagedString != IntPtr.Zero)
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
        }
    }
}

public sealed class ProtectedBytes: IDisposable
{
    private static readonly AesEngine _engine;

    private readonly byte[] _bytes;

    static ProtectedBytes()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        _engine = new AesEngine(iv);
        _engine.Init(key);
    }
    
    private ProtectedBytes(byte[] source)
    {
        _bytes = source;
    }
    
    public static ProtectedBytes Protect(byte[] data)
    {
        // Encrypt the data using DataProtectionScope.CurrentUser. The result can be decrypted
        // only by the same current user.
        return new ProtectedBytes(_engine.Encrypt(data));
    }

    public byte[] Unprotect()
    {
        //Decrypt the data using DataProtectionScope.CurrentUser.
        return _engine.Decrypt(_bytes);
    }

    public void Dispose()
    {
        Array.Clear(_bytes);
    }

    public string GetUnprotectedString()
    {
        return Encoding.UTF8.GetString(Unprotect());
    }
}
