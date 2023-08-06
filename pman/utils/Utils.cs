using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Integrative.Encryption;

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

public class ProtectedBytes
{
    private static readonly byte[] AdditionalEntropy = RandomNumberGenerator.GetBytes(32);

    private readonly byte[] _bytes;

    private ProtectedBytes(byte[] source)
    {
        _bytes = source;
    }
    
    public static ProtectedBytes Protect(byte[] data)
    {
        // Encrypt the data using DataProtectionScope.CurrentUser. The result can be decrypted
        // only by the same current user.
        return new ProtectedBytes(CrossProtect.Protect(data, AdditionalEntropy, DataProtectionScope.CurrentUser));
    }

    public byte[] Unprotect()
    {
        //Decrypt the data using DataProtectionScope.CurrentUser.
        return CrossProtect.Unprotect(_bytes, AdditionalEntropy, DataProtectionScope.CurrentUser);
    }

    public string GetUnprotectedString()
    {
        var unprotected = Unprotect();
        var result = Encoding.UTF8.GetString(unprotected);
        Array.Clear(unprotected, 0, unprotected.Length);
        return result;
    }
}
