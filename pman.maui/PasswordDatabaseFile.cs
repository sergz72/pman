using System.Security;
using pman.keepass;

namespace pman.maui;

public struct PasswordDatabaseFile
{
    public string FullPath { get; }
    public bool IsOpen { get; private set; }
    public readonly bool IsPrepared => _passwordDatabase != null && !IsOpen;
    public readonly bool IsError => ErrorMessage != null;

    public readonly bool IsReadOnly => _passwordDatabase?.IsReadOnly() ?? false;
    
    public bool SecondPasswordIsRequired { get; }
    public bool KeyFileIsRequired { get; }
    
    private readonly IPasswordDatabase? _passwordDatabase;
    public readonly string? ErrorMessage;

    public PasswordDatabaseFile(string fullPath)
    {
        IsOpen = false;
        FullPath = fullPath;
        if (fullPath.EndsWith(".kdbx"))
        {
            SecondPasswordIsRequired = false;
            KeyFileIsRequired = true;
            try
            {
                _passwordDatabase = new KeePassDb(fullPath);
                ErrorMessage = null;
            }
            catch (Exception ex)
            {
                ErrorMessage = ex.Message;
            }
        }
        else
        {
            SecondPasswordIsRequired = true;
            KeyFileIsRequired = false;
        }
    }

    public readonly override int GetHashCode()
    {
        return FullPath.GetHashCode();
    }

    public readonly override bool Equals(object? obj)
    {
        if (obj is PasswordDatabaseFile db)
            return db.FullPath == FullPath;
        return false;
    }

    public readonly override string ToString()
    {
        return FullPath;
    }

    public static bool operator ==(PasswordDatabaseFile left, PasswordDatabaseFile right)
    {
        return left.Equals(right);
    }

    public static bool operator !=(PasswordDatabaseFile left, PasswordDatabaseFile right)
    {
        return !(left == right);
    }

    public void Open(SecureString password, SecureString? password2, string? keyFileName)
    {
        _passwordDatabase?.Open(password, password2, keyFileName);
        IsOpen = true;
    }
}
