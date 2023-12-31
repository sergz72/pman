using System.Security;
using pman.keepass;

namespace pman.maui;

public class PasswordDatabaseFile
{
    public string FullPath { get; }
    public bool IsOpen { get; private set; }
    public bool IsPrepared => _passwordDatabase != null && !IsOpen;
    public bool IsError => ErrorMessage != null;

    public bool IsReadOnly => _passwordDatabase?.IsReadOnly() ?? true;
    public bool IsReadWrite => !_passwordDatabase?.IsReadOnly() ?? false;
    
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

    public override int GetHashCode()
    {
        return FullPath.GetHashCode();
    }

    public override bool Equals(object? obj)
    {
        if (obj is PasswordDatabaseFile db)
            return db.FullPath == FullPath;
        return false;
    }

    public override string ToString()
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

    public Dictionary<string, List<DatabaseSearchResult>> Search(string filter)
    {
        return _passwordDatabase?.GetGroups(filter) ?? new Dictionary<string, List<DatabaseSearchResult>>();
    }
}
