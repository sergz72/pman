using pman.keepass;

namespace pman.maui;

public struct PasswordDatabaseFile
{
    public string FullPath { get; }
    public bool IsOpen { get; private set; }
    public readonly bool IsPrepared { get { return _passwordDatabase != null; } }
    public readonly bool IsError { get { return ErrorMessage != null; } }

    private readonly IPasswordDatabase? _passwordDatabase;
    public readonly string? ErrorMessage;

    public PasswordDatabaseFile(string fullPath)
    {
        IsOpen = false;
        FullPath = fullPath;
        if (fullPath.EndsWith(".kdbx"))
        {
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
    }

    public override readonly int GetHashCode()
    {
        return FullPath.GetHashCode();
    }

    public override readonly bool Equals(object? obj)
    {
        if (obj is PasswordDatabaseFile db)
            return db.FullPath == FullPath;
        return false;
    }

    public override readonly string ToString()
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
}
