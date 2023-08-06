using pman.utils;

namespace pman;

public abstract class ReadOnlyPasswordDatabase: IPasswordDatabase
{
    private readonly Dictionary<int, ProtectedBytes> _groups;
    private readonly Dictionary<int, ProtectedBytes> _users;
    private readonly List<IPasswordDatabaseEntry> _entries;
    
    protected ReadOnlyPasswordDatabase(Dictionary<int, ProtectedBytes> groups, Dictionary<int, ProtectedBytes> users, List<IPasswordDatabaseEntry> entries)
    {
        _groups = groups;
        _users = users;
        _entries = entries;
    }
    
    public Dictionary<int, ProtectedBytes> GetGroups()
    {
        return _groups;
    }

    public Dictionary<int, ProtectedBytes> GetUsers()
    {
        return _users;
    }

    public IEnumerable<IPasswordDatabaseEntry> GetEntries()
    {
        return _entries;
    }

    public bool IsReadOnly()
    {
        return true;
    }

    public string GetUnprotectedString(ProtectedBytes value)
    {
        return value.GetUnprotectedString();
    }

    public abstract string GetUnprotectedPassword(ProtectedBytes value);
}
