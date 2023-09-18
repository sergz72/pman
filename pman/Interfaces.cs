using System.Security;
using pman.utils;

namespace pman;

public interface IPasswordDatabase
{
    bool IsReadOnly();
    
    Dictionary<string, List<DatabaseSearchResult>> GetGroups(string filter);
    HashSet<string> GetUsers();
    
    IPasswordDatabaseEntry GetEntry(DatabaseSearchResult entry);

    void Open(SecureString password, SecureString? password2, string? keyFileName);
}

public interface IPasswordDatabaseEntry
{
    ProtectedBytes? GetUserName();
    ProtectedBytes GetPassword();
    ProtectedBytes? GetUrl();
    Times GetTimes();
    IEnumerable<string> GetProperties();
    ProtectedBytes GetProperty(string name);

    void SetUserId(int id);
    void SetGroupId(int id);
    void SetName(string name);
    void SetPassword(string password);
    void SetUrl(string? url);
    void SetProperty(string name, string value);
    void DeleteProperty(string name);
}