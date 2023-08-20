using pman.utils;

namespace pman;

public interface IPasswordDatabase
{
    bool IsReadOnly();
    
    Dictionary<string, int> GetGroups();
    HashSet<string> GetUsers();

    List<DatabaseSearchResult> GetGroupEntries(string group);
    List<DatabaseSearchResult> GetEntries(string filter);

    IPasswordDatabaseEntry GetEntry(string name);
}

public interface IPasswordDatabaseEntry
{
    ProtectedBytes? GetUserName();
    ProtectedBytes GetPassword();
    ProtectedBytes? GetUrl();
    Times GetTimes();
    IEnumerable<string> GetProperties();
    string GetProperty(string name);

    void SetUserId(int id);
    void SetGroupId(int id);
    void SetName(string name);
    void SetPassword(string password);
    void SetUrl(string? url);
    void SetProperty(string name, string value);
    void DeleteProperty(string name);
}