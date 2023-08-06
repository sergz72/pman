using pman.utils;

namespace pman;

public interface IPasswordDatabase
{
    bool IsReadOnly();
    
    Dictionary<int, ProtectedBytes> GetGroups();
    Dictionary<int, ProtectedBytes> GetUsers();

    IEnumerable<IPasswordDatabaseEntry> GetEntries();
    
    string GetUnprotectedString(ProtectedBytes value);
    string GetUnprotectedPassword(ProtectedBytes value);
}

public interface IPasswordDatabaseEntry
{
    int GetUserId();
    int GetGroupId();
    ProtectedBytes GetName();
    ProtectedBytes GetPassword();
    ProtectedBytes? GetUrl();
    Dictionary<ProtectedBytes, ProtectedBytes> GetProperties();

    void SetUserId(IPasswordDatabase db, int id);
    void SetGroupId(IPasswordDatabase db, int id);
    void SetName(IPasswordDatabase db, string name);
    void SetPassword(IPasswordDatabase db, string password);
    void SetUrl(IPasswordDatabase db, string url);
    void SetProperty(IPasswordDatabase db, string name, string value);
    void DeleteProperty(IPasswordDatabase db, string name);
}