using pman.utils;

namespace pman;

public class ReadOnlyDatabaseEntry: IPasswordDatabaseEntry
{
    private readonly int _userId;
    private readonly int _groupId;
    private readonly ProtectedBytes _name;
    private readonly ProtectedBytes _password;
    private readonly ProtectedBytes? _url;
    private readonly Dictionary<ProtectedBytes, ProtectedBytes> _properties;

    public ReadOnlyDatabaseEntry(int groupId, int userId, ProtectedBytes name, ProtectedBytes password, ProtectedBytes? url,
        Dictionary<ProtectedBytes, ProtectedBytes> properties)
    {
        _groupId = groupId;
        _userId = userId;
        _name = name;
        _password = password;
        _url = url;
        _properties = properties;
    }
    
    public int GetUserId()
    {
        return _userId;
    }

    public int GetGroupId()
    {
        return _groupId;
    }

    public ProtectedBytes GetName()
    {
        return _name;
    }

    public ProtectedBytes GetPassword()
    {
        return _password;
    }

    public ProtectedBytes? GetUrl()
    {
        return _url;
    }

    public Dictionary<ProtectedBytes, ProtectedBytes> GetProperties()
    {
        return _properties;
    }

    public void SetUserId(IPasswordDatabase db, int id)
    {
        throw new NotImplementedException();
    }

    public void SetGroupId(IPasswordDatabase db, int id)
    {
        throw new NotImplementedException();
    }

    public void SetName(IPasswordDatabase db, string name)
    {
        throw new NotImplementedException();
    }

    public void SetPassword(IPasswordDatabase db, string password)
    {
        throw new NotImplementedException();
    }

    public void SetUrl(IPasswordDatabase db, string url)
    {
        throw new NotImplementedException();
    }

    public void SetProperty(IPasswordDatabase db, string name, string value)
    {
        throw new NotImplementedException();
    }

    public void DeleteProperty(IPasswordDatabase db, string name)
    {
        throw new NotImplementedException();
    }
}
