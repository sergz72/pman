using pman.utils;

namespace pman.keepass;

internal sealed class KeePassDatabaseEntry: IPasswordDatabaseEntry
{
    private const string PasswordKey = "Password";
    private const string UrlKey = "URL";
    
    private readonly ProtectedBytes _password;
    private readonly ProtectedBytes? _userName;
    private readonly ProtectedBytes? _url;
    private readonly Dictionary<string, ProtectedBytes> _properties;
    internal KeePassDatabaseEntry(SecureXmlDocument.XmlTag entry)
    {
        var tags = entry.FindAll("Entry", "String");
        _properties = new Dictionary<string, ProtectedBytes>();
        foreach (var tag in tags)
        {
            var key = tag.GetChildValue("Key").GetUnprotectedString();
            var value = tag.GetChildValue("Value");
            if (_properties.ContainsKey(key))
                throw new KeePassXmlDocument.KeePassXmlDocumentException("duplicate entry string key");
            _properties[key] = value;
        }
        if (!_properties.TryGetValue(PasswordKey, out _password))
            throw new KeePassXmlDocument.KeePassXmlDocumentException("database entry has no password property");
        _properties.Remove(PasswordKey);
        if (_properties.TryGetValue(KeePassXmlDocument.UserNameKey, out _userName))
            _properties.Remove(KeePassXmlDocument.UserNameKey);
        if (_properties.TryGetValue(UrlKey, out _url))
            _properties.Remove(UrlKey);
    }

    public ProtectedBytes? GetUserName()
    {
        return _userName;
    }

    public ProtectedBytes GetPassword()
    {
        return _password;
    }

    public ProtectedBytes? GetUrl()
    {
        return _url;
    }

    public Times GetTimes()
    {
        throw new NotImplementedException();
    }

    public IEnumerable<string> GetProperties()
    {
        return _properties.Keys;
    }

    public string GetProperty(string name)
    {
        return _properties[name].GetUnprotectedString();
    }

    public void SetUserId(int id)
    {
        throw new NotImplementedException();
    }

    public void SetGroupId(int id)
    {
        throw new NotImplementedException();
    }

    public void SetName(string name)
    {
        throw new NotImplementedException();
    }

    public void SetPassword(string password)
    {
        throw new NotImplementedException();
    }

    public void SetUrl(string? url)
    {
        throw new NotImplementedException();
    }

    public void SetProperty(string name, string value)
    {
        throw new NotImplementedException();
    }

    public void DeleteProperty(string name)
    {
        throw new NotImplementedException();
    }
}