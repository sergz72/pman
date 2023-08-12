using pman.utils;

namespace pman.keepass;

internal sealed class KeePassDatabaseEntry: IPasswordDatabaseEntry
{
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
    }

    public ProtectedBytes GetUserName()
    {
        return _properties[KeePassXmlDocument.UserNameKey];
    }

    public ProtectedBytes GetPassword()
    {
        return _properties["Password"];
    }

    public ProtectedBytes? GetUrl()
    {
        _properties.TryGetValue("URL", out var url);
        return url;
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