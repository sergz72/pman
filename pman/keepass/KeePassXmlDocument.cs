using pman.utils;

namespace pman.keepass;

public sealed class KeePassXmlDocument: IDisposable, IPasswordDatabase
{
    internal const string UserNameKey = "UserName";
    private const string TitleKey = "Title";
    private const string Protected = "Protected";

    internal class KeePassXmlDocumentException: Exception
    {
        public KeePassXmlDocumentException(string message) : base(message)
        {
        }
    }
    
    private readonly SecureXmlDocument _document;
    private readonly Action<byte[]>? _decrypter;
    
    public KeePassXmlDocument(byte[] contents, int offset, Action<byte[]>? decrypter)
    {
        _decrypter = decrypter;
        _document = new SecureXmlDocument(contents, offset, DecryptValue);
    }

    private void DecryptValue(byte[] value, Dictionary<string, string> properties)
    {
        if (_decrypter == null) return;
        if (!properties.TryGetValue(Protected, out var protectedProperty)) return;
        if (protectedProperty.ToLower() != "true") return;
        _decrypter.Invoke(value);
    }
    
    public bool IsReadOnly()
    {
        return true;
    }

    private IEnumerable<SecureXmlDocument.XmlTag> GetAllGroups() =>
        _document.FindAll("KeePassFile", "Root", "Group", "Group");

    public Dictionary<string, int> GetGroups()
    {
        var result = new Dictionary<string, int>();
        foreach (var group in GetAllGroups())
        {
            var value = group.GetChildValue("Name").GetUnprotectedString();
            if (result.ContainsKey(value))
                throw new KeePassXmlDocumentException("duplicate group name");
            result[value] = group.FindAll("Group", "Entry").Count();
        }
        return result;
    }

    public HashSet<string> GetUsers()
    {
        var result = new HashSet<string>();
        foreach (var group in GetAllGroups())
        {
            foreach (var entry in group.FindAll("Group", "Entry"))
            {
                var userName = entry.FindAll("Entry", "String")
                    .First(s => s.GetChildValue("Key").GetUnprotectedString() == UserNameKey);
                result.Add(userName.GetChildValue("Value").GetUnprotectedString());
            }
        }
        return result;
    }

    public List<DatabaseSearchResult> GetGroupEntries(string groupName)
    {
        var group = GetAllGroups()
            .First(group => group.GetChildValue("Name").GetUnprotectedString() == groupName);
        var result = new List<DatabaseSearchResult>();
        foreach (var entry in group.FindAll("Group", "Entry"))
        {
            var title = entry.FindAll("Entry", "String")
                .First(s => s.GetChildValue("Key").GetUnprotectedString() == TitleKey);
            result.Add(new DatabaseSearchResult(groupName, title.GetChildValue("Value").GetUnprotectedString()));
        }

        return result;
    }

    public List<DatabaseSearchResult> GetEntries(string filter)
    {
        var result = new List<DatabaseSearchResult>();
        foreach (var group in GetAllGroups())
        {
            var groupName = group.GetChildValue("Name").GetUnprotectedString();
            foreach (var entry in group.FindAll("Group", "Entry"))
            {
                var title = entry.FindAll("Entry", "String")
                    .First(s => s.GetChildValue("Key").GetUnprotectedString() == TitleKey)
                    .GetChildValue("Value").GetUnprotectedString();
                if (title.Contains(filter))
                    result.Add(new DatabaseSearchResult(groupName, title));
            }
        }
        return result;
    }

    public IPasswordDatabaseEntry GetEntry(string name)
    {
        foreach (var group in GetAllGroups())
        {
            var groupName = group.GetChildValue("Name").GetUnprotectedString();
            foreach (var entry in group.FindAll("Group", "Entry"))
            {
                var title = entry.FindAll("Entry", "String")
                    .First(s => s.GetChildValue("Key").GetUnprotectedString() == TitleKey)
                    .GetChildValue("Value").GetUnprotectedString();
                if (title == name)
                    return new KeePassDatabaseEntry(entry);
            }
        }
        throw new KeePassXmlDocumentException("entry not found");
    }

    public void Dispose()
    {
        _document.Dispose();
    }
}