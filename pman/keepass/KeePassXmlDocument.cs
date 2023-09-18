using System.Text;

namespace pman.keepass;

public sealed class KeePassXmlDocument: IDisposable
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
        //string s = Encoding.UTF8.GetString(contents, offset, contents.Length - offset);
        _decrypter = decrypter;
        _document = new SecureXmlDocument(contents, offset, DecryptValue);
    }

    private byte[] DecryptValue(byte[] value, Dictionary<string, string> properties)
    {
        if (_decrypter == null) return value;
        if (!properties.TryGetValue(Protected, out var protectedProperty)) return value;
        if (protectedProperty.ToLower() != "true") return value;
        var s = Encoding.UTF8.GetString(value);
        var b = Convert.FromBase64String(s);
        _decrypter.Invoke(b);
        return b;
    }
    
    public bool IsReadOnly()
    {
        return true;
    }

    private IEnumerable<SecureXmlDocument.XmlTag> GetAllGroups() =>
        _document.FindAll("KeePassFile", "Root", "Group", "Group");

    public Dictionary<string, List<DatabaseSearchResult>> GetGroups(string filter)
    {
        var result = new Dictionary<string, List<DatabaseSearchResult>>();
        foreach (var group in GetAllGroups())
        {
            var value = group.GetChildValue("Name").GetUnprotectedString();
            if (result.ContainsKey(value))
                throw new KeePassXmlDocumentException("duplicate group name");
            var entries = new List<DatabaseSearchResult>();
            foreach (var entry in group.FindAll("Group", "Entry"))
            {
                var title = entry.FindAll("Entry", "String")
                    .First(s => s.GetChildValue("Key").GetUnprotectedString() == TitleKey)
                    .GetChildValue("Value").GetUnprotectedString();
                if (title.Contains(filter))
                   entries.Add(new DatabaseSearchResult(value, title));
            }

            result[value] = entries;
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
    
    public IPasswordDatabaseEntry GetEntry(DatabaseSearchResult entry)
    {
        var group = GetAllGroups()
            .First(group => group.GetChildValue("Name").GetUnprotectedString() == entry.Group);
        foreach (var entryTag in group.FindAll("Group", "Entry"))
        {
            var title = entryTag.FindAll("Entry", "String")
                .First(s => s.GetChildValue("Key").GetUnprotectedString() == TitleKey)
                .GetChildValue("Value").GetUnprotectedString();
            if (title == entry.Name)
                return new KeePassDatabaseEntry(entryTag);
        }
        throw new KeePassXmlDocumentException("entry not found");
    }

    public void Dispose()
    {
        _document.Dispose();
    }
}