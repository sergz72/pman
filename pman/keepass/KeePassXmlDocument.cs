namespace pman.keepass;

public class KeePassXmlDocument: IDisposable, IPasswordDatabase
{
    private const string UserNameKey = "UserName";
    private const string TitleKey = "Title";

    public class KeePassXmlDocumentException: Exception
    {
        public KeePassXmlDocumentException(string message) : base(message)
        {
        }
    }
    
    private readonly SecureXmlDocument _document;
    public KeePassXmlDocument(byte[] contents, int offset)
    {
        _document = new SecureXmlDocument(contents, offset, DecryptValue);
    }

    private void DecryptValue(byte[] value, Dictionary<string, string> properties)
    {
        
    }
    
    public bool IsReadOnly()
    {
        return true;
    }

    public Dictionary<string, int> GetGroups()
    {
        var result = new Dictionary<string, int>();
        foreach (var group in _document.FindAll("KeePassFile", "Root", "Group", "Group"))
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
        foreach (var group in _document.FindAll("KeePassFile", "Root", "Group", "Group"))
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
        var group = _document
            .FindAll("KeePassFile", "Root", "Group", "Group")
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
        throw new NotImplementedException();
    }

    public IPasswordDatabaseEntry GetEntry(string name)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        _document.Dispose();
    }
}