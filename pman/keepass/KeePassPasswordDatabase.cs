using System.Net.Http.Headers;
using pman.utils;

namespace pman.keepass;

public sealed class KeePassPasswordDatabase : ReadOnlyPasswordDatabase
{
    private class XmlTag
    {
        private Dictionary<string, string> _properties;
        private int _valueOffset;
    }
    
    private KeePassPasswordDatabase(Dictionary<int, ProtectedBytes> groups, Dictionary<int, ProtectedBytes> users, List<IPasswordDatabaseEntry> entries) : base(groups, users, entries)
    {
    }

    public static KeePassPasswordDatabase Create(byte[] contents, int offset)
    {
        var entries = ProcessContents(contents, offset, out var groups, out var users);
        return new KeePassPasswordDatabase(groups, users, entries);
    }

    private static List<IPasswordDatabaseEntry> ProcessContents(byte[] contents, int offset,
        out Dictionary<int, ProtectedBytes> groups, out Dictionary<int, ProtectedBytes> users)
    {
        groups = new Dictionary<int, ProtectedBytes>();
        users = new Dictionary<int, ProtectedBytes>();
        var entries = new List<IPasswordDatabaseEntry>();

        var keePassFileOffset = Search(contents, offset, "KeePassFile", true);
        var rootOffset = Search(contents, keePassFileOffset, "Root", true);
        var groupOffset = Search(contents, rootOffset, "Group", false);
        while (groupOffset != 0)
        {
            var endOffset = FindTags(new[]{"Name", "Entry"}, out var tags);
            var nameTags = tags["Name"];
            if (nameTags.Length != 1)
                throw new FormatException("duplicate name tag");
            var name = GetValue(contents, nameTags[0]);
            foreach (int entryOffset in tags["Entry"])
            {
                FindTags(new[]{"String"}, out var strings);
                foreach (int stringOffset in strings["String"])
                {
                    
                }
            }
            groupOffset = Search(contents, endOffset, "Group", false);
        }
        
        return entries;
    }

    private static string GetValue(byte[] contents, int offset)
    {
        throw new NotImplementedException();
    }

    private static int FindTags(string[] tags, out Dictionary<string, XmlTag[]> result)
    {
        throw new NotImplementedException();
    }

    private static Dictionary<string, string> GetItems(byte[] contents, int offset, string keyName)
    {
        throw new NotImplementedException();
    }

    private static int Search(byte[] contents, int offset, string keyName, bool raiseException)
    {
        while (offset < contents.Length)
        {
            byte b = contents[offset++];
            switch (b)
            {
                
            }
        }

        if (raiseException)
            throw new FormatException($"key {keyName} not found in the XML");
        return 0;
    }

    public override string GetUnprotectedPassword(ProtectedBytes value)
    {
        return value.GetUnprotectedString();
    }
}