using System.Text;
using pman.utils;

namespace pman.keepass;

public sealed class KeePassPasswordDatabase : ReadOnlyPasswordDatabase
{
    private const string InvalidParameter = "invalid XML tag parameter";
    private const string UnterminatedParameter = "unterminated XML tag parameter";
    private const string UnterminatedTag = "unterminated tag";

    public struct XmlTag
    {
        public readonly string Name;
        public readonly Dictionary<string, string> Properties;
        public readonly int ValueOffset;

        public XmlTag()
        {
            Name = "";
            ValueOffset = 0;
            Properties = new Dictionary<string, string>();
        }

        public XmlTag(string name, Dictionary<string, string> properties, int valueOffset)
        {
            Name = name;
            ValueOffset = valueOffset;
            Properties = properties;
        }
    }

    private KeePassPasswordDatabase(Dictionary<int, ProtectedBytes> groups, Dictionary<int, ProtectedBytes> users,
        List<IPasswordDatabaseEntry> entries) : base(groups, users, entries)
    {
    }

    public static KeePassPasswordDatabase Create(byte[] contents, int offset)
    {
        //string c = Encoding.UTF8.GetString(contents, offset, contents.Length - offset);
        var entries = ProcessContents(contents, offset, out var groups, out var users);
        return new KeePassPasswordDatabase(groups, users, entries);
    }

    private static List<IPasswordDatabaseEntry> ProcessContents(byte[] contents, int offset,
        out Dictionary<int, ProtectedBytes> groups, out Dictionary<int, ProtectedBytes> users)
    {
        groups = new Dictionary<int, ProtectedBytes>();
        users = new Dictionary<int, ProtectedBytes>();
        var entries = new List<IPasswordDatabaseEntry>();

        var keePassFileOffset = Search(contents, offset, out var foundKey, true, "KeePassFile");
        var rootOffset = Search(contents, keePassFileOffset, out foundKey, true, "Root");
        var groupOffset = Search(contents, rootOffset, out foundKey, false, "Group");
        while (groupOffset != 0)
        {
            var tagOffset = Search(contents, groupOffset, out foundKey, true, "Name", "Entry");
            string? name = null;
            var properties = new Dictionary<string, XmlTag>();
            do
            {
                switch (foundKey.Name)
                {
                    case "Name":
                        if (name != null)
                            throw new FormatException("duplicate name tag");
                        name = GetValueString(contents, tagOffset);
                        break;
                    default: // entry
                        var stringOffset = Search(contents, groupOffset, out foundKey, true, "String");
                        do
                        {
                            stringOffset = FindTags(contents, stringOffset, out var tags);
                            if (tags.Count != 2 || !tags.ContainsKey("Key") || !tags.ContainsKey("Value"))
                                throw new FormatException("invalid String tag");
                            properties[GetValueString(contents, tags["Key"].ValueOffset)] = tags["Value"];
                            stringOffset = Search(contents, stringOffset, out foundKey, false, "String");
                            if (stringOffset != 0)
                                tagOffset = stringOffset;
                        } while (stringOffset != 0);

                        groupOffset = tagOffset;
                        break;
                }

                tagOffset = Search(contents, tagOffset, out foundKey, false, "Name", "Entry");
                if (tagOffset != 0)
                    groupOffset = tagOffset;
            } while (tagOffset != 0);

            groupOffset = Search(contents, groupOffset, out foundKey, false, "Group");
        }

        return entries;
    }

    public static int FindTags(byte[] contents, int offset, out Dictionary<string, XmlTag> tags)
    {
        tags = new Dictionary<string, XmlTag>();
        while (offset < contents.Length - 1 && !(contents[offset] == '<' && contents[offset + 1] == '/'))
        {
            offset = Search(contents, offset, out var key, true);
            tags[key.Name] = key;
            offset = Search(contents, offset, out var key2, true, "/" + key.Name);
        }

        return offset + 2;
    }

    private static string GetValueString(byte[] contents, int offset)
    {
        return Encoding.UTF8.GetString(GetValueBytes(contents, offset));
    }

    private static int SearchFor(byte[] contents, int offset, char value, string errorMessage)
    {
        while (offset < contents.Length && contents[offset] != value)
            offset++;
        if (offset == contents.Length)
            throw new FormatException(errorMessage);
        return offset;
    }

    private static byte[] GetValueBytes(byte[] contents, int offset)
    {
        var endOffset = SearchFor(contents, offset, '<', UnterminatedTag);
        var result = new byte[endOffset - offset];
        Array.Copy(contents, offset, result, 0, result.Length);
        return result;
    }

    public static int Search(byte[] contents, int offset, out XmlTag foundKey, bool raiseException,
        params string[] keyNames)
    {
        var keySet = new HashSet<string>(keyNames);
        for (;;)
        {
            while (offset < contents.Length && contents[offset] != '<')
                offset++;
            offset++;
            if (offset >= contents.Length)
                break;
            if (contents[offset] == '?')
                continue;
            offset = BuildXmlTag(contents, offset, out foundKey);
            if (keySet.Count == 0 || keySet.Contains(foundKey.Name))
                return offset;
        }

        if (raiseException)
            throw new FormatException($"keys {keyNames} were not found in the XML");

        foundKey = new XmlTag();

        return 0;
    }

    private static int SkipSpaces(byte[] contents, int offset, string errorMessage)
    {
        while (offset < contents.Length && char.IsWhiteSpace((char)contents[offset]))
            offset++;
        if (offset == contents.Length)
            throw new FormatException(errorMessage);
        return offset;
    }

    private static int GetName(byte[] contents, int offset, char endTag, string emptyNameErrorMessage, string eofErrorMessage, out string name)
    {
        // skipping spaces
        offset = SkipSpaces(contents, offset, "invalid XML tag");
        var paramsOffset = offset;
        // getting name
        while (paramsOffset < contents.Length && !char.IsWhiteSpace((char)contents[paramsOffset]))
        {
            if (contents[paramsOffset] == endTag)
                break;

            paramsOffset++;
        }

        if (paramsOffset == offset)
            throw new FormatException("XML tag without name");
        if (paramsOffset == contents.Length)
            throw new FormatException("unterminated tag name");
        name = Encoding.UTF8.GetString(contents, offset, paramsOffset - offset);
        return paramsOffset;
    }
    
    public static int BuildXmlTag(byte[] contents, int offset, out XmlTag tag)
    {
        var paramsOffset = GetName(contents, offset, '>', "XML tag without name",
            "unterminated tag name", out var name);
        var parameters = new Dictionary<string, string>();
        while (paramsOffset < contents.Length && contents[paramsOffset] != '>')
            paramsOffset = MayBeAddParameter(contents, paramsOffset, parameters);
        paramsOffset++;
        if (paramsOffset >= contents.Length)
            throw new FormatException(UnterminatedTag);
        tag = new XmlTag(name, parameters, paramsOffset);
        return paramsOffset;
    }

    public static int MayBeAddParameter(byte[] contents, int offset, Dictionary<string, string> parameters)
    {
        // skipping spaces
        offset = SkipSpaces(contents, offset, InvalidParameter);
        // end of tag
        if (contents[offset] == '>')
            return offset;
        if (contents[offset] == '/')
        {
            offset++;
            if (offset == contents.Length || contents[offset] != '>')
                throw new FormatException(InvalidParameter);
            return offset;
        }
        var paramsOffset = offset;
        // getting name
        paramsOffset = GetName(contents, offset, '=', "XML parameter without name", 
            UnterminatedParameter, out var name);
        // skipping spaces
        paramsOffset = SkipSpaces(contents, paramsOffset, UnterminatedParameter);
        // validating
        if (contents[paramsOffset] != '=')
            throw new FormatException(InvalidParameter);
        paramsOffset++;
        // skipping spaces
        paramsOffset = SkipSpaces(contents, paramsOffset, UnterminatedParameter);
        // validating
        if (contents[paramsOffset] != '"')
            throw new FormatException(InvalidParameter);
        paramsOffset++;
        var valueOffset = paramsOffset;
        while (valueOffset < contents.Length && contents[valueOffset] != '"')
            valueOffset++;
        if (valueOffset == contents.Length)
            throw new FormatException(UnterminatedParameter);
        var value = Encoding.UTF8.GetString(contents, paramsOffset, valueOffset - paramsOffset);
        if (parameters.ContainsKey(name))
            throw new FormatException("duplicate parameter name");
        parameters[name] = value;
        return valueOffset + 1;
    }

    public override string GetUnprotectedPassword(ProtectedBytes value)
    {
        return value.GetUnprotectedString();
    }
}