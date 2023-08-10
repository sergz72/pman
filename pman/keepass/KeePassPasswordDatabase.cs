using pman.utils;

namespace pman.keepass;

public sealed class KeePassPasswordDatabase : ReadOnlyPasswordDatabase
{
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

        return new List<IPasswordDatabaseEntry>();
    }

    public override string GetUnprotectedPassword(ProtectedBytes value)
    {
        throw new NotImplementedException();
    }
}