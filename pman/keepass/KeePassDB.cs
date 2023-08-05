namespace pman.keepass;

public class KeePassDb
{
    internal const string FileCorrupted = "corrupted DB file";
    
    private readonly KeePassDbHeader _header;
    
    public uint VersionMajor => _header.VersionMajor;
    public uint VersionMinor => _header.VersionMinor;

    public Dictionary<KeePassDbHeader.HeaderFieldType, KeePassDbHeader.HeaderField> HeaderFields => _header.HeaderFields;

    public KeePassDb(string fileName, string password, string? keyFileName)
    {
        var credentials = new KeePassCredentials(password, keyFileName);
        var bytes = File.ReadAllBytes(fileName);
        _header = new KeePassDbHeader(bytes, credentials);
        var l = _header.Length;
        var dbBlocks = new List<KeePassDbBlock>();
        var maxL = bytes.Length - KeePassDbBlock.HeaderLength;
        long blockNumber = 0;
        while (l <= maxL)
        {
            var dbBlock = new KeePassDbBlock(bytes, l, _header, blockNumber++);
            if (!dbBlock.IsEmpty())
                dbBlocks.Add(dbBlock);
            l += dbBlock.Length;
        }

        if (l != bytes.Length)
            throw new FormatException(FileCorrupted);
    }

    public void PrintDbInfo(TextWriter writer)
    {
        writer.WriteLine("Database version: {0}.{1}", VersionMajor, VersionMinor);
        foreach (var field in HeaderFields)
            writer.WriteLine("Header field {0} size {1}", field.Key, field.Value.FieldData?.Length);
        foreach (var entry in _header.KdfParameters.Entries)
            writer.WriteLine("Kdf parameter {0} type {1} size {2}", entry.Key, entry.Value.Type, entry.Value.Value.Length);
    }
}