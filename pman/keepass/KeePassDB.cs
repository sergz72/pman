using System.Security;

namespace pman.keepass;

public sealed class KeePassDb: IDisposable, IPasswordDatabase
{
    internal const string FileCorrupted = "corrupted DB file";
    private const string DatabaseIsNotOpen = "database is not open";
    
    private readonly KeePassDbHeader _header;
    private KeePassInnerHeader? _innerHeader;
    private readonly List<KeePassDbBlock> _dbBlocks;
    private KeePassXmlDocument? _database;
    
    public KeePassDb(string fileName)
    {
        var bytes = File.ReadAllBytes(fileName);
        _header = new KeePassDbHeader(bytes);
        var l = _header.Length;
        _dbBlocks = new List<KeePassDbBlock>();
        var maxL = bytes.Length - KeePassDbBlock.HeaderLength;
        while (l <= maxL)
        {
            var dbBlock = new KeePassDbBlock(bytes, l);
            if (!dbBlock.IsEmpty())
                _dbBlocks.Add(dbBlock);
            l += dbBlock.Length;
        }

        if (l != bytes.Length || _dbBlocks.Count == 0)
            throw new FormatException(FileCorrupted);
    }

    public void Decrypt(SecureString password, string? keyFileName)
    {
        var credentials = new KeePassCredentials(password, keyFileName);
        password.Dispose();
        _header.Decrypt(credentials);
        credentials.Dispose();
        int dataLength = 0;
        int blockNumber = 0;
        foreach (var dbBlock in _dbBlocks)
            dataLength += dbBlock.Validate(_header, blockNumber++);
        byte[] decrypted = new byte[dataLength];
        int offset = 0;
        foreach (var block in _dbBlocks)
        {
            var result = block.Decrypt(_header);
            Array.Copy(result, 0, decrypted, offset, result.Length);
            offset += result.Length;
        }
        byte[] decompressed = _header.Decompress(decrypted);
        Array.Clear(decrypted, 0, decrypted.Length);

        _innerHeader = new KeePassInnerHeader(decompressed);
        _database = new KeePassXmlDocument(decompressed, _innerHeader.DataOffset, _innerHeader.Decrypt);
        Array.Clear(decompressed, 0, decompressed.Length);
    }
    
    public void PrintUnencryptedDbInfo(TextWriter writer)
    {
        writer.WriteLine("Database version: {0}.{1}", _header.VersionMajor, _header.VersionMinor);
        foreach (var field in _header.HeaderFields)
            writer.WriteLine("Header field {0} size {1}", field.Key, field.Value.FieldData?.Length);
        foreach (var entry in _header.KdfParameters.Entries)
            writer.WriteLine("Kdf parameter {0} type {1} size {2}", entry.Key, entry.Value.Type, entry.Value.Value.Length);
    }

    public void PrintEncryptedDbInfo(TextWriter writer)
    {
        foreach (var field in _innerHeader!.HeaderFields)
            writer.WriteLine("Inner header field {0} size {1}", field.Key, field.Value.FieldData?.Length);
    }
    
    public void Dispose()
    {
        _innerHeader?.Dispose();
        _database?.Dispose();
    }

    public bool IsReadOnly()
    {
        return true;
    }

    public Dictionary<string, int> GetGroups()
    {
        return _database?.GetGroups() ?? throw new FormatException(DatabaseIsNotOpen);
    }

    public HashSet<string> GetUsers()
    {
        return _database?.GetUsers() ?? throw new FormatException(DatabaseIsNotOpen);
    }

    public List<DatabaseSearchResult> GetGroupEntries(string group)
    {
        return _database?.GetGroupEntries(group) ?? throw new FormatException(DatabaseIsNotOpen);
    }

    public List<DatabaseSearchResult> GetEntries(string filter)
    {
        return _database?.GetEntries(filter) ?? throw new FormatException(DatabaseIsNotOpen);
    }

    public IPasswordDatabaseEntry GetEntry(string name)
    {
        return _database?.GetEntry(name) ?? throw new FormatException(DatabaseIsNotOpen);
    }
}