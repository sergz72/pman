using System.Security;
using System.Xml;

namespace pman.keepass;

public class KeePassDb
{
    internal const string FileCorrupted = "corrupted DB file";
    
    private readonly KeePassDbHeader _header;
    private KeePassInnerHeader? _innerHeader;
    private readonly List<KeePassDbBlock> _dbBlocks;
    
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
        MemoryStream xmlStream = new MemoryStream(decompressed, _innerHeader.DataOffset,
            decompressed.Length - _innerHeader.DataOffset);
        XmlDocument document = new XmlDocument();
        document.Load(xmlStream);
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
}