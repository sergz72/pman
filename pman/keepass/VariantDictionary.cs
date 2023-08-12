using System.Text;

namespace pman.keepass;

internal sealed class VariantDictionary
{
    internal enum EntryType
    {
        Uint32 = 4,
        Uint64 = 5,
        Bool = 8,
        Int32 = 0xC,
        Int64 = 0xD,
        String = 0x18, // UTF-8, without BOM, without null terminator
        Array = 0x42
    }
    
    internal class Entry
    {
        internal readonly EntryType Type;
        internal readonly byte[] Value;

        internal Entry(byte type, byte[] value)
        {
            if (!Enum.IsDefined(typeof(EntryType), (Int32)type))
                throw new FormatException(KeePassDb.FileCorrupted);
            Type = (EntryType)type;
            Value = value;
        }
    }
    
    private readonly int _version;
    internal readonly Dictionary<string, Entry> Entries;

    internal VariantDictionary(byte[] bytes)
    {
        int offset = 0;
        _version = BitConverter.ToInt16(bytes, offset) >> 8;
        if (_version != 1)
            throw new FormatException("variant dictionary version must be 1");
        offset += 2;
        byte type = bytes[offset++];
        Entries = new Dictionary<string, Entry>();
        while (type != 0)
        {
            var length = BitConverter.ToInt32(bytes, offset);
            offset += 4;
            var key = Encoding.ASCII.GetString(bytes, offset, length);
            offset += length;
            length = BitConverter.ToInt32(bytes, offset);
            offset += 4;
            var value = new byte[length];
            Array.Copy(bytes, offset, value, 0, length);
            offset += length;
            Entries[key] = new Entry(type, value);
            type = bytes[offset++];
        }
    }

    private Entry CheckEntry(string key, EntryType type, int size)
    {
        if (!Entries.TryGetValue(key, out var e))
            throw new FormatException($"entry {key} is not present in kdfParameters");
        if (e.Type != type)
            throw new FormatException($"entry {key} is in kdfParameters has wrong entry type");
        if (size >= 0 && e.Value.Length != size)
            throw new FormatException($"entry {key} is in kdfParameters has wrong size");
        return e;
    }
    
    internal bool IsArray(string key, byte[] value)
    {
        return CheckEntry(key, EntryType.Array, value.Length).Value.SequenceEqual(value);
    }

    internal uint AsUint32(string key)
    {
        var value = CheckEntry(key, EntryType.Uint32, 4).Value;
        return BitConverter.ToUInt32(value);
    }

    internal byte[] AsArray(string key, int size)
    {
        return CheckEntry(key, EntryType.Array, size).Value;
    }

    internal ulong AsUint64(string key)
    {
        var value = CheckEntry(key, EntryType.Uint64, 8).Value;
        return BitConverter.ToUInt64(value);
    }
}