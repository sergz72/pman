namespace pman;

public struct DatabaseSearchResult
{
    public readonly string Group;
    public readonly string Name;

    public DatabaseSearchResult(string group, string name)
    {
        Group = group;
        Name = name;
    }
}

public struct Times
{
    public readonly DateTime CreationTime;
    public DateTime ModificationTime;
    public DateTime LastAccessTime;

    public Times(DateTime creationTime)
    {
        CreationTime = creationTime;
        ModificationTime = creationTime;
        LastAccessTime = creationTime;
    }
    
    public Times(DateTime creationTime, DateTime modificationTime, DateTime lastAccessTime)
    {
        CreationTime = creationTime;
        ModificationTime = modificationTime;
        LastAccessTime = lastAccessTime;
    }
}