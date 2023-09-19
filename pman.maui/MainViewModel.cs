using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security;
using System.Text.Json;

namespace pman.maui;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private const string PasswordDatabasesPreference = "PasswordDatabases";

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<PasswordDatabaseFile> PasswordDatabases { get; }

    public List<DatabaseGroup> Groups
    {
        get
        {
            return _groups
                .Select(group => new DatabaseGroup(group.Key, group.Value.Count, IsReadOnly))
                .OrderBy(group => group.Name)
                .ToList();
        }
    }

    private Dictionary<string, List<DatabaseEntity>> _groups;

    public List<DatabaseEntity> Entities { get; private set; }

    private PasswordDatabaseFile? _selectedDatabase;

    public bool IsDbOpen => _selectedDatabase?.IsOpen ?? false;
    public bool IsDbPrepared => _selectedDatabase?.IsPrepared ?? false;
    public bool IsDbError => _selectedDatabase?.IsError ?? false;
    public string? DbError => _selectedDatabase?.ErrorMessage ?? null;
    public bool SecondPasswordIsRequired => _selectedDatabase?.SecondPasswordIsRequired ?? false;
    public bool KeyFileIsRequired => _selectedDatabase?.KeyFileIsRequired ?? false;
    public bool IsReadOnly => _selectedDatabase?.IsReadOnly ?? true;

    private bool _isPortrait;

    public bool IsLandscape => !_isPortrait;

    public bool IsPortrait
    {
        get => _isPortrait;
        set
        {
            if (value == _isPortrait) return;
            _isPortrait = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsPortrait)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsLandscape)));
        }
    }

    public MainViewModel()
    {
        PasswordDatabases = new ObservableCollection<PasswordDatabaseFile>();
        _groups = new Dictionary<string, List<DatabaseEntity>>();
        Entities = new List<DatabaseEntity>();
        _selectedDatabase = null;
        _isPortrait = true;
    }

    internal void LoadPreferences()
    {
        LoadPasswordDatabases();
    }

    private void LoadPasswordDatabases()
    {
        var passwordDatabasesJson = Preferences.Default.Get(PasswordDatabasesPreference, "[]");
        var passwordDatabases =
            JsonSerializer.Deserialize<string[]>(passwordDatabasesJson);
        if (passwordDatabases == null) return;
        foreach (var passwordDatabaseName in passwordDatabases)
            AddPasswordDatabaseFile(passwordDatabaseName);
    }

    private void SavePasswordDatabases()
    {
        var passwordDatabases = PasswordDatabases.Select(it => it.FullPath).ToArray();
        var passwordDatabasesJson = JsonSerializer.Serialize(passwordDatabases);
        Preferences.Default.Set(PasswordDatabasesPreference, passwordDatabasesJson);
    }

    internal void AddPasswordDatabaseFile(string fileName)
    {
        PasswordDatabases.Add(new PasswordDatabaseFile(fileName));
        SavePasswordDatabases();
    }

    internal void RemovePasswordDatabaseFile(int index)
    {
        PasswordDatabases.RemoveAt(index);
        SavePasswordDatabases();
    }

    internal string? OpenDatabase(SecureString password, SecureString? password2, string? keyFileName)
    {
        try
        {
            _selectedDatabase?.Open(password, password2, keyFileName);
            Search("");
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbOpen)));
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbPrepared)));
            return null;
        }
        catch (Exception e)
        {
            return e.Message;
        }
    }

    public void Search(string filter)
    {
        Entities = new List<DatabaseEntity>();
        _groups = IsDbOpen
            ? _selectedDatabase!.Search(filter)
                .ToDictionary(el => el.Key,
                    el => el.Value.Select(v => new DatabaseEntity(v, IsReadOnly)).ToList())
            : new Dictionary<string, List<DatabaseEntity>>();
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Groups)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Entities)));
    }

    internal void SelectDatabase(IReadOnlyList<object> currentSelection)
    {
        _selectedDatabase = (PasswordDatabaseFile?)currentSelection.FirstOrDefault();
        Search("");
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbOpen)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbPrepared)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbError)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DbError)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SecondPasswordIsRequired)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(KeyFileIsRequired)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsReadOnly)));
    }

    internal void SelectGroup(string? group)
    {
        Entities = group == null ? new List<DatabaseEntity>() : _groups[group];
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Entities)));
    }
}

public readonly struct DatabaseGroup(string name, int count, bool isReadOnly)
{
    public string Name { get; } = name;
    public int EntryCount { get; } = count;
    public bool IsReadWrite { get; } = !isReadOnly;
}

public readonly struct DatabaseEntity(DatabaseSearchResult result, bool isReadOnly)
{
    public DatabaseSearchResult Entity { get; } = result;
    public bool IsReadWrite { get; } = !isReadOnly;
}
