using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Security;
using System.Text.Json;

namespace pman.maui;

public class MainViewModel: INotifyPropertyChanged
{
    private const string PasswordDatabasesPreference = "PasswordDatabases";
    
    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<PasswordDatabaseFile> PasswordDatabases { get; }
    public ObservableCollection<PasswordDatabaseGroup> Groups { get; }
    public ObservableCollection<PasswordDatabaseEntity> Entities { get; }

    private PasswordDatabaseFile? _selectedDatabase;

    public bool IsDbOpen => _selectedDatabase?.IsOpen ?? false;
    public bool IsDbPrepared => _selectedDatabase?.IsPrepared ?? false;
    public bool IsDbError => _selectedDatabase?.IsError ?? false;
    public string? DbError => _selectedDatabase?.ErrorMessage ?? null;
    public bool SecondPasswordIsRequired => _selectedDatabase?.SecondPasswordIsRequired ?? false;
    public bool KeyFileIsRequired => _selectedDatabase?.KeyFileIsRequired ?? false;
    
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
        Groups = new ObservableCollection<PasswordDatabaseGroup>();
        Entities = new ObservableCollection<PasswordDatabaseEntity>();
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
            return null;
        }
        catch (Exception e)
        {
            return e.Message;
        }
    }
    
    internal void SelectDatabase(IReadOnlyList<object> currentSelection)
    {
        _selectedDatabase = currentSelection.FirstOrDefault() as PasswordDatabaseFile?;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbOpen)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbPrepared)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDbError)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DbError)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SecondPasswordIsRequired)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(KeyFileIsRequired)));
    }
}
