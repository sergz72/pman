using System.Collections.ObjectModel;
using System.ComponentModel;

namespace pman.maui;

public partial class MainPage
{
    public MainPage()
    {
        InitializeComponent();
    }

    private async void OpenCommand(object sender, EventArgs e)
    {
        var fileTypes = new Dictionary<DevicePlatform, IEnumerable<string>>()
        {
            { DevicePlatform.MacCatalyst, new []{"kdbx"}},
            { DevicePlatform.iOS, new[] { "public.kdbx" } }, // UTType values
            { DevicePlatform.Android, new[] { "application/*" } }, // MIME type
            { DevicePlatform.WinUI, new[] { ".kdbx" } }, // file extension
        };
        var options = new PickOptions
        {
            FileTypes = new FilePickerFileType(fileTypes),
            PickerTitle = "Open a password database"
        };
        try
        {
            var result = await FilePicker.Default.PickAsync(options);
            if (result != null)
                ((MainViewModel)this.BindingContext).PasswordDatabases.Add(new PasswordDatabaseFile(result.FullPath));
        }
        catch (Exception ex)
        {
            // The user canceled or something went wrong
        }
    }

    private void AddGroup(object sender, EventArgs e)
    {
    }

    private void AddEntity(object sender, EventArgs e)
    {
    }

    void DbView_SelectionChanged(System.Object sender, Microsoft.Maui.Controls.SelectionChangedEventArgs e)
    {
        ((MainViewModel)this.BindingContext).SelectDatabase(e.CurrentSelection);
    }

    void SelectKeyFile(System.Object sender, System.EventArgs e)
    {
    }

    void OpenDatabase(System.Object sender, System.EventArgs e)
    {
    }
}

public class MainViewModel: INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<PasswordDatabaseFile> PasswordDatabases { get; }
    public ObservableCollection<PasswordDatabaseGroup> Groups { get; }
    public ObservableCollection<PasswordDatabaseEntity> Entities { get; }

    private PasswordDatabaseFile? _selectedDatabase;

    public bool IsDBOpen {  get { return _selectedDatabase?.IsOpen ?? false; } }
    public bool IsDBPrepared { get { return _selectedDatabase?.IsPrepared ?? false; } }
    public bool IsDBError { get { return _selectedDatabase?.IsError ?? false; } }
    public string? DBError {  get { return _selectedDatabase?.ErrorMessage ?? null; } }

    public MainViewModel()
    {
        PasswordDatabases = new ObservableCollection<PasswordDatabaseFile>();
        Groups = new ObservableCollection<PasswordDatabaseGroup>();
        Entities = new ObservableCollection<PasswordDatabaseEntity>();
        _selectedDatabase = null;
    }

    internal void SelectDatabase(IReadOnlyList<object> currentSelection)
    {
        _selectedDatabase = currentSelection.FirstOrDefault() as PasswordDatabaseFile?;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDBOpen)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDBPrepared)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsDBError)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DBError)));
    }
}
