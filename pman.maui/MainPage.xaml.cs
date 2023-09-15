using System.Windows.Input;

namespace pman.maui;

public partial class MainPage
{
    public ICommand OpenCommand { get; private set; }
    
    public MainPage()
    {
        OpenCommand = new Command(() => OpenFile(null, EventArgs.Empty));
        InitializeComponent();
        ((MainViewModel)BindingContext).LoadPreferences();
    }
    
    private async void OpenFile(object? sender, EventArgs e)
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
                ((MainViewModel)BindingContext).AddPasswordDatabaseFile(result.FullPath);
        }
        catch (Exception)
        {
            // The user canceled or something went wrong
        }
    }

    protected override void OnSizeAllocated(double width, double height)
    {
        base.OnSizeAllocated(width, height);
        ((MainViewModel)BindingContext).IsPortrait = height > width;
    }
}
