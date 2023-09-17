using System.Security;
using System.Text;

namespace pman.maui;

public partial class CredentialsForm
{
    public class CredentialsFormEventArgs
    {
        public readonly SecureString FirstPassword;
        public readonly SecureString? SecondPassword;
        public readonly string? KeyFileName;
        public string? ErrorMessage; 

        public CredentialsFormEventArgs(SecureString firstPassword, SecureString? secondPassword, string? keyFileName)
        {
            FirstPassword = firstPassword;
            SecondPassword = secondPassword;
            KeyFileName = keyFileName;
        }
    }
    
    public static readonly BindableProperty ShowSecondPasswordProperty =
        BindableProperty.Create (nameof(ShowSecondPassword), typeof(bool), typeof(CredentialsForm),
            false, propertyChanged: OnShowSecondPasswordChanged);
    
    public static readonly BindableProperty ShowKeyFileProperty =
        BindableProperty.Create (nameof(ShowKeyFile), typeof(bool), typeof(CredentialsForm),
            false, propertyChanged: OnShowKeyFileChanged);

    public event EventHandler<CredentialsFormEventArgs>? OpenDatabaseEvent;
    
    private SecureString _firstPassword;
    private SecureString _secondPassword;
    private bool _ignoreTextChangeEvent;
    
    public bool ShowSecondPassword
    {
        get => (bool)GetValue(ShowSecondPasswordProperty);
        set => SetValue(ShowSecondPasswordProperty, value);
    }

    public bool ShowKeyFile
    {
        get => (bool)GetValue(ShowKeyFileProperty);
        set => SetValue(ShowKeyFileProperty, value);
    }

    public CredentialsForm()
    {
        InitializeComponent();
        SecondPasswordLabel.IsVisible = false;
        SecondPassword.IsVisible = false;
        KeyFileLabel.IsVisible = false;
        KeyFileLayout.IsVisible = false;
        _firstPassword = new SecureString();
        _secondPassword = new SecureString();
        _ignoreTextChangeEvent = false;
    }

    private void SelectKeyFile(Object sender, EventArgs e)
    {
    }

    private void OpenDatabase(Object sender, EventArgs e)
    {
        var args = new CredentialsFormEventArgs(_firstPassword, ShowSecondPassword ? _secondPassword : null,
            ShowKeyFile ? (KeyFileName.Text == "None" ? null : KeyFileName.Text) : null);
        OpenDatabaseEvent?.Invoke(this, args);
        ErrorLabel.Text = args.ErrorMessage ?? "";
        _firstPassword = new SecureString();
        _secondPassword = new SecureString();
        _ignoreTextChangeEvent = true;
        FirstPassword.Text = "";
        SecondPassword.Text = "";
        _ignoreTextChangeEvent = false;
    }

    private void SecondPassword_OnTextChanged(object? sender, TextChangedEventArgs e)
    {
        TextChangedHandler(SecondPassword, e, _secondPassword);
    }

    private void FirstPassword_OnTextChanged(object? sender, TextChangedEventArgs e)
    {
        TextChangedHandler(FirstPassword, e, _firstPassword);
    }

    private void TextChangedHandler(Entry passwordEntry, TextChangedEventArgs e, SecureString password)
    {
        if (_ignoreTextChangeEvent)
            return;
        var l = e.OldTextValue?.Length ?? 0;
        if (e.NewTextValue.Length > l)
        {
            var sb = new StringBuilder(e.NewTextValue);
            for (var i = l; i < e.NewTextValue.Length; i++)
            {
                password.AppendChar(e.NewTextValue[i]);
                sb[i] = '*';
            }

            _ignoreTextChangeEvent = true;
            passwordEntry.Text = sb.ToString();
            _ignoreTextChangeEvent = false;
        }
        else if (e.NewTextValue.Length < l)
        {
            for (var i = e.NewTextValue.Length; i < l; i++)
                password.RemoveAt(e.NewTextValue.Length);
        }

        if (ShowSecondPassword)
            OpenDatabaseButton.IsEnabled = _firstPassword.Length > 0 && _secondPassword.Length > 0;
        else
            OpenDatabaseButton.IsEnabled = _firstPassword.Length > 0;
    }

    private static void OnShowSecondPasswordChanged(BindableObject bindable, object oldvalue, object newvalue)
    {
        var f = (CredentialsForm)bindable;
        var b = (bool)newvalue;
        f.SecondPasswordLabel.IsVisible = b;
        f.SecondPassword.IsVisible = b;
    }
    
    private static void OnShowKeyFileChanged(BindableObject bindable, object oldvalue, object newvalue)
    {
        var f = (CredentialsForm)bindable;
        var b = (bool)newvalue;
        f.KeyFileLabel.IsVisible = b;
        f.KeyFileLayout.IsVisible = b;
    }
}