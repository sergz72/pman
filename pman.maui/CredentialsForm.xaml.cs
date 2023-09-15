namespace pman.maui;

public partial class CredentialsForm
{
    public static readonly BindableProperty ShowSecondPasswordProperty =
        BindableProperty.Create (nameof(ShowSecondPassword), typeof(bool), typeof(CredentialsForm),
            false, propertyChanged: OnShowSecondPasswordChanged);
    
    public static readonly BindableProperty ShowKeyFileProperty =
        BindableProperty.Create (nameof(ShowKeyFile), typeof(bool), typeof(CredentialsForm),
            false, propertyChanged: OnShowKeyFileChanged);
    
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
    }

    private void SelectKeyFile(Object sender, EventArgs e)
    {
    }

    private void OpenDatabase(Object sender, EventArgs e)
    {
    }

    private void SecondPassword_OnTextChanged(object? sender, TextChangedEventArgs e)
    {
    }

    private void FirstPassword_OnTextChanged(object? sender, TextChangedEventArgs e)
    {
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