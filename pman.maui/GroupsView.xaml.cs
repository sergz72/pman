namespace pman.maui;

public partial class GroupsView
{
    public static readonly BindableProperty IsReadOnlyProperty =
        BindableProperty.Create (nameof(IsDbReadOnly), typeof(bool), typeof(CredentialsForm),
            false, propertyChanged: OnReadOnlyChanged);

    public bool IsDbReadOnly
    {
        get => (bool)GetValue(IsReadOnlyProperty);
        set => SetValue(IsReadOnlyProperty, value);
    }

    public GroupsView()
    {
        InitializeComponent();
    }
    private void AddGroup(object sender, EventArgs e)
    {
    }
    
    private static void OnReadOnlyChanged(BindableObject bindable, object oldvalue, object newvalue)
    {
        var v = (GroupsView)bindable;
        v.AddButton.IsEnabled = !(bool)newvalue;
    }
}