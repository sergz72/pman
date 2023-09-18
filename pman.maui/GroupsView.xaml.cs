namespace pman.maui;

public partial class GroupsView
{
    public static readonly BindableProperty IsDbReadOnlyProperty =
        BindableProperty.Create (nameof(IsDbReadOnly), typeof(bool), typeof(GroupsView),
            false, propertyChanged: OnReadOnlyChanged);

    public static readonly BindableProperty ItemsSourceProperty =
        BindableProperty.Create (nameof(ItemsSource), typeof(List<DatabaseGroup>),
            typeof(GroupsView),
            new List<DatabaseGroup>(), propertyChanged: OnSourceChanged);
    
    public bool IsDbReadOnly
    {
        get => (bool)GetValue(IsDbReadOnlyProperty);
        set => SetValue(IsDbReadOnlyProperty, value);
    }

    public List<DatabaseSearchResult> ItemsSource
    {
        get => (List<DatabaseSearchResult>)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
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

    private static void OnSourceChanged(BindableObject bindable, object oldvalue, object newvalue)
    {
        var v = (GroupsView)bindable;
        v.GroupsListView.ItemsSource = (List<DatabaseGroup>)newvalue;
    }
}