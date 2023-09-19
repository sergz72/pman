namespace pman.maui;

public partial class EntityView
{
    public static readonly BindableProperty IsDbReadOnlyProperty =
        BindableProperty.Create (nameof(IsDbReadOnly), typeof(bool), typeof(GroupsView),
            false, propertyChanged: OnReadOnlyChanged);

    public static readonly BindableProperty ItemsSourceProperty =
        BindableProperty.Create (nameof(ItemsSource), typeof(List<DatabaseEntity>),
            typeof(GroupsView),
            new List<DatabaseEntity>(), propertyChanged: OnSourceChanged);
    
    public bool IsDbReadOnly
    {
        get => (bool)GetValue(IsDbReadOnlyProperty);
        set => SetValue(IsDbReadOnlyProperty, value);
    }

    public List<DatabaseEntity> ItemsSource
    {
        get => (List<DatabaseEntity>)GetValue(ItemsSourceProperty);
        set => SetValue(ItemsSourceProperty, value);
    }

    public EntityView()
    {
        InitializeComponent();
    }
    
    private void AddEntity(object sender, EventArgs e)
    {
    }
    
    private static void OnReadOnlyChanged(BindableObject bindable, object oldvalue, object newvalue)
    {
        var v = (EntityView)bindable;
        v.AddButton.IsEnabled = !(bool)newvalue;
    }

    private static void OnSourceChanged(BindableObject bindable, object oldvalue, object newvalue)
    {
        var v = (EntityView)bindable;
        v.EntitiesView.ItemsSource = (List<DatabaseEntity>)newvalue;
        v.EntitiesView.SelectedItem = null;
    }

    private void OnRemoveEntity(object? sender, EventArgs e)
    {
    }
    
    private void OnEditEntity(object? sender, EventArgs e)
    {
    }
}