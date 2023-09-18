namespace pman.maui;

public partial class DatabaseView
{
    public DatabaseView()
    {
        InitializeComponent();
    }
    
    private void DbView_SelectionChanged(Object sender, SelectionChangedEventArgs e)
    {
        ((MainViewModel)BindingContext).SelectDatabase(e.CurrentSelection);
    }
    
    private void OnRemoveDb(object? sender, EventArgs e)
    {
    }
    
    private void OnEditDb(object? sender, EventArgs e)
    {
        var model = (MainViewModel)BindingContext;
        if (!model.IsReadOnly)
        {
            
        }
    }
}