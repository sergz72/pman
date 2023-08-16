using pman.keepass;

namespace pman.tests;

public class KeePassXmlDocumentTest
{
    [Test]
    public void TestKeePassXmlDocument()
    {
        var contents = File.ReadAllBytes("test.xml");
        var document = new KeePassXmlDocument(contents, 0, null);
        var groups = document.GetGroups();
        Assert.That(groups, Has.Count.EqualTo(6));
        Assert.That(groups.ContainsKey("General"));

        var entries = document.GetGroupEntries("General");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("General", "Sample Entry")));

        entries = document.GetGroupEntries("Windows");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("Windows", "Sample Entry #2")));

        entries = document.GetEntries("#2");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("Windows", "Sample Entry #2")));

        var entry = document.GetEntry("Sample Entry");
        
        var users = document.GetUsers();
        Assert.That(users, Has.Count.EqualTo(2));
        Assert.That(users, Does.Contain("User Name"));
    }
}