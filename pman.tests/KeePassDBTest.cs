using System.Security;
using pman.keepass;

namespace pman.tests;

public class KeePassDBTest
{
    [Test]
    public void TestKeePassDb()
    {
        var db = new KeePassDb("testKeePassDB.kdbx");
        var s = new SecureString();
        s.AppendChar('0');
        s.AppendChar('1');
        s.AppendChar('2');
        s.AppendChar('3');
        s.AppendChar('4');
        s.AppendChar('5');
        s.AppendChar('6');
        s.AppendChar('7');
        s.AppendChar('8');
        s.AppendChar('9');
        db.Decrypt(s, null);
        
        var groups = db.GetGroups();
        Assert.That(groups, Has.Count.EqualTo(6));
        Assert.That(groups.ContainsKey("General"));

        var entries = db.GetGroupEntries("General");
        Assert.That(entries, Has.Count.EqualTo(6));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("General", "Sample Entry")));

        entries = db.GetGroupEntries("Windows");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("Windows", "Sample Entry #2")));

        entries = db.GetGroupEntries("Network");
        Assert.That(entries, Has.Count.EqualTo(5));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("Network", "test6")));
        
        entries = db.GetEntries("t10");
        Assert.That(entries, Has.Count.EqualTo(1));
        Assert.That(entries[0], Is.EqualTo(new DatabaseSearchResult("Network", "test10")));

        var entry = db.GetEntry("test10");
        var user = entry.GetUserName()!.GetUnprotectedString();
        Assert.That(user, Is.EqualTo("user3"));
        var password = entry.GetPassword().GetUnprotectedString();
        Assert.That(password, Is.EqualTo("12345678901234567890"));
        
        var users = db.GetUsers();
        Assert.That(users, Has.Count.EqualTo(5));
        Assert.That(users, Does.Contain("user3"));
    }
}