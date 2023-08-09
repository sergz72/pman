using System.Text;
using pman.keepass;

namespace pman.tests;

public class KeePassPasswordDatabaseTest
{
    [Test]
    public void TestBuildXmlTag()
    {
        var tag = BuildXmlTag("name property=\"abc\" property2=\"cde\">value<");
        Assert.That(tag.Name, Is.EqualTo("name"));
        Assert.That(tag.Properties.Count, Is.EqualTo(2));
        Assert.True(tag.Properties.ContainsKey("property"));
        Assert.True(tag.Properties.ContainsKey("property2"));
        Assert.That(tag.Properties["property"], Is.EqualTo("abc"));
        Assert.That(tag.Properties["property2"], Is.EqualTo("cde"));
    }

    private KeePassPasswordDatabase.XmlTag BuildXmlTag(string xml)
    {
        var offset = KeePassPasswordDatabase.BuildXmlTag(Encoding.UTF8.GetBytes(xml), 0, out var tag);
        if (offset != xml.IndexOf('>') + 1)
            Assert.Fail("wrong offset");
        return tag;
    }

    [Test]
    public void TestSearch()
    {
        string xml = "<String><Key>aaa</Key><Value Protected=\"True\">bbb</Value></String>";
        var offset = KeePassPasswordDatabase.Search(Encoding.UTF8.GetBytes(xml), 0, out var tag, true, "Value");
        Assert.That(tag.Name, Is.EqualTo("Value"));
        Assert.That(tag.Properties.Count, Is.EqualTo(1));
        Assert.True(tag.Properties.ContainsKey("Protected"));
        Assert.That(tag.Properties["Protected"], Is.EqualTo("True"));
        Assert.That(offset, Is.EqualTo(xml.IndexOf("bbb")));
    }
    
    [Test]
    public void TestFindTags()
    {
        string xml = "\n<Key>aaa</Key>\n<Value Protected=\"True\">bbb</Value>\n</String>";
        var offset = KeePassPasswordDatabase.FindTags(Encoding.UTF8.GetBytes(xml), 0, out var tags);
        Assert.That(tags.Count, Is.EqualTo(2));
        Assert.True(tags.ContainsKey("Key"));
        Assert.True(tags.ContainsKey("Value"));
        Assert.That(offset, Is.EqualTo(xml.IndexOf("</String") + 2));
    }

    [Test]
    public void TestProcessContents()
    {
        var contents = File.ReadAllBytes("test.xml");
        var db = KeePassPasswordDatabase.Create(contents, 0);
    }
}