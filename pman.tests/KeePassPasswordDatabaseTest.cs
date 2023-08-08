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
}