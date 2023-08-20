using System.Text;
using pman.keepass;

namespace pman.tests;

public class KeePassPasswordDatabaseTest
{
    [Test]
    public void TestSecureXmlDocument()
    {
        var contents = File.ReadAllBytes("test.xml");
        var document = new SecureXmlDocument(contents, 0, null);
    }

    [Test]
    public void TestCleanup()
    {
        var bytes = Encoding.UTF8.GetBytes("&gt;123&lt;");
        var result = Encoding.UTF8.GetString(SecureXmlDocument.XmlTag.Cleanup(bytes));
        Assert.That(result, Is.EqualTo(">123<"));
        bytes = Encoding.UTF8.GetBytes("&quot;123&gt;");
        result = Encoding.UTF8.GetString(SecureXmlDocument.XmlTag.Cleanup(bytes));
        Assert.That(result, Is.EqualTo("\"123>"));
        bytes = Encoding.UTF8.GetBytes("&apos;123&quot;");
        result = Encoding.UTF8.GetString(SecureXmlDocument.XmlTag.Cleanup(bytes));
        Assert.That(result, Is.EqualTo("`123\""));
        bytes = Encoding.UTF8.GetBytes("&amp;123&apos;");
        result = Encoding.UTF8.GetString(SecureXmlDocument.XmlTag.Cleanup(bytes));
        Assert.That(result, Is.EqualTo("&123`"));
        bytes = Encoding.UTF8.GetBytes("&lt;123&amp;");
        result = Encoding.UTF8.GetString(SecureXmlDocument.XmlTag.Cleanup(bytes));
        Assert.That(result, Is.EqualTo("<123&"));
    }
}