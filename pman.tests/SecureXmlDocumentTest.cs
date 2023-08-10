using System.Text;
using pman.keepass;

namespace pman.tests;

public class KeePassPasswordDatabaseTest
{
    [Test]
    public void TestProcessContents()
    {
        var contents = File.ReadAllBytes("test.xml");
        var document = new SecureXmlDocument(contents, 0);
    }
}