using System.IO.Compression;

namespace pman.keepass;

public class GzipCompressionEngine: ICompressionEngine
{
    public byte[] Decompress(byte[] bytes)
    {
        GZipStream s = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
        MemoryStream decompressed = new MemoryStream();
        s.CopyTo(decompressed);
        return decompressed.GetBuffer();
    }
}