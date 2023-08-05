namespace pman.keepass;

public class NoCompressionEngine: ICompressionEngine
{
    public byte[] Decompress(byte[] bytes)
    {
        return bytes;
    }
}