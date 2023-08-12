namespace pman.keepass;

internal sealed class NoCompressionEngine: ICompressionEngine
{
    public byte[] Decompress(byte[] bytes)
    {
        return bytes;
    }
}