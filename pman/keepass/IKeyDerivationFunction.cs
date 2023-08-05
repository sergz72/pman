namespace pman.keepass;

public interface IKeyDerivationFunction
{
    byte[] GetTransformedKey(byte[] digest);
}