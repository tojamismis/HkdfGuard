using wsit.Hkdf.Primitives;

namespace wsit.Hkdf;

public interface IKeyDerivationFunction
{
    /// <summary>
    /// Derives a key into the result span.
    /// </summary>
    /// <param name="uniqueBytes">Unique bytes for this specific key derivation</param>
    /// <param name="blob">The keyBlob object</param>
    /// <param name="storage">The KeyInputStorageController object</param>
    /// <param name="serviceName">The assigned name or prefix for this service in keyStorage</param>
    /// <param name="result">The 32 byte span for the derived key</param>
    /// <returns>Number of bytes written to the derived key span</returns>
    public int Derive(ReadOnlySpan<byte> uniqueBytes, KeyBlob blob, IKeyInputStorage storage, string serviceName,
        scoped Span<byte> result);
}