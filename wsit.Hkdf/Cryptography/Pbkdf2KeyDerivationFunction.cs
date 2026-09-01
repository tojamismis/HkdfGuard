using System.Security.Cryptography;
using System.Text.Json.Serialization;
using wsit.Hkdf.Primitives;

namespace wsit.Hkdf.Cryptography;

public class Pbkdf2KeyDerivationFunction : IKeyDerivationFunction
{
    public int Derive(ReadOnlySpan<byte> uniqueBytes, KeyBlob blob, IKeyInputStorage storage, string serviceName,
        scoped Span<byte> result)
    {
        Span<byte> keyMaterial = stackalloc byte[32];
        Span<byte> saltBytes = stackalloc byte[uniqueBytes.Length + blob.Salt.Length];
        try
        {
            uniqueBytes.CopyTo(saltBytes.Slice(0, uniqueBytes.Length));
            blob.Salt.CopyTo(saltBytes.Slice(uniqueBytes.Length, blob.Salt.Length));
            var index = $"{serviceName}.{blob.MaterialIdentifier}";
            storage.CreateOrGet(index, keyMaterial);
            return DeriveCore(keyMaterial, saltBytes, blob.Iterations, result);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyMaterial);
            CryptographicOperations.ZeroMemory(saltBytes);
        }
    }

    //The actual derivation requires a static set of keyMaterial during the 
    private int DeriveCore(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> salt, 
        int iterations, scoped Span<byte> result)
    {
        Rfc2898DeriveBytes.Pbkdf2(keyMaterial, salt, result, iterations, HashAlgorithmName.SHA256);
        return result.Length;
    }
}